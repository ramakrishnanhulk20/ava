import { msg } from "@qorechain/sdk";
import { DENOM } from "../packages/server/src/config.ts";
import { accountSequence, balanceOf, feeForGas, formatQor, nativeTx, pqcStatus, simulateNative, type Fee, type Messages } from "./lib/chain.ts";
import { loadSuiteEnv } from "./lib/env.ts";
import { assertNoForeignSecrets, assertTestnet, installFetchGuard } from "./lib/guard.ts";
import { DEMO_POOL, FILL_RANGE, NOKEM_SPONSORED_RANGE, ROLES, SHARED_KEM_SPONSORED_RANGE, SPONSORED_RANGE, personAt, type Person } from "./lib/identities.ts";
import { isOurKey } from "./lib/people.ts";

/**
 * A range the suite takes in index order is read only until this many indices in a row the chain
 * has never seen: each run takes the next fresh index and funds every one it takes, so the used
 * part of such a range never has a gap this wide.
 */
const UNSEEN_STOP = 10;
const PARALLEL = 4;
/** Less than any send's fee, so a balance this small is left where it is. */
const DUST_UQOR = 10_000n;

interface Range {
  name: string;
  indices: readonly number[];
  inOrder: boolean;
}

const span = (from: number, to: number): number[] => Array.from({ length: to - from + 1 }, (_, i) => from + i);

/** Every index the suite derives a test identity from. The wallet, index 0, is where the QOR goes, so it is left out. */
const RANGES: readonly Range[] = [
  { name: "roles", indices: Object.values(ROLES).map((r) => r.index).filter((i) => i !== ROLES.wallet.index), inOrder: false },
  { name: "sponsored", indices: span(SPONSORED_RANGE.from, SPONSORED_RANGE.to), inOrder: true },
  { name: "no-kem guests", indices: span(NOKEM_SPONSORED_RANGE.from, NOKEM_SPONSORED_RANGE.to), inOrder: true },
  { name: "fill", indices: span(FILL_RANGE.from, FILL_RANGE.from + FILL_RANGE.count - 1), inOrder: true },
  { name: "demo guests", indices: span(DEMO_POOL.from, DEMO_POOL.to), inOrder: true },
  { name: "copiers", indices: span(SHARED_KEM_SPONSORED_RANGE.from, SHARED_KEM_SPONSORED_RANGE.to), inOrder: true },
];

interface Held {
  range: string;
  person: Person;
  balance: bigint;
}

type Plan = Held & ({ send: { mode: "classical" | "hybrid"; fee: Fee; feeUqor: bigint; amount: bigint } } | { kept: string });

const q = (uqor: bigint): string => `${formatQor(uqor)} QOR`;
const sum = (xs: readonly bigint[]): bigint => xs.reduce((s, x) => s + x, 0n);

/** One MsgSend of `amount` from the identity to the wallet. The destination is fixed here and nowhere else. */
function sendBack(person: Person, wallet: Person, amount: bigint): Messages {
  return [msg.bank.send({ fromAddress: person.qor1, toAddress: wallet.qor1, amount: [{ denom: DENOM, amount: amount.toString() }] })];
}

/** The identities of one range that hold QOR, and how many indices were read. */
async function scan(mnemonic: string, range: Range): Promise<{ held: Held[]; read: number }> {
  const held: Held[] = [];
  let unseen = 0;
  let read = 0;
  for (let start = 0; start < range.indices.length; start += PARALLEL) {
    const batch = range.indices.slice(start, start + PARALLEL);
    const people: Person[] = [];
    for (const index of batch) people.push(await personAt(mnemonic, index, `${range.name} ${index}`));
    const seen = await Promise.all(people.map(async (p) => ((await accountSequence(p.qor1)) === undefined ? undefined : balanceOf(p.qor1))));
    for (const [i, person] of people.entries()) {
      read++;
      const balance = seen[i];
      if (balance === undefined) {
        unseen++;
        if (range.inOrder && unseen >= UNSEEN_STOP) return { held, read };
        continue;
      }
      unseen = 0;
      if (balance > 0n) held.push({ range: range.name, person, balance });
    }
  }
  return { held, read };
}

/**
 * What to send back: the whole balance less the fee the chain's own simulation sets, hybrid-signed
 * when the identity has registered this phrase's ML-DSA-87 key and classical when it has none.
 * Nothing is sent here.
 */
async function planFor(h: Held, wallet: Person): Promise<Plan> {
  if (h.balance < DUST_UQOR) return { ...h, kept: "below any send's fee" };
  const pqc = await pqcStatus(h.person.qor1);
  if (pqc.registered && !isOurKey(pqc, h.person)) return { ...h, kept: "it holds an ML-DSA-87 key that is not this phrase's" };
  const mode = pqc.registered ? "hybrid" : "classical";
  const sim = await simulateNative(h.person, mode, sendBack(h.person, wallet, h.balance));
  if (!sim.ok) return { ...h, kept: `the chain refuses the simulated ${mode} send, HTTP ${sim.status}: ${sim.message}` };
  let fee: Fee;
  try {
    fee = feeForGas(sim.gasUsed);
  } catch (err) {
    return { ...h, kept: err instanceof Error ? err.message : String(err) };
  }
  const feeUqor = BigInt(fee.amount[0]?.amount ?? "0");
  if (feeUqor >= h.balance) return { ...h, kept: `the fee of ${q(feeUqor)} is not less than what it holds` };
  return { ...h, send: { mode, fee, feeUqor, amount: h.balance - feeUqor } };
}

/**
 * Sends what the suite left on its test identities back to the security wallet, keeping only each
 * send's fee. Every identity is derived from SECURITY_TESTNET_KEY, every send goes to the wallet
 * alone, and the chain ids are checked before anything is read or sent. With --dry-run it reads,
 * has the chain simulate each send, and prints what it would send; nothing is broadcast.
 */
async function main(): Promise<void> {
  const dryRun = process.argv.slice(2).includes("--dry-run");
  assertNoForeignSecrets();
  const env = loadSuiteEnv();
  installFetchGuard();
  const chain = await assertTestnet();
  const wallet = await personAt(env.mnemonic, ROLES.wallet.index, "wallet");
  const walletBefore = await balanceOf(wallet.qor1);
  console.log(`Ava attack suite, QOR recovery${dryRun ? ", dry run: nothing is sent" : ""}.`);
  console.log(`chain:    ${chain.cosmos} and EVM ${chain.evm} confirmed`);
  console.log(`wallet:   ${wallet.qor1}, ${q(walletBefore)}`);

  const held: Held[] = [];
  for (const range of RANGES) {
    const found = await scan(env.mnemonic, range);
    held.push(...found.held);
    const read = range.indices.slice(0, found.read);
    const which = range.inOrder ? `${read[0]} to ${read.at(-1)}` : read.join(", ");
    console.log(`scanned:  ${range.name}, indices ${which}: ${found.held.length} hold QOR, ${q(sum(found.held.map((h) => h.balance)))}`);
  }
  const unrealisedBefore = sum(held.map((h) => h.balance));

  const plans: Plan[] = [];
  for (let start = 0; start < held.length; start += PARALLEL) plans.push(...(await Promise.all(held.slice(start, start + PARALLEL).map((h) => planFor(h, wallet)))));

  console.log("");
  const sent: { plan: Plan; amount: bigint; feeUqor: bigint }[] = [];
  const left: { plan: Plan; why: string }[] = [];
  for (let start = 0; start < plans.length; start += PARALLEL) {
    await Promise.all(
      plans.slice(start, start + PARALLEL).map(async (p) => {
        const who = `${p.range} ${p.person.index} ${p.person.qor1}, ${q(p.balance)}`;
        if ("kept" in p) {
          left.push({ plan: p, why: p.kept });
          console.log(`  kept:   ${who}: ${p.kept}`);
          return;
        }
        if (dryRun) {
          sent.push({ plan: p, amount: p.send.amount, feeUqor: p.send.feeUqor });
          console.log(`  would:  ${who} -> ${q(p.send.amount)} to the wallet, fee ${q(p.send.feeUqor)}, ${p.send.mode}`);
          return;
        }
        try {
          const tx = await nativeTx(p.person, p.send.mode, sendBack(p.person, wallet, p.send.amount), p.send.fee);
          sent.push({ plan: p, amount: p.send.amount, feeUqor: p.send.feeUqor });
          console.log(`  sent:   ${who} -> ${q(p.send.amount)} to the wallet, fee ${q(p.send.feeUqor)}, ${p.send.mode}, in ${tx.hash}`);
        } catch (err) {
          const why = err instanceof Error ? err.message.replace(/\s+/g, " ").slice(0, 300) : String(err);
          left.push({ plan: p, why });
          console.log(`  FAILED: ${who}: ${why}`);
        }
      }),
    );
  }

  const back = sum(sent.map((s) => s.amount));
  const fees = sum(sent.map((s) => s.feeUqor));
  console.log("");
  console.log(`before:   ${q(unrealisedBefore)} unrealised, held by ${held.length} test identities`);
  if (dryRun) {
    console.log(`realised: nothing, this is a dry run. Without --dry-run: ${q(back)} back to the wallet from ${sent.length} identities, ${q(fees)} burned in fees on the way`);
    console.log(`left:     ${q(sum(left.map((l) => l.plan.balance)))} would stay unrecovered on ${left.length} identities (each line marked kept says why)`);
    return;
  }
  const walletAfter = await balanceOf(wallet.qor1);
  // Read back rather than worked out, because a send that failed in a block still spent its fee.
  const after: bigint[] = [];
  for (let start = 0; start < held.length; start += PARALLEL) after.push(...(await Promise.all(held.slice(start, start + PARALLEL).map((h) => balanceOf(h.person.qor1)))));
  const stays = sum(after);
  console.log(`realised: ${q(walletAfter - walletBefore)} back in the wallet (${q(walletBefore)} to ${q(walletAfter)}) from ${sent.length} sends of ${q(back)}, and ${q(fees)} burned in their fees`);
  console.log(`left:     ${q(stays)} unrecovered, read back from the ${held.length} identities that held QOR (each line marked kept or FAILED says why)`);
  if (left.some((l) => !("kept" in l.plan))) process.exitCode = 1;
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
