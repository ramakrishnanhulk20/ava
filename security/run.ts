import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { keccak256 } from "viem";
import { REGISTRY_CODE_KECCAK } from "../packages/server/src/config.ts";
import { attacks as contract } from "./attacks/contract.ts";
import { attacks as demo } from "./attacks/demo.ts";
import { attacks as proxy } from "./attacks/proxy.ts";
import { attacks as relay } from "./attacks/relay.ts";
import { attacks as sponsor } from "./attacks/sponsor.ts";
import { attacks as uploads, lateAttacks } from "./attacks/uploads.ts";
import { COST, NOT_RUN, SETUP, type Attack, type SetupName } from "./lib/attack.ts";
import { balanceOf, formatQor, pqcStatus } from "./lib/chain.ts";
import { Ctx } from "./lib/context.ts";
import { dev, ownHeaders } from "./lib/dev.ts";
import { loadSuiteEnv } from "./lib/env.ts";
import { REGISTRY, assertNoForeignSecrets, assertServerTarget, assertTestnet, installFetchGuard } from "./lib/guard.ts";
import { FILL_RANGE, FUND_FULL_UQOR } from "./lib/identities.ts";
import { KEM_FEE_EST_UQOR, MLDSA_FEE_UQOR, isOurProvenKey, kemOf } from "./lib/people.ts";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const RESULTS = fileURLToPath(new URL("./results/", import.meta.url));

interface Area {
  name: string;
  where: string;
  attacks: readonly Attack[];
}

/**
 * The run order. Uploads go first so C44's 50-minute verify window runs out while everything else
 * runs, and its last check goes at the end. The sponsor goes before the relay because C40's guest
 * is the identity C27 funds.
 */
const AREAS: readonly Area[] = [
  { name: "uploads", where: "dev server, live blob store", attacks: uploads },
  { name: "proxy", where: "dev server", attacks: proxy },
  { name: "contract", where: "live chain", attacks: contract },
  { name: "sponsor", where: "dev server, live chain", attacks: sponsor },
  { name: "relay", where: "dev server, live chain", attacks: relay },
  { name: "demo", where: "dev server, live chain", attacks: demo },
  { name: "late", where: "dev server, live blob store", attacks: lateAttacks },
];

/** Shown by every run and dry run: what is proven by tests rather than attacked live, and why. */
const PROVEN_OFFLINE: readonly { id: string; what: string; tests: string; why: string }[] = [
  {
    id: "C25-leak-halt",
    what: "a relayer window spent outside our own sends halts the relayer for the UTC day and closes the window",
    tests: 'packages/server/test/window.test.ts: "halts the day and closes the window when the chain shows one more transaction or 1 uqor more than we sent"; "on a halted day opens nothing, and still closes a live window it finds"',
    why: "triggering it live would stop the relayer, and the demo with it, for the rest of the day",
  },
  {
    id: "C22-upstream",
    what: "an upstream redirect, a body over 1 MiB or not JSON, the 8-second timeout, and no client header forwarded",
    tests: 'packages/server/test/proxy.test.ts: "refuses an upstream redirect without following it"; "refuses an upstream body over 1 MiB and a body that is not JSON"; "gives up after 8 seconds with 504"; "forwards no request header: Cookie, Authorization and X-Forwarded-For stay behind"',
    why: "the upstream is QoreChain's public REST, which this suite does not control and does not attack",
  },
];

/** C-numbers the backend upholds that no live attack here covers, each with the reason. */
const NO_LIVE_ATTACK: readonly { c: string; why: string }[] = [
  { c: "C11", why: "fresh epoch keys are randomness inside @ava/core's newEpochKey; nothing outside can push on it or see it; core's tests cover the source" },
  { c: "C14", why: "one key and a fresh nonce per document happen inside encryptDocument; not observable from outside; core's tests cover it" },
  { c: "C18, C19, C20, C21", why: "browser invariants (stored identity, CSP, rendering, strangers' boards); the app is not built yet" },
  { c: "C26", why: "the browser treats a relay hash as a claim until the receipt; the app is not built yet" },
  { c: "C31", why: "showing state is shared needs two server instances or a restart of the dev server, which this suite does not control; C27-second-request and C43-replay show the once-only records hold across requests" },
  { c: "C32", why: "its proof is a grep of the built app's bundles, pages and server-component payload, which do not exist yet" },
  { c: "C37", why: "the demo chair's key is attacked through C33 (no signing oracle) and C36 (the drill key); its rotation step is the runbook's own dry run, which reads the demo chair's phrase and so stays outside this suite" },
  { c: "C38, C39", why: "the exposure ledger runs in the browser; not built yet" },
];

const allAttacks = (): { area: Area; attack: Attack }[] => AREAS.flatMap((area) => area.attacks.map((attack) => ({ area, attack })));

function setupCost(): { names: SetupName[]; uqor: bigint } {
  const names = [...new Set(allAttacks().flatMap(({ attack }) => attack.needs ?? []))];
  return { names, uqor: names.reduce((s, n) => s + SETUP[n].costUqor, 0n) };
}

const q = (uqor: bigint): string => `${formatQor(uqor)} QOR`;

function dryRun(): void {
  const all = allAttacks();
  const setup = setupCost();
  const prerequisite = MLDSA_FEE_UQOR + KEM_FEE_EST_UQOR;
  const attacksUqor = all.reduce((s, { attack }) => s + attack.costUqor, 0n);
  const serverUqor = all.reduce((s, { attack }) => s + (attack.serverUqor ?? 0n), 0n);
  const gated = all.filter(({ attack }) => attack.id === "C7-exceed-64" || attack.id === "C41-full-board" || attack.id === "C42-bad-key-guest");
  const gatedUqor = gated.reduce((s, { attack }) => s + attack.costUqor, 0n);
  const total = setup.uqor + attacksUqor + COST.windowClose;
  console.log("Ava attack suite, dry run. Nothing is sent and nothing is read from the network.");
  console.log(`Scope: BoardRegistry ${REGISTRY} and PqcProbe on chain 9800 / qorechain-diana, and our own handlers on the dev server at 127.0.0.1:8787.`);
  console.log(`\nPrerequisite, once: npx tsx register-wallet.ts registers the wallet's ML-DSA-87 and ML-KEM-1024 keys, about ${q(prerequisite)}.`);
  console.log("\nSetup, paid once a run by the first attack that needs it, and nothing when the chain already has it:");
  for (const n of setup.names) console.log(`  ${n.padEnd(8)} ${q(SETUP[n].costUqor).padStart(13)}  ${SETUP[n].what}`);
  console.log("\nAttacks, in run order. Cost is test QOR from the security wallet; server is what our own relayer or sponsor spends.");
  for (const { area, attack } of all) {
    const server = attack.serverUqor === undefined ? "" : `, server ${q(attack.serverUqor)}`;
    console.log(`  ${attack.id}  [${area.name}: ${area.where}; wallet ${q(attack.costUqor)}${server}]`);
    console.log(`      ${attack.claim}`);
    if (attack.costNote !== undefined) console.log(`      cost: ${attack.costNote}`);
  }
  console.log(`\n${all.length} attacks in ${AREAS.length} groups.`);
  console.log(
    `Total from the security wallet: ${q(total)} (setup ${q(setup.uqor)}, attacks ${q(attacksUqor)}, the window close at the end ${q(COST.windowClose)}). ` +
      `Of that, ${q(gatedUqor)} is the three budget-gated attacks (${gated.map(({ attack }) => attack.id).join(", ")}), which report "not run" with their cost when the wallet cannot cover them: ${q(total - gatedUqor)} without them.`,
  );
  console.log(`Fund the wallet with at least ${q(prerequisite + total + 300_000n)} for everything (prerequisite, total and the 0.3 QOR floor the wallet never goes below), or ${q(prerequisite + total - gatedUqor + 300_000n)} without the gated three.`);
  console.log(`Our own relayer and sponsor would spend about ${q(serverUqor)} more, from their own accounts.`);
  console.log(
    `Realised versus unrealised: most of the total is QOR sent to test identities (${FILL_RANGE.count} of them for the fills). Their two registrations burn up to ${q(prerequisite)} each, realised; ` +
      `at least ${q(FUND_FULL_UQOR - prerequisite)} each stays on them, unrealised.`,
  );
  console.log("\nProven offline, not attacked live:");
  for (const p of PROVEN_OFFLINE) console.log(`  ${p.id}: ${p.what}. Proven by ${p.tests}. Why not live: ${p.why}.`);
  console.log("\nC-numbers the backend upholds with no live attack here:");
  for (const n of NO_LIVE_ATTACK) console.log(`  ${n.c}: ${n.why}.`);
}

interface Row {
  id: string;
  claim: string;
  held: boolean;
  notRun: boolean;
  evidence: string;
}

function git(args: string[]): string {
  try {
    return execFileSync("git", args, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "";
  }
}

const cell = (s: string): string => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const short = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 3)}...` : s);
/** Always yes or no; "no (not run)" when the attack could not run. */
const heldCell = (r: Row): string => (r.held ? "yes" : r.notRun ? "no (not run)" : "NO");

function writeResults(stamp: string, header: string[], rows: Row[], footer: string[]): string {
  mkdirSync(RESULTS, { recursive: true });
  const name = `run-${stamp}.md`;
  const table = ["| id | claim | held | evidence |", "|---|---|---|---|", ...rows.map((r) => `| ${r.id} | ${cell(r.claim)} | ${heldCell(r)} | ${cell(r.evidence)} |`)];
  const offline = ["## Proven offline, not attacked live", "", ...PROVEN_OFFLINE.map((p) => `- ${p.id}: ${p.what}. Proven by ${p.tests}. Why not live: ${p.why}.`)];
  const none = ["## C-numbers with no live attack here", "", ...NO_LIVE_ATTACK.map((n) => `- ${n.c}: ${n.why}.`)];
  writeFileSync(`${RESULTS}${name}`, [...header, "", ...table, "", ...footer, "", ...offline, "", ...none, ""].join("\n"), "utf8");
  return `security/results/${name}`;
}

async function live(): Promise<number> {
  const startedAt = Date.now();
  const stamp = new Date(startedAt).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  assertNoForeignSecrets();
  const env = loadSuiteEnv();
  installFetchGuard(env.blobOrigin === undefined ? {} : { blobOrigin: env.blobOrigin });
  assertServerTarget();
  const chain = await assertTestnet();
  const ctx = await Ctx.create(env, startedAt);
  const code = await ctx.client.getCode({ address: REGISTRY });
  if (code === undefined || keccak256(code) !== REGISTRY_CODE_KECCAK) throw new Error(`The code at ${REGISTRY} is not the BoardRegistry recorded at deploy. Stopping before any attack.`);
  const [pqc, kem] = await Promise.all([pqcStatus(ctx.wallet.qor1), kemOf(ctx.wallet.evm)]);
  if (!isOurProvenKey(pqc, ctx.wallet) || kem === undefined) throw new Error("The security wallet's keys are not registered. Run: npx tsx register-wallet.ts");
  const ping = await dev({ method: "GET", path: "/api/security-suite-ping", from: ctx.ips.fresh() }).catch(() => undefined);
  if (ping === undefined || ping.status !== 404 || ping.error !== "not_found" || !ownHeaders(ping)) {
    throw new Error("The dev server is not answering at 127.0.0.1:8787. In packages/server run: npx tsx scripts/dev-server.ts");
  }
  const commit = git(["rev-parse", "HEAD"]) || "unknown";
  const dirty = git(["status", "--porcelain", "--", "packages", "security"]);
  const startBalance = await balanceOf(ctx.wallet.qor1);

  ctx.log(`Ava attack suite, live run. Started ${new Date(startedAt).toISOString()}.`);
  ctx.log(`chain:    ${chain.cosmos} and EVM ${chain.evm} confirmed; registry code hash matches the deploy record`);
  ctx.log(`wallet:   ${ctx.wallet.qor1} / ${ctx.wallet.evm}, ${q(startBalance)}`);
  ctx.log(`code:     commit ${commit}${dirty === "" ? "" : " with uncommitted changes under packages/ or security/"}`);

  const rows: Row[] = [];
  let stopped: string | undefined;
  try {
    for (const { area, attack } of allAttacks()) {
      if (stopped !== undefined) {
        rows.push({ id: attack.id, claim: attack.claim, held: false, notRun: true, evidence: `${NOT_RUN}the run stopped at ${stopped}` });
        continue;
      }
      ctx.log(`\n${attack.id} (${area.name}): ${attack.claim}`);
      try {
        await ctx.prepare(attack.needs);
        const result = await attack.run(ctx);
        const notRun = result.evidence.startsWith(NOT_RUN);
        rows.push({ id: attack.id, claim: attack.claim, held: result.held, notRun, evidence: result.evidence });
        ctx.log(`  ${notRun ? "NOT RUN" : result.held ? "held" : "NOT HELD"}: ${result.evidence}`);
      } catch (err) {
        stopped = attack.id;
        const message = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
        rows.push({ id: attack.id, claim: attack.claim, held: false, notRun: false, evidence: `UNEXPECTED EXCEPTION, the run stopped here: ${message.slice(0, 600)}` });
        ctx.log(`  UNEXPECTED EXCEPTION, stopping: ${message.slice(0, 600)}`);
      }
    }
  } finally {
    try {
      const closed = await ctx.lane.close();
      ctx.log(`\nwindow:   ${closed === undefined ? "the wallet holds no live window" : `the wallet's window closed in ${closed}`}`);
    } catch (err) {
      ctx.log(`\nwindow:   the close failed (${err instanceof Error ? err.message.slice(0, 200) : String(err)}); close it before the next run`);
    }
  }

  const endBalance = await balanceOf(ctx.wallet.qor1).catch(() => undefined);
  const funded = ctx.people.fundedUqor.reduce((s, f) => s + f.uqor, 0n);
  const identityFees = ctx.people.fees.filter((f) => !f.what.startsWith("fund ")).reduce((s, f) => s + f.uqor, 0n);
  const held = rows.filter((r) => r.held).length;
  const notRunCount = rows.filter((r) => r.notRun).length;
  const footer: string[] = ["## Money", ""];
  if (endBalance === undefined) {
    footer.push("- The wallet's end balance could not be read.");
  } else {
    const spent = startBalance - endBalance;
    footer.push(`- Realised: ${q(spent - funded + identityFees)} burned in fees and gas (the wallet's own ${q(spent - funded)}, the test identities' registrations ${q(identityFees)}).`);
    footer.push(`- Unrealised: ${q(funded - identityFees)} sent to test identities this run and still held by them.`);
    footer.push(`- The wallet went from ${q(startBalance)} to ${q(endBalance)}. Our relayer's and sponsor's spend is not measured here; the hashes are in the evidence.`);
  }
  const header = [
    `# Attack run ${stamp}`,
    "",
    `- Code: commit ${commit}${dirty === "" ? "" : " (with uncommitted changes under packages/ or security/)"}`,
    `- Chain: ${chain.cosmos}, EVM ${chain.evm}; BoardRegistry ${REGISTRY}, code hash checked against the deploy record`,
    `- Server: packages/server/scripts/dev-server.ts on 127.0.0.1:8787`,
    `- Wallet: ${ctx.wallet.qor1} / ${ctx.wallet.evm}`,
    `- Started ${new Date(startedAt).toISOString()}, ended ${new Date().toISOString()}`,
    `- Result: ${held} of ${rows.length} held, ${notRunCount} not run, ${rows.length - held - notRunCount} not held${stopped === undefined ? "" : `; stopped at ${stopped} by an unexpected exception`}`,
  ];
  const path = writeResults(stamp, header, rows, footer);

  console.log("\n| id | claim | held | evidence |");
  for (const r of rows) console.log(`| ${r.id} | ${short(r.claim, 90)} | ${heldCell(r)} | ${short(r.evidence, 160)} |`);
  console.log(`\n${header.at(-1)!.slice(2)}`);
  for (const line of footer.slice(2)) console.log(line);
  console.log(`report:   ${path}`);
  return held === rows.length ? 0 : 1;
}

async function main(): Promise<void> {
  if (process.argv.includes("--dry-run")) {
    dryRun();
    return;
  }
  process.exitCode = await live();
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
