import { SPONSOR_AMOUNT_UQOR } from "../../packages/server/src/config.ts";
import { COST, notRun, verdict, type Attack, type Probe } from "../lib/attack.ts";
import { balanceOf, sleep } from "../lib/chain.ts";
import type { Ctx } from "../lib/context.ts";
import { dev, notConfigured, ownHeaders, said, type DevAnswer } from "../lib/dev.ts";
import { PROBE, REGISTRY } from "../lib/guard.ts";
import { SPONSORED_RANGE } from "../lib/identities.ts";
import { standingOf } from "../lib/people.ts";

const JSON_HEADERS = { "content-type": "application/json" };
const MAX_FRESH_TRIES = 3;

const ask = (ctx: Ctx, address: string): Promise<DevAnswer> =>
  dev({ method: "POST", path: "/api/sponsor", from: ctx.ips.fresh(), headers: JSON_HEADERS, body: JSON.stringify({ address }), timeoutMs: 90_000 });

const expect = (label: string, a: DevAnswer, status: number, error: string): Probe => ({ ok: a.status === status && a.error === error && ownHeaders(a), line: `${label} -> ${said(a)}` });

async function balanceReaches(qor1: string, target: bigint, withinMs: number): Promise<bigint> {
  let balance = await balanceOf(qor1);
  for (const started = Date.now(); balance < target && Date.now() - started < withinMs; ) {
    await sleep(3_000);
    balance = await balanceOf(qor1);
  }
  return balance;
}

/** A qor1 address with its last checksum character swapped for another valid one. */
const badChecksum = (qor1: string): string => `${qor1.slice(0, -1)}${qor1.at(-1) === "q" ? "p" : "q"}`;

const second: Attack = {
  id: "C27-second-request",
  claim: "The sponsor funds each new identity once: a fresh identity is sent exactly 0.25 QOR, and a second request for the same account, by its 0x form, is refused and sends nothing.",
  costUqor: 0n,
  serverUqor: COST.sponsor,
  costNote: "the sponsor pays, not the wallet; the funded identity then registers its own keys and joins the demo board in C40",
  async run(ctx) {
    for (let index = SPONSORED_RANGE.from, tries = 0; index <= SPONSORED_RANGE.to && tries < MAX_FRESH_TRIES; index++) {
      const person = await ctx.people.derive(index, "sponsored");
      const before = await standingOf(person);
      if (before.balance !== 0n || before.pqc.registered) continue;
      tries++;
      const first = await ask(ctx, person.qor1);
      if (notConfigured(first)) return notRun(`the sponsor answers ${said(first)}`);
      // An earlier run whose send failed leaves the once-only mark behind: take the next fresh identity.
      if (first.status === 409 && first.error === "already_sponsored") continue;
      if (first.status !== 202) return notRun(`the first request for a fresh identity answered ${said(first)}`);
      const funded = await balanceReaches(person.qor1, SPONSOR_AMOUNT_UQOR, 60_000);
      const again = await ask(ctx, person.evm);
      await sleep(8_000);
      const after = await balanceOf(person.qor1);
      ctx.state.sponsoredIndex = index;
      const hash = (first.json as { txHash?: unknown }).txHash;
      return verdict([
        { ok: funded === SPONSOR_AMOUNT_UQOR, line: `first request for ${person.qor1} -> 202 ${String(hash)}; its balance went from 0 to ${funded} uqor` },
        expect(`second request, by ${person.evm}`, again, 409, "already_sponsored"),
        { ok: after === funded, line: `balance after the second request: ${after} uqor` },
      ]);
    }
    return notRun("no fresh identity left to try in the sponsored range");
  },
};

const funded: Attack = {
  id: "C27-funded",
  claim: "Eligibility is read from the chain: an address that holds even 1 uqor is refused.",
  costUqor: 0n,
  needs: ["dust"],
  async run(ctx) {
    const dust = await ctx.need("dust");
    const balance = await balanceOf(dust.qor1);
    const a = await ask(ctx, dust.qor1);
    if (notConfigured(a)) return notRun(`the sponsor answers ${said(a)}`);
    return verdict([{ ok: balance > 0n, line: `setup: ${dust.qor1} holds ${balance} uqor and no key` }, expect("sponsor it", a, 403, "already_funded")]);
  },
};

const contract: Attack = {
  id: "C27-contract",
  claim: "A contract can never register a key, so the sponsor refuses to fund one: both of our contracts are refused.",
  costUqor: 0n,
  async run(ctx) {
    const r = await ask(ctx, REGISTRY);
    if (notConfigured(r)) return notRun(`the sponsor answers ${said(r)}`);
    return verdict([expect(`the BoardRegistry ${REGISTRY}`, r, 403, "contract_address"), expect(`the PqcProbe ${PROBE}`, await ask(ctx, PROBE), 403, "contract_address")]);
  },
};

const lowercase: Attack = {
  id: "C16-sponsor-lowercase",
  claim: "Addresses in a request are decoded strictly: an all-lowercase 0x address, a qor1 with a bad checksum and the zero account are refused before anything is read or sent.",
  costUqor: 0n,
  async run(ctx) {
    const stranger = await ctx.people.role("stranger");
    const a = await ask(ctx, stranger.evm.toLowerCase());
    if (notConfigured(a)) return notRun(`the sponsor answers ${said(a)}`);
    return verdict([
      expect(`${stranger.evm.toLowerCase()}`, a, 400, "bad_address"),
      expect(`${badChecksum(stranger.qor1)}`, await ask(ctx, badChecksum(stranger.qor1)), 400, "bad_address"),
      expect("0x0000000000000000000000000000000000000000", await ask(ctx, "0x0000000000000000000000000000000000000000"), 400, "bad_address"),
    ]);
  },
};

export const attacks: readonly Attack[] = [second, funded, contract, lowercase];
