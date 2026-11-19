import { accountBytes, newEpochKey, paramsCreate, sameAccount, sha256, toHex, toQor1 } from "@ava/core";
import { bytesToHex, type Hex } from "viem";
import { GAS_CEILING, RELAY_LIMITS, WINDOW } from "../../packages/server/src/config.ts";
import { COST, notRun, verdict, type Attack, type Probe } from "../lib/attack.ts";
import { isRegistryOnly, readEvmWindow, registryEvents } from "../lib/chain.ts";
import type { Ctx } from "../lib/context.ts";
import { admit, demoHistory, freshGuest, key } from "../lib/demo.ts";
import { dev, notConfigured, ownHeaders, said, type DevAnswer } from "../lib/dev.ts";
import { PROBE, REGISTRY } from "../lib/guard.ts";
import { FILL_PROFILE, type Person } from "../lib/identities.ts";
import { standingOf } from "../lib/people.ts";
import { Action, ZERO_SIGNATURE, boardAt, boardCount, calldata, createNonceOf, random32, sealTo, sign } from "../lib/registry.ts";

const JSON_HEADERS = { "content-type": "application/json" };
/** At most 30, split over two addresses so neither reaches its own per-IP limit of 20. */
const JUNK = 30;

const relay = (from: string, body: unknown): Promise<DevAnswer> =>
  dev({ method: "POST", path: "/api/relay", from, headers: JSON_HEADERS, body: typeof body === "string" ? body : JSON.stringify(body), timeoutMs: 90_000 });

const expect = (label: string, a: DevAnswer, status: number, error: string): Probe => ({ ok: a.status === status && a.error === error && ownHeaders(a), line: `${label} -> ${said(a)}` });

/** A create body for `chair` with a signature no key made: right shape, so only the registry's check can refuse it. */
async function junkCreate(ctx: Ctx, chair: Hex): Promise<Record<string, unknown>> {
  return {
    action: "create",
    params: { chair: toHex(accountBytes(chair)), boardRef: random32(), envelopeHash: random32(), envelopeSize: "1000" },
    deadline: (await ctx.deadline()).toString(),
    signature: ZERO_SIGNATURE,
  };
}

const target: Attack = {
  id: "C24-target-ignored",
  claim: "The relayer pays only for valid actions on our own contract: a real chair-signed create whose body also names another target, a value, a gas limit and calldata lands on the registry with the calldata the server built itself, and every extra field has no effect.",
  costUqor: 0n,
  serverUqor: COST.create + COST.windowOpen,
  costNote: "our relayer pays for one createBoard, and a window open if its window needs renewing",
  async run(ctx) {
    const w = ctx.wallet;
    const boardRef = random32();
    const envelope = await sealTo([w.evm], boardRef, 0n, newEpochKey());
    const envelopeHash = bytesToHex(sha256(envelope));
    const nonce = await createNonceOf(ctx.client, w.evm);
    const deadline = await ctx.deadline();
    const signature = sign(w, { action: Action.CREATE, boardId: 0n, paramsHash: paramsCreate({ chair: w.evm, boardRef, envelopeHash, envelopeSize: envelope.length }), nonce, deadline });
    const body = {
      action: "create",
      params: { chair: w.evm, boardRef, envelopeHash, envelopeSize: String(envelope.length) },
      deadline: deadline.toString(),
      signature,
      target: PROBE,
      to: PROBE,
      value: "1000000000000",
      gas: "21000",
      from: w.evm,
      data: "0xdeadbeef",
      chainId: "1",
    };
    const a = await relay(ctx.ips.fresh(), body);
    if (notConfigured(a)) return notRun(`the relay answers ${said(a)}`);
    const hash = (a.json as { txHash?: unknown } | undefined)?.txHash;
    if (a.status !== 202 || typeof hash !== "string") return verdict([{ ok: false, line: `relay -> ${said(a)}` }]);
    const receipt = await ctx.client.waitForTransactionReceipt({ hash: hash as Hex, timeout: 120_000, pollingInterval: 2_000 });
    const tx = await ctx.client.getTransaction({ hash: hash as Hex });
    const built = calldata.createBoard({ chair: w.evm, boardRef, envelopeHash, envelopeSize: envelope.length, deadline, signature });
    const created = registryEvents(receipt).find((e) => e.eventName === "BoardCreated");
    ctx.state.relayer = { evm: toHex(accountBytes(tx.from)), qor1: toQor1(accountBytes(tx.from)) };
    return verdict([
      { ok: tx.to !== null && sameAccount(tx.to, REGISTRY), line: `relay -> 202 ${hash}; sent to ${tx.to} (the body named ${PROBE})` },
      { ok: tx.value === 0n, line: `value ${tx.value} (the body asked for 1000000000000)` },
      { ok: tx.input.toLowerCase() === built.toLowerCase(), line: `calldata ${tx.input.toLowerCase() === built.toLowerCase() ? "is exactly" : "DIFFERS FROM"} the createBoard built from the typed fields (the body offered 0xdeadbeef)` },
      { ok: tx.gas === GAS_CEILING.create, line: `gas limit ${tx.gas}, the server's own ceiling for a create (the body asked for 21000)` },
      { ok: receipt.status === "success" && created !== undefined && sameAccount(String(created.args.chair), w.evm), line: `receipt ${receipt.status}, BoardCreated for chair ${String(created?.args.chair)}` },
    ]);
  },
};

const strict: Attack = {
  id: "C24-body-strict",
  claim: "The relay reads only typed fields: an extra field inside params, an unknown action, a signature of the wrong length and a lowercase chair address are refused before any chain call.",
  costUqor: 0n,
  async run(ctx) {
    const from = ctx.ips.fresh();
    const base = await junkCreate(ctx, ctx.wallet.evm);
    const params = base.params as Record<string, unknown>;
    const first = await relay(from, { ...base, params: { ...params, target: PROBE } });
    if (notConfigured(first)) return notRun(`the relay answers ${said(first)}`);
    return verdict(
      [
        expect("params with an extra target field", first, 400, "bad_body"),
        expect("action transfer_funds", await relay(from, { ...base, action: "transfer_funds" }), 400, "bad_body"),
        expect("a 100-byte signature", await relay(from, { ...base, signature: `0x${"00".repeat(100)}` }), 400, "bad_body"),
        expect("chair in all-lowercase 0x", await relay(from, { ...base, params: { ...params, chair: ctx.wallet.evm.toLowerCase() } }), 400, "bad_body"),
      ],
      `from ${from}: `,
    );
  },
};

const unknownBoard: Attack = {
  id: "C9-unknown-board",
  claim: "Real boards are the ones the registry made: a post and an addMember for a board id the registry never issued are refused by the relay's pre-flight with the registry's own UnknownBoard.",
  costUqor: 0n,
  async run(ctx) {
    const from = ctx.ips.fresh();
    const id = ((await boardCount(ctx.client)) + 1_000_000n).toString();
    const deadline = (await ctx.deadline()).toString();
    const post = { action: "post", boardId: id, params: { docRef: random32(), cipherHash: random32(), cipherSize: "1000", epoch: "0" }, deadline, signature: ZERO_SIGNATURE };
    const a = await relay(from, post);
    if (notConfigured(a)) return notRun(`the relay answers ${said(a)}`);
    const add = { action: "add", boardId: id, params: { member: ctx.wallet.evm, mode: "0", envelopeHash: random32(), envelopeSize: "1000", epochAfter: "0" }, deadline, signature: ZERO_SIGNATURE };
    return verdict([expect(`post to board ${id}`, a, 422, "UnknownBoard"), expect(`addMember on board ${id}`, await relay(from, add), 422, "UnknownBoard")], `from ${from}: `);
  },
};

const windowScope: Attack = {
  id: "C25-window-scope",
  claim: "The relayer's window stays narrow: read back from the chain, it admits calls to the registry alone, never native-only or unscoped, at the 40-transaction, 12,000-block shape and within its value cap.",
  costUqor: 0n,
  costNote: "reads only; the leak halt is proven offline (packages/server/test/window.test.ts) and never triggered live",
  async run(ctx) {
    const relayer = ctx.state.relayer;
    if (relayer === undefined) return notRun("C24-target-ignored landed no relayed transaction to name the relayer");
    const w = await readEvmWindow(relayer.qor1);
    if (!w.found || !w.live) return { held: true, evidence: `the relayer ${relayer.qor1} holds no live window now (found ${w.found}): nothing a leaked classical key could spend` };
    return verdict([
      { ok: isRegistryOnly(w), line: `allowed_targets [${w.allowedTargets.join(", ")}], native-only ${w.nativeOnly}` },
      { ok: w.maxTxs === BigInt(WINDOW.maxTxs) && w.expiryHeight - w.openedHeight === BigInt(WINDOW.blocks), line: `${w.maxTxs} transactions over ${w.expiryHeight - w.openedHeight} blocks` },
      { ok: w.maxValue > 0n && w.maxValue <= WINDOW.maxValue, line: `max_value ${w.maxValue} uqor, cap ${WINDOW.maxValue}` },
    ], `relayer ${relayer.qor1}: `);
  },
};

/** The guest C40 admits: the identity the sponsor funded in C27 when it is still fresh, or a pool identity. */
async function floodGuest(ctx: Ctx, boardId: bigint): Promise<Person> {
  const h = await demoHistory(ctx, boardId);
  if (ctx.state.sponsoredIndex !== undefined) {
    const person = await ctx.people.derive(ctx.state.sponsoredIndex, "sponsored");
    const s = await standingOf(person);
    if (!h.admitted.has(key(person.evm)) && s.balance > 0n) {
      await ctx.people.ensureAll([{ person, profile: FILL_PROFILE }]);
      return person;
    }
  }
  return freshGuest(ctx, boardId, "flood-guest");
}

const flood: Attack = {
  id: "C40-junk-flood",
  claim: `Junk cannot starve a chair's real actions: ${JUNK} junk create bodies naming the demo chair, from two other addresses, are refused by the registry's own check, and the next real action for that chair, a guest's admission, still lands.`,
  costUqor: 0n,
  serverUqor: COST.join,
  costNote: "the guest is the identity the sponsor funded in C27, which pays its own registrations; our relayer pays the admission",
  async run(ctx) {
    const boardId = ctx.env.demoBoardId;
    if (boardId === undefined) return notRun("DEMO_BOARD_ID is not set in security/.env");
    const board = await boardAt(ctx.client, boardId);
    const guest = await floodGuest(ctx, boardId);
    const ips = [ctx.ips.fresh(), ctx.ips.fresh()];
    const tally = new Map<string, number>();
    for (let i = 0; i < JUNK; i++) {
      const a = await relay(ips[i % 2]!, await junkCreate(ctx, board.chair));
      if (notConfigured(a)) return notRun(`the relay answers ${said(a)}`);
      tally.set(said(a), (tally.get(said(a)) ?? 0) + 1);
    }
    const allRefused = tally.size === 1 && tally.get("422 BadSignature") === JUNK;
    const joined = await admit(ctx, guest);
    const after = await boardAt(ctx.client, boardId);
    return verdict([
      { ok: allRefused, line: `${JUNK} junk creates naming ${board.chair} from ${ips.join(" and ")}: ${[...tally].map(([k, n]) => `${n} x ${k}`).join(", ")}` },
      { ok: joined.landed, line: `then ${guest.evm} joins from a third address: ${joined.steps}` },
      { ok: after.members.some((m) => sameAccount(m, guest.evm)), line: `the guest is a member of board ${boardId}` },
      {
        ok: true,
        line: `not covered here: ${JUNK} is under the per-chair limit of ${RELAY_LIMITS.perChair}, so this run shows the real action lands, not by itself that junk never counted against the chair; packages/server/test/relay.test.ts proves the count with 60`,
      },
    ]);
  },
};

export const attacks: readonly Attack[] = [target, strict, unknownBoard, windowScope, flood];
