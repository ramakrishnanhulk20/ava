import { randomBytes } from "node:crypto";
import { accountBytes, deadlineFrom, newEpochKey, paramsCreate, paramsPost, sameAccount, sha256, signBoardAction, toHex, toQor1 } from "@ava/core";
import { bytesToHex, type Hex, type TransactionReceipt } from "viem";
import { GAS_CEILING, RELAY_LIMITS, WINDOW } from "../../packages/server/src/config.ts";
import { COST, notRun, verdict, type Attack, type Probe } from "../lib/attack.ts";
import { ethCall, isRegistryOnly, readEvmWindow, refusalOf, registryEvents, sleep } from "../lib/chain.ts";
import type { Ctx } from "../lib/context.ts";
import { admit, demoHistory, freshGuest, key, txHashOf } from "../lib/demo.ts";
import { dev, notConfigured, ownHeaders, said, type DevAnswer } from "../lib/dev.ts";
import { PROBE, REGISTRY } from "../lib/guard.ts";
import { FILL_PROFILE, type Person } from "../lib/identities.ts";
import { standingOf } from "../lib/people.ts";
import { Action, DEADLINE_SECONDS, ZERO_SIGNATURE, boardAt, boardCount, calldata, createNonceOf, random32, sealTo, sign, type Board } from "../lib/registry.ts";
import { verifiedDocument } from "./uploads.ts";

const JSON_HEADERS = { "content-type": "application/json" };
/** At most 30, split over two addresses so neither reaches its own per-IP limit of 20. */
const JUNK = 30;
/** The document C9 and C44 upload and verify, so their posts get past the relay's size check. */
const SIZE_TEST_BYTES = 4_096;

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
  costNote: `one ${SIZE_TEST_BYTES}-byte document in our own blob store, which the sweep deletes two hours on because no post names it; nothing is sent`,
  async run(ctx) {
    // The relay checks a post's verified size before its pre-flight, so only a verified document reaches the registry's check.
    const doc = await verifiedDocument(ctx, randomBytes(SIZE_TEST_BYTES));
    if ("why" in doc) return doc.unconfigured ? notRun(doc.why) : verdict([{ ok: false, line: `setup: ${doc.why}` }]);
    const from = ctx.ips.fresh();
    const id = ((await boardCount(ctx.client)) + 1_000_000n).toString();
    const deadline = (await ctx.deadline()).toString();
    const post = { action: "post", boardId: id, params: { docRef: random32(), cipherHash: `0x${doc.sha}`, cipherSize: String(doc.size), epoch: "0" }, deadline, signature: ZERO_SIGNATURE };
    const a = await relay(from, post);
    if (notConfigured(a)) return notRun(`the relay answers ${said(a)}`);
    const add = { action: "add", boardId: id, params: { member: ctx.wallet.evm, mode: "0", envelopeHash: random32(), envelopeSize: "1000", epochAfter: "0" }, deadline, signature: ZERO_SIGNATURE };
    return verdict(
      [
        expect(`post of document/${doc.sha.slice(0, 16)}..., uploaded with our handler's token and verified at ${doc.size} bytes, to board ${id}`, a, 422, "UnknownBoard"),
        expect(`addMember on board ${id}`, await relay(from, add), 422, "UnknownBoard"),
      ],
      `from ${from}: `,
    );
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

/** A post on one of the wallet's boards, signed by its chair at the board's nonce and epoch, as the relay body the app sends and as the calldata the relay builds from it. */
async function signedPost(ctx: Ctx, b: Board, cipherHash: Hex, cipherSize: bigint): Promise<{ body: string; data: Hex }> {
  const docRef = random32();
  const deadline = await ctx.deadline();
  const signature = sign(ctx.wallet, { action: Action.POST, boardId: b.id, paramsHash: paramsPost({ docRef, cipherHash, cipherSize, epoch: b.epoch }), nonce: b.nonce, deadline });
  return {
    body: JSON.stringify({ action: "post", boardId: b.id.toString(), params: { docRef, cipherHash, cipherSize: cipherSize.toString(), epoch: b.epoch.toString() }, deadline: deadline.toString(), signature }),
    data: calldata.postDocument({ boardId: b.id, docRef, cipherHash, cipherSize, epoch: b.epoch, deadline, signature }),
  };
}

const sizeMismatch: Attack = {
  id: "C44-size-mismatch",
  claim: `A post's size must be the size we hold: on the wallet's own board A, a chair-signed post of a ${SIZE_TEST_BYTES}-byte document our server verified, carrying a cipherSize one byte larger, is refused 422 size_mismatch, and a chair-signed post naming a hash nobody uploaded is refused 422 document_unverified. The registry would take both posts, and in both cases the board's nonce does not move and nothing is sent.`,
  costUqor: 0n,
  costNote: `one ${SIZE_TEST_BYTES}-byte document in our own blob store, which the sweep deletes two hours on because no post names it; nothing is sent`,
  needs: ["boards"],
  async run(ctx) {
    const { a: boardId } = await ctx.boards();
    const doc = await verifiedDocument(ctx, randomBytes(SIZE_TEST_BYTES));
    if ("why" in doc) return doc.unconfigured ? notRun(doc.why) : verdict([{ ok: false, line: `setup: ${doc.why}` }]);
    const relayer = ctx.state.relayer;
    const probes: Probe[] = [{ ok: true, line: `setup: document/${doc.sha.slice(0, 16)}... uploaded with our handler's token and verified at ${doc.size} bytes` }];
    const cases: [label: string, cipherHash: Hex, cipherSize: bigint, error: string][] = [
      [`the verified document posted with cipherSize ${doc.size + 1}`, `0x${doc.sha}`, BigInt(doc.size + 1), "size_mismatch"],
      ["a post naming a hash nobody uploaded", random32(), BigInt(doc.size), "document_unverified"],
    ];
    for (const [label, cipherHash, cipherSize, error] of cases) {
      const before = await boardAt(ctx.client, boardId);
      const sentBefore = relayer === undefined ? undefined : await ctx.client.getTransactionCount({ address: relayer.evm, blockTag: "pending" });
      const post = await signedPost(ctx, before, cipherHash, cipherSize);
      // Only a post the registry itself would take shows that the refusal is the server's size rule.
      const control = await ethCall(ctx.client, { from: relayer?.evm ?? ctx.wallet.evm, to: REGISTRY, data: post.data });
      const a = await relay(ctx.ips.fresh(), post.body);
      if (notConfigured(a)) return notRun(`the relay answers ${said(a)}`);
      const after = await boardAt(ctx.client, boardId);
      const still = txHashOf(a) === undefined && after.nonce === before.nonce && after.documentCount === before.documentCount;
      probes.push(
        { ok: control.ok, line: `${label}: the registry's eth_call of that exact post ${control.ok ? "passes" : `REFUSES IT: ${refusalOf(control).text}`}` },
        expect(`${label}, relayed`, a, 422, error),
        { ok: still, line: `board ${boardId}: nonce ${before.nonce} before and ${after.nonce} after, ${before.documentCount} documents before and ${after.documentCount} after, ${txHashOf(a) === undefined ? "no transaction hash answered" : `ANSWERED ${txHashOf(a)}`}` },
      );
      if (relayer !== undefined && sentBefore !== undefined) {
        const sentAfter = await ctx.client.getTransactionCount({ address: relayer.evm, blockTag: "pending" });
        probes.push({ ok: sentAfter === sentBefore, line: `the relayer ${relayer.evm}: nonce ${sentBefore} before and ${sentAfter} after (a judge's action in these seconds would move it too)` });
      }
    }
    if (relayer === undefined) probes.push({ ok: true, line: "not covered here: C24-target-ignored named no relayer this run, so the relayer's own nonce was not read" });
    return verdict(probes);
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
  serverUqor: COST.join + COST.remove,
  costNote: "the guest is the identity the sponsor funded in C27, which pays its own registrations; our relayer pays the admission, and the removal of the background pass it starts when it leaves the demo board above 34",
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

const COPIES = 5;
/**
 * The first body gets this head start so it is likely the one past its pre-flight first. The relay
 * answers only after the receipt, so the copies still arrive while the first is pending.
 */
const COPY_HEAD_START_MS = 300;

/** A ROTATE of one of the wallet's boards, signed by signBoardAction from one block's view of it, as the relay body the app sends. */
async function signedRotate(ctx: Ctx, boardId: bigint): Promise<string> {
  const b = await boardAt(ctx.client, boardId);
  const epochAfter = b.epoch + 1n;
  const envelope = await sealTo(b.members, b.boardRef, epochAfter, newEpochKey());
  const envelopeHash = ctx.blobs.put(envelope);
  const deadline = deadlineFrom(b.timestamp, DEADLINE_SECONDS);
  const { signature } = signBoardAction(ctx.wallet.pqc.secretKey, {
    action: Action.ROTATE,
    envelopeHash,
    envelopeSize: envelope.length,
    epochAfter,
    registry: REGISTRY,
    boardId,
    nonce: b.nonce,
    deadline,
    latestBlockTimestamp: b.timestamp,
  });
  return JSON.stringify({
    action: "rotate",
    boardId: boardId.toString(),
    params: { envelopeHash, envelopeSize: String(envelope.length), epochAfter: epochAfter.toString() },
    deadline: deadline.toString(),
    signature: bytesToHex(signature),
  });
}

const landed = (ctx: Ctx, hash: Hex | undefined): Promise<TransactionReceipt | undefined> =>
  hash === undefined ? Promise.resolve(undefined) : ctx.client.waitForTransactionReceipt({ hash, timeout: 120_000, pollingInterval: 2_000 });

const copies: Attack = {
  id: "C40-copies",
  claim: `Copies of one signed action are served once: the wallet's own ROTATE of its board B, sent to the relay and then posted byte for byte ${COPIES} more times at once while it is pending, is relayed once and every copy answers 409 duplicate; the chair's next, different action is still served.`,
  costUqor: 0n,
  serverUqor: 2n * COST.addRotate,
  costNote: "our relayer pays for two rotations of board B, priced here as two rotating adds; the wallet pays nothing",
  needs: ["boards"],
  async run(ctx) {
    const { b: boardId } = await ctx.boards();
    const from = ctx.ips.fresh();
    const before = await boardAt(ctx.client, boardId);
    const body = await signedRotate(ctx, boardId);
    const original = relay(from, body);
    await sleep(COPY_HEAD_START_MS);
    const copied = Promise.all(Array.from({ length: COPIES }, () => relay(from, body)));
    const answers = [await original, ...(await copied)];
    const unready = answers.find(notConfigured);
    if (unready !== undefined) return notRun(`the relay answers ${said(unready)}`);

    const served = answers.flatMap((a, i) => {
      const hash = txHashOf(a);
      return hash === undefined ? [] : [{ i, hash }];
    });
    const duplicates = answers.filter((a) => a.status === 409 && a.error === "duplicate" && ownHeaders(a)).length;
    const tally = new Map<string, number>();
    for (const a of answers) tally.set(said(a), (tally.get(said(a)) ?? 0) + 1);
    const late = answers.some((a) => a.status === 422) ? " (a 422 is a copy that reached its pre-flight after the first had landed: run it again)" : "";
    const which = served.length === 1 ? (served[0]!.i === 0 ? "the first" : `copy ${served[0]!.i}, which passed its pre-flight first`) : `${served.length} of them`;
    const receipt = served.length === 1 ? await landed(ctx, served[0]!.hash) : undefined;
    const mid = await boardAt(ctx.client, boardId);

    const next = await relay(ctx.ips.fresh(), await signedRotate(ctx, boardId));
    const nextHash = txHashOf(next);
    const nextReceipt = await landed(ctx, nextHash);
    const after = await boardAt(ctx.client, boardId);
    return verdict([
      {
        ok: served.length === 1 && duplicates === COPIES,
        line: `${COPIES + 1} byte-identical ROTATE bodies for board ${boardId} from ${from}, the first and ${COPIES} more ${COPY_HEAD_START_MS} ms later: ${[...tally].map(([k, n]) => `${n} x ${k}`).join(", ")}${late}, served ${which}`,
      },
      {
        ok: receipt?.status === "success" && mid.nonce === before.nonce + 1n && mid.epoch === before.epoch + 1n,
        line: `${served[0]?.hash ?? "nothing relayed"}: ${receipt?.status ?? "no receipt"}, board ${boardId} moved once, nonce ${before.nonce} to ${mid.nonce} and epoch ${before.epoch} to ${mid.epoch}`,
      },
      {
        ok: nextReceipt?.status === "success" && after.epoch === mid.epoch + 1n,
        line: `then the chair's next, different ROTATE -> ${said(next)}${nextHash === undefined ? "" : ` ${nextHash}, ${nextReceipt?.status ?? "no receipt"}`}, epoch ${after.epoch}`,
      },
      {
        ok: true,
        line: `not covered here: ${COPIES} copies sit far under the per-chair limit of ${RELAY_LIMITS.perChair}, so this shows the next action is served, not by itself that the copies moved no counter; packages/server/test/relay.test.ts proves that with 60 copies`,
      },
    ]);
  },
};

export const attacks: readonly Attack[] = [target, strict, unknownBoard, windowScope, sizeMismatch, flood, copies];
