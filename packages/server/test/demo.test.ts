// Not covered here: the live chain and the live blob store. The registry, pqcKeyStatus, qor_getKEMKey
// and the receipts come from stubs, and the relayer's chain is a stub that accepts every pre-flight,
// so whether the registry really accepts the bot's addMember and removeMember is checked by
// scripts/live-demo-check.ts and scripts/seed-demo-board.ts. Signatures, envelopes, the upload path,
// the relay pipeline and the shared store are the real code.
import {
  Action,
  KemKeyUnavailable,
  Mode,
  actionMessage,
  generateMnemonic,
  identityFromMnemonic,
  newEpochKey,
  openEpochKey,
  paramsAdd,
  sealEpochKey,
  sha256,
  signAction,
  toHex,
  verifyAction,
  type Identity,
  type KemKeyFailure,
} from "@ava/core";
import type { EvmWindow } from "@qorechain/evm";
import { generateSealKeys } from "@qorechain/qoreseal";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { bytesToHex, decodeFunctionData, encodeFunctionResult, hexToBytes, toFunctionSelector, type Hex } from "viem";
import { boardRegistryAbi } from "../src/abi/boardRegistry.ts";
import { MemoryBlobBackend, handleUpload } from "../src/blob.ts";
import type { EvmSend, RelayChain, TxRequest } from "../src/chain/types.ts";
import { DEMO_GUEST_CAP, REGISTRY_ADDRESS, WINDOW } from "../src/config.ts";
import { admittedKey, challengeKey, handleDemoChallenge, handleDemoJoin, sweepDemoGuests, type DemoContext } from "../src/demo.ts";
import type { BoardSnapshot, DemoChain, Grant, KeyStatus } from "../src/demoBoard.ts";
import { loadEnv } from "../src/env.ts";
import { MemoryStore } from "../src/store.ts";

// The real upload handler, wrapped so one test can rewrite its answer.
vi.mock("../src/blob.ts", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/blob.ts")>();
  return { ...real, handleUpload: vi.fn(real.handleUpload) };
});

const NOW = Date.parse("2026-11-19T12:00:00Z");
const HOUR = 3_600_000;
const BOARD_ID = 9n;
const ORIGIN = "https://blobs.example";
const RELAYER = { qor1: "qor1xss2hc8w33twyssdzejd7hepmd3qxgywvplhff", evm: "0x3420ABE0Ee8c56e2420D1664dF5F21db6203208e" } as const;
const ZERO: Hex = "0x0000000000000000000000000000000000000000";
const GET_BOARD = toFunctionSelector("getBoard(uint256)");
const GWEI = 1_000_000_000n;
const ROOMY = { join: { perIp: 100, windowSeconds: 3600, perDay: 100 }, challenge: { perIp: 100, total: 1000, windowSeconds: 3600 } };

let chairPhrase: string;
let chair: Identity;
let asha: Identity;
let ben: Identity;
let g1: Identity;
let g2: Identity;
let g3: Identity;
let g4: Identity;

beforeAll(async () => {
  chairPhrase = generateMnemonic();
  const ids = await Promise.all([chairPhrase, ...Array.from({ length: 6 }, () => generateMnemonic())].map((m) => identityFromMnemonic(m)));
  [chair, asha, ben, g1, g2, g3, g4] = ids as [Identity, Identity, Identity, Identity, Identity, Identity, Identity];
}, 60_000);

let logged: string[] = [];

beforeEach(() => {
  logged = [];
  vi.spyOn(console, "warn").mockImplementation((line: unknown) => {
    logged.push(String(line));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** A board member for sealing only: an account and its QoreSeal keys, with no ML-DSA key. */
type Member = Pick<Identity, "evm" | "seal">;

/** Guests that only hold a seat and an ML-KEM key, to fill the demo board up to its cap. */
function fillers(count: number): Member[] {
  return Array.from({ length: count }, (_, i) => ({ evm: toHex(Uint8Array.from({ length: 20 }, (_, j) => (j === 19 ? i + 1 : 0xf0))), seal: generateSealKeys() }));
}

/** The QoreSeal error code a call throws, or undefined when it does not throw. */
function codeOf(fn: () => unknown): unknown {
  try {
    fn();
    return undefined;
  } catch (error) {
    return (error as { code?: unknown }).code;
  }
}

const proven = (who: Identity): KeyStatus => ({ registered: true, algorithmId: 1, pubkey: who.mldsa.publicKey, possessionProven: true });

interface BoardState {
  boardRef: Hex;
  epoch: bigint;
  nonce: bigint;
  members: Hex[];
  grants: Grant[];
}

/** A board whose current epoch's envelope is sealed to every member, stored where the bot looks for it. */
async function seededBoard(blobs: MemoryBlobBackend, members: Member[]): Promise<{ state: BoardState; epochKey: Uint8Array }> {
  const boardRef = bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
  const epoch = 3n;
  const epochKey = newEpochKey();
  const envelope = sealEpochKey({ registry: REGISTRY_ADDRESS, boardRef, epoch, epochKey, recipients: members.map((m) => ({ address: m.evm, kemPublicKey: m.seal.mlkemPublicKey })) });
  const envelopeHash = bytesToHex(sha256(envelope));
  await blobs.put(`envelope/${envelopeHash.slice(2)}`, envelope);
  return {
    state: { boardRef, epoch, nonce: 11n, members: members.map((m) => m.evm), grants: [{ envelopeHash, envelopeSize: envelope.length, mode: Mode.ROTATE, member: ZERO }] },
    epochKey: Uint8Array.from(epochKey),
  };
}

function demoChain(state: BoardState, statuses: Map<string, KeyStatus>, kems: Map<string, Uint8Array>, kemFailures: Map<string, KemKeyFailure>, receipt: "success" | "reverted" = "success") {
  const counts = { board: 0, keyStatus: 0, kem: 0 };
  const chain: DemoChain = {
    board: async (boardId): Promise<BoardSnapshot> => {
      counts.board += 1;
      return { boardId, blockNumber: 100n, blockTimestamp: BigInt(NOW / 1000), chair: chair.evm, ...state, members: [...state.members], grants: [...state.grants] };
    },
    keyStatus: async (account) => {
      counts.keyStatus += 1;
      return statuses.get(account.toLowerCase()) ?? { registered: false, algorithmId: 0, pubkey: new Uint8Array(), possessionProven: false };
    },
    kemKey: async (account) => {
      counts.kem += 1;
      // The live lookup, fetchKemKey, answers every failure with KemKeyUnavailable.
      const failure = kemFailures.get(account.toLowerCase());
      if (failure !== undefined) throw new KemKeyUnavailable(failure, "stub failure");
      const key = kems.get(account.toLowerCase());
      if (key === undefined) throw new KemKeyUnavailable("NOT_FOUND", "stub has no key");
      return key;
    },
    receipt: async () => receipt,
  };
  return { chain, counts };
}

/**
 * The relayer's chain: a usable window, the registry's getBoard, and every pre-flight accepted. Given
 * the board's state, it also lands each removeMember and addMember the bot sends, as the registry would.
 */
function relayChain(board?: BoardState) {
  const sends: EvmSend[] = [];
  const preflights: TxRequest[] = [];
  const window: EvmWindow = {
    found: true,
    live: true,
    openedHeight: 1_000n,
    expiryHeight: 1_000n + BigInt(WINDOW.blocks),
    maxTxs: BigInt(WINDOW.maxTxs),
    usedTxs: 0n,
    maxValue: WINDOW.maxValue,
    usedValue: 0n,
    remainingBlocks: BigInt(WINDOW.blocks),
    remainingTxs: BigInt(WINDOW.maxTxs),
    remainingValue: WINDOW.maxValue,
    nativeOnly: false,
    allowedTargets: [REGISTRY_ADDRESS.toLowerCase()],
  };
  const chain: RelayChain = {
    readWindow: async () => window,
    openWindow: async () => ({ hash: "CD".repeat(32) }),
    closeWindow: async () => ({ hash: "EF".repeat(32) }),
    call: async (req) => {
      if (req.data.startsWith(GET_BOARD)) {
        const result = { chair: chair.evm, boardRef: `0x${"11".repeat(32)}` as Hex, epoch: 3n, nonce: 11n, memberCount: 3, documentCount: 0 };
        return { ok: true, data: encodeFunctionResult({ abi: boardRegistryAbi, functionName: "getBoard", result }) };
      }
      preflights.push(req);
      return { ok: true, data: "0x" };
    },
    estimateGas: async () => 300_000n,
    feeQuote: async () => ({ baseFeePerGas: 100n * GWEI, maxPriorityFeePerGas: GWEI }),
    send: async (tx) => {
      sends.push(tx);
      if (board !== undefined) land(board, tx);
      return `0x${sends.length.toString(16).padStart(64, "0")}`;
    },
  };
  return { chain, sends, preflights };
}

/** What the registry does with the bot's own removeMember and addMember once they land. */
function land(board: BoardState, tx: EvmSend): void {
  const decoded = decodeFunctionData({ abi: boardRegistryAbi, data: tx.data });
  if (decoded.functionName === "removeMember") {
    const [, member, envelopeHash, envelopeSize, epochAfter] = decoded.args as unknown as readonly [bigint, Hex, Hex, number, bigint];
    Object.assign(board, {
      epoch: epochAfter,
      nonce: board.nonce + 1n,
      members: board.members.filter((m) => m.toLowerCase() !== member.toLowerCase()),
      grants: [{ envelopeHash, envelopeSize, mode: Mode.ROTATE, member: ZERO }],
    });
  }
  if (decoded.functionName === "addMember") {
    const [, member, mode, envelopeHash, envelopeSize] = decoded.args as unknown as readonly [bigint, Hex, number, Hex, number];
    Object.assign(board, { nonce: board.nonce + 1n, members: [...board.members, member], grants: [...board.grants, { envelopeHash, envelopeSize, mode, member }] });
  }
}

async function setup(options: { members?: Member[]; seeded?: Identity[]; boardId?: bigint; receipt?: "success" | "reverted"; storeNow?: () => number; landSends?: boolean } = {}) {
  const blobs = new MemoryBlobBackend(ORIGIN, { now: () => NOW });
  const members = options.members ?? [chair, asha, ben];
  const { state, epochKey } = await seededBoard(blobs, members);
  const everyone = [chair, asha, ben, g1, g2, g3, g4];
  const statuses = new Map(everyone.map((who) => [who.evm.toLowerCase(), proven(who)]));
  const kems = new Map([...everyone, ...members].map((who) => [who.evm.toLowerCase(), who.seal.mlkemPublicKey]));
  const kemFailures = new Map<string, KemKeyFailure>();
  const demo = demoChain(state, statuses, kems, kemFailures, options.receipt);
  const relay = relayChain(options.landSends === true ? state : undefined);
  const store = new MemoryStore({ now: options.storeNow ?? (() => NOW) });
  const ctx: DemoContext = {
    clientIp: "203.0.113.9",
    now: NOW,
    store,
    env: {
      DEMO_BOARD_ID: "boardId" in options ? options.boardId : BOARD_ID,
      DEMO_SEEDED: (options.seeded ?? [asha, ben]).map((s) => s.evm),
      DEMO_CHAIR_MNEMONIC: chairPhrase,
      BLOB_ORIGIN: ORIGIN,
    },
    chain: demo.chain,
    blobs,
    relayer: RELAYER,
    relayChain: relay.chain,
    limits: ROOMY,
    clock: () => 0,
  };
  const untouched = () => blobs.pulled === 0 && relay.sends.length === 0 && relay.preflights.length === 0 && blobs.blobs.size === 1;
  return { ctx, state, epochKey, blobs, statuses, kems, kemFailures, store, demo, relay, untouched };
}

function post(path: string, body: unknown): Request {
  return new Request(`http://localhost/api/demo/${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
}

async function answer(response: Response): Promise<{ status: number; body: Record<string, unknown> }> {
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

interface Challenge {
  registry: string;
  boardId: string;
  botNonce: Hex;
  expiry: string;
  message: Hex;
}

async function challengeFor(ctx: DemoContext, guest: Identity): Promise<Challenge> {
  const response = await handleDemoChallenge(post("challenge", { guest: guest.qor1 }), ctx);
  expect(response.status).toBe(200);
  return (await response.json()) as Challenge;
}

function joinBody(guest: Identity, c: Challenge, signer: Identity = guest, message: Uint8Array = hexToBytes(c.message)) {
  return { guest: guest.evm, botNonce: c.botNonce, expiry: c.expiry, signature: bytesToHex(signAction(signer.mldsa.secretKey, message)) };
}

const join = (ctx: DemoContext, body: unknown) => handleDemoJoin(post("join", body), ctx);

function addMemberArgs(send: EvmSend) {
  const decoded = decodeFunctionData({ abi: boardRegistryAbi, data: send.data });
  expect(decoded.functionName).toBe("addMember");
  const [boardId, member, mode, envelopeHash, envelopeSize, epochAfter, deadline, signature] = decoded.args as unknown as readonly [bigint, Hex, number, Hex, number, bigint, bigint, Hex];
  return { boardId, member, mode, envelopeHash, envelopeSize, epochAfter, deadline, signature };
}

describe("handleDemoChallenge", () => {
  it("issues the exact 224 bytes to sign, bound to the registry, the demo board, the guest, a fresh nonce and a 300 s expiry", async () => {
    const { ctx, store } = await setup();
    const c = await challengeFor(ctx, g1);
    expect(c.registry).toBe(REGISTRY_ADDRESS);
    expect(c.boardId).toBe(BOARD_ID.toString());
    expect(BigInt(c.expiry)).toBe(BigInt(NOW / 1000 + 300));
    expect(hexToBytes(c.message)).toHaveLength(224);
    expect(await store.get(challengeKey(g1.account))).not.toBeNull();
    expect(await challengeFor(ctx, g1)).toEqual(c);
    expect((await challengeFor(ctx, g2)).botNonce).not.toBe(c.botNonce);
  });
});

describe("handleDemoJoin", () => {
  it("admits a guest whose fresh challenge is signed by its proven key, sealing the current epoch key to that guest alone", async () => {
    const { ctx, relay, blobs, epochKey, state, store } = await setup();
    const result = await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))));
    expect(result).toEqual({ status: 202, body: { txHash: `0x${"1".padStart(64, "0")}` } });
    expect(relay.sends).toHaveLength(1);
    expect(relay.sends[0]?.to).toBe(REGISTRY_ADDRESS);
    expect(await store.get(admittedKey(g1.account))).toBe(String(NOW));

    const args = addMemberArgs(relay.sends[0] as EvmSend);
    const sealed = await blobs.read(new URL(`${ORIGIN}/envelope/${args.envelopeHash.slice(2)}`), args.envelopeSize);
    const open = (who: Identity) =>
      openEpochKey({ registry: REGISTRY_ADDRESS, boardRef: state.boardRef, epoch: state.epoch, envelope: sealed as Uint8Array, expectedHash: args.envelopeHash, expectedSize: args.envelopeSize, sealKeys: who.seal });
    expect(open(g1)).toEqual(epochKey);
    expect(codeOf(() => open(chair))).toBe("NOT_A_RECIPIENT");
  });

  it("keeps a guest's live challenge through a join with a bad signature or another nonce, so nobody else can cancel it", async () => {
    const { ctx, relay, store } = await setup();
    const c = await challengeFor(ctx, g1);
    expect(await answer(await join(ctx, joinBody(g1, c, g2)))).toEqual({ status: 403, body: { error: "bad_signature" } });
    expect(await answer(await join(ctx, { ...joinBody(g1, c), botNonce: `0x${"ab".repeat(32)}` }))).toEqual({ status: 403, body: { error: "challenge_mismatch" } });
    expect(await store.get(challengeKey(g1.account))).not.toBeNull();
    expect(relay.sends).toHaveLength(0);

    expect((await join(ctx, joinBody(g1, c))).status).toBe(202);
    expect(await store.get(challengeKey(g1.account))).toBeNull();
    expect(relay.sends).toHaveLength(1);
  });

  it("lets one valid challenge admit at most once, even for two racing joins, and refuses its replay", async () => {
    const { ctx, relay } = await setup();
    const body = joinBody(g2, await challengeFor(ctx, g2));
    const results = await Promise.all([join(ctx, body), join(ctx, body)].map(async (r) => answer(await r)));
    expect(results.map((r) => r.status).sort()).toEqual([202, 409]);
    expect(results.find((r) => r.status === 409)?.body).toEqual({ error: "no_challenge" });
    expect(await answer(await join(ctx, body))).toEqual({ status: 409, body: { error: "no_challenge" } });
    expect(relay.sends).toHaveLength(1);
  });

  it("refuses an expired challenge before reading the guest's key", async () => {
    const { ctx, demo, untouched } = await setup({ storeNow: () => NOW });
    const c = await challengeFor(ctx, g1);
    const late = { ...ctx, now: NOW + 301_000 };
    expect(await answer(await join(late, joinBody(g1, c)))).toEqual({ status: 403, body: { error: "challenge_expired" } });
    expect(demo.counts.keyStatus).toBe(0);
    expect(untouched()).toBe(true);
  });

  it("refuses a signature over different bytes, by another key, or with a botNonce the bot did not issue", async () => {
    const { ctx, untouched } = await setup();
    let c = await challengeFor(ctx, g1);
    const otherBoard = hexToBytes(c.message);
    otherBoard[127] = (otherBoard[127] ?? 0) ^ 1;
    expect(await answer(await join(ctx, joinBody(g1, c, g1, otherBoard)))).toEqual({ status: 403, body: { error: "bad_signature" } });
    c = await challengeFor(ctx, g1);
    expect(await answer(await join(ctx, joinBody(g1, c, g3)))).toEqual({ status: 403, body: { error: "bad_signature" } });
    c = await challengeFor(ctx, g1);
    expect(await answer(await join(ctx, { ...joinBody(g1, c), botNonce: `0x${"ab".repeat(32)}` }))).toEqual({ status: 403, body: { error: "challenge_mismatch" } });
    expect(untouched()).toBe(true);
  });

  it("refuses a guest whose key is not registered, not ML-DSA-87, not possession-proven or not 2,592 bytes", async () => {
    const { ctx, statuses, untouched } = await setup();
    const variants: KeyStatus[] = [
      { ...proven(g1), registered: false },
      { ...proven(g1), algorithmId: 2 },
      { ...proven(g1), possessionProven: false },
      { ...proven(g1), pubkey: g1.mldsa.publicKey.slice(0, 2591) },
    ];
    for (const status of variants) {
      statuses.set(g1.evm.toLowerCase(), status);
      expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 403, body: { error: "no_proven_key" } });
    }
    expect(untouched()).toBe(true);
  });

  it("refuses a second join by a guest already admitted, before any envelope is read", async () => {
    const { ctx, relay, blobs } = await setup();
    expect((await join(ctx, joinBody(g1, await challengeFor(ctx, g1)))).status).toBe(202);
    const pulled = blobs.pulled;
    expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 409, body: { error: "already_admitted" } });
    expect(blobs.pulled).toBe(pulled);
    expect(relay.sends).toHaveLength(1);
  });

  it("admits a new judge at a full board by removing the oldest guest first, through the sweep's own removal", async () => {
    const guests = fillers(DEMO_GUEST_CAP - 3);
    const { ctx, state, store, relay, blobs } = await setup({ members: [chair, asha, ben, ...guests], landSends: true });
    // Admitted 1 to 37 minutes ago: none is past its six hours, so only the full board can remove one.
    await Promise.all(guests.map((g, i) => store.setIfAbsent(admittedKey(hexToBytes(g.evm)), String(NOW - (i + 1) * 60_000), 86_400)));
    const oldest = guests.at(-1) as Member;

    expect((await join(ctx, joinBody(g1, await challengeFor(ctx, g1)))).status).toBe(202);
    expect(relay.sends.map((tx) => decodeFunctionData({ abi: boardRegistryAbi, data: tx.data }).functionName)).toEqual(["removeMember", "addMember"]);
    const removal = decodeFunctionData({ abi: boardRegistryAbi, data: (relay.sends[0] as EvmSend).data }).args as unknown as readonly [bigint, Hex, Hex, number, bigint];
    expect([removal[1], removal[4]]).toEqual([oldest.evm, 4n]);
    expect(state.members).toHaveLength(DEMO_GUEST_CAP);
    expect(state.members).toContain(g1.evm);
    expect(state.members).not.toContain(oldest.evm);
    const sealed = (await blobs.read(new URL(`${ORIGIN}/envelope/${removal[2].slice(2)}`), removal[3])) as Uint8Array;
    const open = (keys: Member["seal"]) => openEpochKey({ registry: REGISTRY_ADDRESS, boardRef: state.boardRef, epoch: 4n, envelope: sealed, expectedHash: removal[2], expectedSize: removal[3], sealKeys: keys });
    expect(open((guests[0] as Member).seal)).toEqual(open(chair.seal));
    expect(codeOf(() => open(oldest.seal))).toBe("NOT_A_RECIPIENT");
  });

  it("refuses at a full board it cannot make room on, and takes the admission mark back, so nothing is signed", async () => {
    const guests = fillers(DEMO_GUEST_CAP - 3);
    const { ctx, store, relay, kems } = await setup({ members: [chair, asha, ben, ...guests] });
    await store.setIfAbsent(admittedKey(hexToBytes((guests[0] as Member).evm)), String(NOW - 60_000), 86_400);
    kems.delete(chair.evm.toLowerCase());
    expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 503, body: { error: "protected_key_unusable" } });
    expect(await store.get(admittedKey(g1.account))).toBeNull();
    expect(relay.sends).toHaveLength(0);
    expect(relay.preflights).toHaveLength(0);
  });

  it("refuses past each rate limit: joins per IP, joins per day and challenges per IP", async () => {
    const perIp = await setup();
    perIp.ctx.limits = { ...ROOMY, join: { perIp: 3, windowSeconds: 3600, perDay: 100 } };
    for (let n = 0; n < 3; n++) expect((await join(perIp.ctx, { guest: g1.evm })).status).toBe(400);
    const limited = await join(perIp.ctx, joinBody(g1, await challengeFor(perIp.ctx, g1)));
    expect(await answer(limited)).toEqual({ status: 429, body: { error: "rate_limited" } });
    expect(limited.headers.get("retry-after")).toBe("3600");
    expect(perIp.untouched()).toBe(true);

    const perDay = await setup();
    perDay.ctx.limits = { ...ROOMY, join: { perIp: 100, windowSeconds: 3600, perDay: 1 } };
    expect((await join(perDay.ctx, joinBody(g1, await challengeFor(perDay.ctx, g1)))).status).toBe(202);
    expect(await answer(await join(perDay.ctx, joinBody(g2, await challengeFor(perDay.ctx, g2))))).toEqual({ status: 503, body: { error: "daily_limit" } });
    expect(perDay.relay.sends).toHaveLength(1);

    const challenges = await setup();
    challenges.ctx.limits = { ...ROOMY, challenge: { perIp: 2, total: 100, windowSeconds: 3600 } };
    await challengeFor(challenges.ctx, g1);
    await challengeFor(challenges.ctx, g2);
    expect((await handleDemoChallenge(post("challenge", { guest: g3.evm }), challenges.ctx)).status).toBe(429);
  });

  it("stops at a swapped envelope that opens fine but is not the one recorded on chain, before its key is used", async () => {
    const { ctx, state, blobs, relay, store } = await setup();
    const path = `envelope/${state.grants[0]?.envelopeHash.slice(2)}`;
    // The attack C12 exists for: a valid envelope of the same size, sealed to the same members under a key the attacker knows.
    const recipients = [chair, asha, ben].map((m) => ({ address: m.evm, kemPublicKey: m.seal.mlkemPublicKey }));
    const swapped = sealEpochKey({ registry: REGISTRY_ADDRESS, boardRef: state.boardRef, epoch: state.epoch, epochKey: newEpochKey(), recipients });
    expect(swapped.length).toBe(state.grants[0]?.envelopeSize);
    blobs.blobs.set(path, swapped);
    expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 502, body: { error: "envelope_mismatch" } });
    expect(blobs.blobs.size).toBe(1);
    expect(relay.sends).toHaveLength(0);
    expect(relay.preflights).toHaveLength(0);
    expect(await store.get(admittedKey(g1.account))).toBeNull();
  });

  it("builds and signs addMember from its own board read, never from request fields beyond the guest", async () => {
    const { ctx, relay, state, blobs } = await setup();
    const c = await challengeFor(ctx, g1);
    const hostile = { ...joinBody(g1, c), boardId: "77", member: g4.evm, mode: "1", epochAfter: "99", envelopeHash: `0x${"cd".repeat(32)}`, envelopeSize: "5", nonce: "0" };
    expect((await join(ctx, hostile)).status).toBe(202);
    const args = addMemberArgs(relay.sends[0] as EvmSend);
    const stored = await blobs.read(new URL(`${ORIGIN}/envelope/${args.envelopeHash.slice(2)}`), args.envelopeSize);
    expect(args).toMatchObject({ boardId: BOARD_ID, member: g1.evm, mode: Mode.SEAL_CURRENT, epochAfter: state.epoch, deadline: BigInt(NOW / 1000 + 600) });
    expect(bytesToHex(sha256(stored as Uint8Array))).toBe(args.envelopeHash);
    const paramsHash = paramsAdd({ member: g1.evm, mode: Mode.SEAL_CURRENT, envelopeHash: args.envelopeHash, envelopeSize: args.envelopeSize, epochAfter: state.epoch });
    const message = actionMessage({ registry: REGISTRY_ADDRESS, action: Action.ADD, boardId: BOARD_ID, paramsHash, nonce: state.nonce, deadline: args.deadline });
    expect(verifyAction(chair.mldsa.publicKey, message, hexToBytes(args.signature))).toBe(true);
  });

  it("checks the upload's answered hash as bytes, so the same hash in uppercase hex still matches the envelope sent", async () => {
    const { ctx, relay } = await setup();
    const real = (await vi.importActual<typeof import("../src/blob.ts")>("../src/blob.ts")).handleUpload;
    vi.mocked(handleUpload).mockImplementationOnce(async (request, uploadCtx) => {
      const answered = await real(request, uploadCtx);
      const body = (await answered.json()) as { sha256: string };
      return Response.json({ ...body, sha256: body.sha256.toUpperCase() }, { status: answered.status });
    });
    expect((await join(ctx, joinBody(g1, await challengeFor(ctx, g1)))).status).toBe(202);
    expect(relay.sends).toHaveLength(1);
  });

  it("refuses an all-lowercase 0x guest address on the challenge and on the join", async () => {
    const { ctx, untouched } = await setup();
    const lower = g1.evm.toLowerCase();
    expect(await answer(await handleDemoChallenge(post("challenge", { guest: lower }), ctx))).toEqual({ status: 400, body: { error: "bad_guest" } });
    const c = await challengeFor(ctx, g1);
    expect(await answer(await join(ctx, { ...joinBody(g1, c), guest: lower }))).toEqual({ status: 400, body: { error: "bad_guest" } });
    expect(untouched()).toBe(true);
  });

  it("answers not_ready on every demo endpoint until the board is seeded", async () => {
    const { ctx, untouched } = await setup({ boardId: undefined });
    expect(await answer(await handleDemoChallenge(post("challenge", { guest: g1.evm }), ctx))).toEqual({ status: 503, body: { error: "not_ready" } });
    expect(await answer(await join(ctx, { guest: g1.evm }))).toEqual({ status: 503, body: { error: "not_ready" } });
    expect(await sweepDemoGuests(ctx)).toEqual({ done: "not_ready" });
    expect(untouched()).toBe(true);
  });
});

describe("sweepDemoGuests", () => {
  it("removes only the oldest expired guest per call and never the chair or a seeded director", async () => {
    const { ctx, state, store, relay, blobs } = await setup({ members: [chair, asha, ben, g1, g2, g3, g4] });
    const at = (who: Identity, hoursAgo: number) => store.setIfAbsent(admittedKey(who.account), String(NOW - hoursAgo * HOUR), 86_400);
    await Promise.all([at(chair, 10), at(asha, 10), at(g2, 6.5), at(g1, 7), at(g3, 1)]);

    const first = await sweepDemoGuests(ctx);
    expect(first).toMatchObject({ done: "removed", member: g1.evm, epochAfter: "4", landed: true });
    expect(relay.sends).toHaveLength(1);
    const decoded = decodeFunctionData({ abi: boardRegistryAbi, data: (relay.sends[0] as EvmSend).data });
    expect(decoded.functionName).toBe("removeMember");
    const [boardId, member, envelopeHash, envelopeSize, epochAfter] = decoded.args as unknown as readonly [bigint, Hex, Hex, number, bigint];
    expect([boardId, member, epochAfter]).toEqual([BOARD_ID, g1.evm, 4n]);
    const sealed = (await blobs.read(new URL(`${ORIGIN}/envelope/${envelopeHash.slice(2)}`), envelopeSize)) as Uint8Array;
    const open = (who: Identity) => openEpochKey({ registry: REGISTRY_ADDRESS, boardRef: state.boardRef, epoch: 4n, envelope: sealed, expectedHash: envelopeHash, expectedSize: envelopeSize, sealKeys: who.seal });
    const fresh = open(chair);
    for (const who of [asha, ben, g2, g3, g4]) expect(open(who)).toEqual(fresh);
    expect(codeOf(() => open(g1))).toBe("NOT_A_RECIPIENT");

    // The removal lands: the board moves to epoch 4 without g1.
    Object.assign(state, { epoch: 4n, nonce: state.nonce + 1n, members: state.members.filter((m) => m !== g1.evm), grants: [{ envelopeHash, envelopeSize, mode: Mode.ROTATE, member: ZERO }] });
    expect(await sweepDemoGuests(ctx)).toMatchObject({ done: "removed", member: g2.evm, epochAfter: "5" });
    Object.assign(state, { epoch: 5n, nonce: state.nonce + 1n, members: state.members.filter((m) => m !== g2.evm) });

    expect(await sweepDemoGuests(ctx)).toEqual({ done: "nothing_due", guests: 2, unknown: 1 });
    expect(relay.sends).toHaveLength(2);
  });
});

describe("sweepDemoGuests: no member's key can block another member's removal", () => {
  const admitted = (store: MemoryStore, who: Identity, hoursAgo: number) => store.setIfAbsent(admittedKey(who.account), String(NOW - hoursAgo * HOUR), 86_400);

  it("removes the guest whose ML-KEM key is gone, whatever its age, instead of stalling on the expired one", async () => {
    const { ctx, state, store, relay, blobs, kems } = await setup({ members: [chair, asha, ben, g1, g2] });
    await Promise.all([admitted(store, g1, 7), admitted(store, g2, 1)]);
    kems.delete(g2.evm.toLowerCase());

    expect(await sweepDemoGuests(ctx)).toMatchObject({ done: "removed", member: g2.evm, reason: "key_missing", epochAfter: "4", landed: true });
    const [, member, envelopeHash, envelopeSize] = decodeFunctionData({ abi: boardRegistryAbi, data: (relay.sends[0] as EvmSend).data }).args as unknown as readonly [bigint, Hex, Hex, number];
    expect(member).toBe(g2.evm);
    const sealed = (await blobs.read(new URL(`${ORIGIN}/envelope/${envelopeHash.slice(2)}`), envelopeSize)) as Uint8Array;
    const open = (who: Identity) => openEpochKey({ registry: REGISTRY_ADDRESS, boardRef: state.boardRef, epoch: 4n, envelope: sealed, expectedHash: envelopeHash, expectedSize: envelopeSize, sealKeys: who.seal });
    for (const who of [asha, ben, g1]) expect(open(who)).toEqual(open(chair));
    expect(codeOf(() => open(g2))).toBe("NOT_A_RECIPIENT");
  });

  it("removes a guest whose key changed since the board was sealed to it, or is not a valid ML-KEM key, whatever its age", async () => {
    const cases = [
      { reason: "key_changed", spoil: (kems: Map<string, Uint8Array>) => kems.set(g2.evm.toLowerCase(), g3.seal.mlkemPublicKey) },
      { reason: "key_invalid", spoil: (kems: Map<string, Uint8Array>) => kems.set(g2.evm.toLowerCase(), new Uint8Array(1568)) },
      { reason: "key_invalid", spoil: (_: Map<string, Uint8Array>, failures: Map<string, KemKeyFailure>) => failures.set(g2.evm.toLowerCase(), "INVALID_KEY") },
    ] as const;
    for (const c of cases) {
      const { ctx, store, relay, kems, kemFailures } = await setup({ members: [chair, asha, ben, g1, g2] });
      await Promise.all([admitted(store, g1, 2), admitted(store, g2, 1)]);
      c.spoil(kems, kemFailures);
      expect(await sweepDemoGuests(ctx)).toMatchObject({ done: "removed", member: g2.evm, reason: c.reason });
      expect(relay.sends).toHaveLength(1);
    }
  });

  it("raises an alert and removes no one when the chair's or a seeded director's key is unusable", async () => {
    for (const who of [chair, asha]) {
      const { ctx, store, relay, kems } = await setup({ members: [chair, asha, ben, g1] });
      await admitted(store, g1, 7);
      kems.delete(who.evm.toLowerCase());
      expect(await sweepDemoGuests(ctx)).toEqual({ done: "refused", reason: "protected_key_unusable" });
      expect(relay.sends).toHaveLength(0);
      expect(logged.some((line) => line.includes("demo_sweep_alert") && line.includes(who.evm))).toBe(true);
    }
  });
});

describe("demo settings", () => {
  it("takes DEMO_BOARD_ID and DEMO_SEEDED only in their strict forms", () => {
    const base = { UPSTASH_REDIS_REST_URL: "https://db.upstash.io", UPSTASH_REDIS_REST_TOKEN: "t", BLOB_READ_WRITE_TOKEN: "t", BLOB_ORIGIN: ORIGIN };
    const env = loadEnv({ ...base, DEMO_BOARD_ID: "12", DEMO_SEEDED: `${asha.qor1}, ${ben.evm.toLowerCase()}` });
    expect(env.DEMO_BOARD_ID).toBe(12n);
    expect(env.DEMO_SEEDED).toEqual([asha.evm, ben.evm]);
    expect(loadEnv(base).DEMO_BOARD_ID).toBeUndefined();
    for (const bad of ["0", "012", "-1", "1.5", "x"]) expect(() => loadEnv({ ...base, DEMO_BOARD_ID: bad })).toThrow(/invalid DEMO_BOARD_ID/);
    for (const bad of [`${asha.evm},`, `${asha.evm},${asha.qor1}`, "qor1nope", `${asha.evm};${ben.evm}`]) {
      expect(() => loadEnv({ ...base, DEMO_SEEDED: bad })).toThrow(/invalid DEMO_SEEDED/);
    }
  });
});
