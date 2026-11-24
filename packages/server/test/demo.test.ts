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
  challengeMessage,
  decryptDocument,
  generateMnemonic,
  identityFromMnemonic,
  leaveMessage,
  newEpochKey,
  openEpochKey,
  paramsAdd,
  paramsPost,
  sealEpochKey,
  sha256,
  signAction,
  signLeave,
  toHex,
  verifyAction,
  type Identity,
  type KemKeyFailure,
  type KemRecipient,
} from "@ava/core";
import type { EvmWindow } from "@qorechain/evm";
import { generateSealKeys } from "@qorechain/qoreseal";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { bytesToHex, decodeFunctionData, encodeFunctionResult, hexToBytes, toFunctionSelector, type Hex } from "viem";
import { boardRegistryAbi } from "../src/abi/boardRegistry.ts";
import { MemoryBlobBackend, handleUpload } from "../src/blob.ts";
import { NotBroadcast } from "../src/chain/evm.ts";
import type { EvmSend, RelayChain, TxRequest } from "../src/chain/types.ts";
import { DEMO_FREE_SEATS, DEMO_GUEST_CAP, DEMO_RELAYS_PER_HOUR, REGISTRY_ADDRESS, REGISTRY_CODE_KECCAK, WINDOW } from "../src/config.ts";
import {
  admittedKey,
  challengeKey,
  ensureCurrentPack,
  freeDemoSeats,
  handleDemoChallenge,
  handleDemoJoin,
  handleDemoLeave,
  handleDemoLeaveChallenge,
  leaveKey,
  sweepDemoGuests,
  type DemoContext,
} from "../src/demo.ts";
import { DEMO_PACK_TEXT } from "../src/demoPack.ts";
import type { BoardSnapshot, DemoChain, Grant, KeyStatus } from "../src/demoBoard.ts";
import { loadEnv } from "../src/env.ts";
import { handleRelay, reserveDemoRelays } from "../src/relay.ts";
import { MemoryStore, type SharedStore } from "../src/store.ts";
import { APP_HEADERS, CROSS_SITE_HEADERS, retriedWrites, stalledBody } from "./fixtures.ts";

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
  vi.useRealTimers();
});

/** What the stub's qor_getKEMKey answers for a member: the fixture's own key and the account's EIP-55 form, the frozen pair fetchKemKey builds. */
const published = (address: Hex, key: Uint8Array): KemRecipient => Object.freeze({ address: toHex(hexToBytes(address)), kemPublicKey: key }) as KemRecipient;

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
  documentCount: number;
  latestDocumentEpoch: bigint | undefined;
}

/** A board whose current epoch's envelope is sealed to every member, stored where the bot looks for it, with that epoch's pack already posted. */
async function seededBoard(blobs: MemoryBlobBackend, members: Member[]): Promise<{ state: BoardState; epochKey: Uint8Array }> {
  const boardRef = bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
  const epoch = 3n;
  const epochKey = newEpochKey();
  const envelope = sealEpochKey({ registry: REGISTRY_ADDRESS, boardRef, epoch, epochKey, recipients: members.map((m) => published(m.evm, m.seal.mlkemPublicKey)) });
  const envelopeHash = bytesToHex(sha256(envelope));
  await blobs.put(`envelope/${envelopeHash.slice(2)}`, envelope);
  return {
    state: { boardRef, epoch, nonce: 11n, members: members.map((m) => m.evm), grants: [{ envelopeHash, envelopeSize: envelope.length, mode: Mode.ROTATE, member: ZERO }], documentCount: 1, latestDocumentEpoch: epoch },
    epochKey: Uint8Array.from(epochKey),
  };
}

/** Members the stub's EnvelopeGranted logs do not name were granted an hour before NOW, when the board was seeded. */
const SEEDED_AT = BigInt(NOW / 1000 - 3600);

function demoChain(state: BoardState, statuses: Map<string, KeyStatus>, kems: Map<string, Uint8Array>, kemFailures: Map<string, KemKeyFailure>, grantTimes: Map<string, bigint>, receipt: "success" | "reverted" = "success") {
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
      return published(account, key);
    },
    receipt: async () => receipt,
    grantTimes: async (_boardId, members) => members.map((m) => grantTimes.get(m.toLowerCase()) ?? SEEDED_AT),
  };
  return { chain, counts };
}

/**
 * The relayer's chain: a usable window, the registry's getBoard, and every pre-flight accepted. Every
 * send lands and moves the board nonce getBoard reports. Given the board's state, it also applies each
 * removeMember and addMember the bot sends, as the registry would.
 */
function relayChain(board?: BoardState) {
  const sends: EvmSend[] = [];
  const preflights: TxRequest[] = [];
  const landed = new Set<string>();
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
        const nonce = board?.nonce ?? 11n + BigInt(sends.length);
        const result = { chair: chair.evm, boardRef: `0x${"11".repeat(32)}` as Hex, epoch: 3n, nonce, memberCount: 3, documentCount: 0 };
        return { ok: true, data: encodeFunctionResult({ abi: boardRegistryAbi, functionName: "getBoard", result }) };
      }
      preflights.push(req);
      return { ok: true, data: "0x" };
    },
    estimateGas: async () => 300_000n,
    feeQuote: async () => ({ baseFeePerGas: 100n * GWEI, maxPriorityFeePerGas: GWEI }),
    send: async (tx, _deadline, beforeBroadcast) => {
      const hash: Hex = `0x${(sends.length + 1).toString(16).padStart(64, "0")}`;
      try {
        await beforeBroadcast?.({ kind: "evm", nonce: BigInt(sends.length), hash });
      } catch {
        throw new NotBroadcast("not recorded");
      }
      sends.push(tx);
      landed.add(hash);
      if (board !== undefined) land(board, tx);
      return hash;
    },
    // The relayer's account nonce moves with every one of its own sends and nothing else.
    nonce: async () => BigInt(sends.length),
    txStatus: async (_kind, hash) => (landed.has(hash) ? "landed" : "unknown"),
    registryCodeHash: async () => REGISTRY_CODE_KECCAK,
  };
  return { chain, sends, preflights };
}

/** What the registry does with the bot's own removeMember, addMember and postDocument once they land. */
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
  if (decoded.functionName === "postDocument") {
    const [, , , , epoch] = decoded.args as unknown as readonly [bigint, Hex, Hex, bigint, bigint];
    Object.assign(board, { nonce: board.nonce + 1n, documentCount: board.documentCount + 1, latestDocumentEpoch: epoch });
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
  const grantTimes = new Map<string, bigint>();
  const demo = demoChain(state, statuses, kems, kemFailures, grantTimes, options.receipt);
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
    wallClock: () => NOW,
  };
  const untouched = () => blobs.pulled === 0 && relay.sends.length === 0 && relay.preflights.length === 0 && blobs.blobs.size === 1;
  return { ctx, state, epochKey, blobs, statuses, kems, kemFailures, grantTimes, store, demo, relay, untouched };
}

/** A board of `size` members whose every send lands: the chair, the two seeded directors, and guests admitted 1, 2, 3 and more minutes ago, the last one oldest. */
async function boardOf(size: number) {
  const guests = fillers(size - 3);
  const board = await setup({ members: [chair, asha, ben, ...guests], landSends: true });
  await Promise.all(guests.map((g, i) => board.store.setIfAbsent(admittedKey(hexToBytes(g.evm)), String(NOW - (i + 1) * 60_000), 86_400)));
  return { ...board, guests };
}

/** A background runner that only collects the work, so a test decides when it runs. */
function collector() {
  const scheduled: (() => Promise<unknown>)[] = [];
  return { scheduled, background: (work: () => Promise<unknown>) => void scheduled.push(work) };
}

/** How many of this clock hour's demo relays are still free. It takes them, so a test calls it last. */
async function hourLeft(store: SharedStore, now = NOW): Promise<number> {
  let left = 0;
  while (left < DEMO_RELAYS_PER_HOUR && (await reserveDemoRelays(store, now, 1))) left += 1;
  return left;
}

const calls = (sends: readonly EvmSend[]) => sends.map((tx) => decodeFunctionData({ abi: boardRegistryAbi, data: tx.data }).functionName);

function post(path: string, body: unknown): Request {
  return new Request(`http://localhost/api/demo/${path}`, { method: "POST", headers: { "content-type": "application/json", ...APP_HEADERS }, body: JSON.stringify(body) });
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

/** The bytes the bot encrypts for every pack it posts. */
const PACK = new TextEncoder().encode(DEMO_PACK_TEXT);

function postArgs(send: EvmSend) {
  const decoded = decodeFunctionData({ abi: boardRegistryAbi, data: send.data });
  expect(decoded.functionName).toBe("postDocument");
  const [boardId, docRef, cipherHash, cipherSize, epoch, deadline, signature] = decoded.args as unknown as readonly [bigint, Hex, Hex, bigint, bigint, bigint, Hex];
  return { boardId, docRef, cipherHash, cipherSize, epoch, deadline, signature };
}

/** A posted pack opened as a member opens it: the epoch key from a grant sealed to that member, then the document the post names. */
async function readPack(blobs: MemoryBlobBackend, boardRef: Hex, grant: Grant, keys: Member["seal"], posted: ReturnType<typeof postArgs>): Promise<Uint8Array> {
  const envelope = (await blobs.read(new URL(`${ORIGIN}/envelope/${grant.envelopeHash.slice(2)}`), grant.envelopeSize)) as Uint8Array;
  const epochKey = openEpochKey({ registry: REGISTRY_ADDRESS, boardRef, epoch: posted.epoch, envelope, expectedHash: grant.envelopeHash, expectedSize: grant.envelopeSize, sealKeys: keys });
  const ciphertext = (await blobs.read(new URL(`${ORIGIN}/document/${posted.cipherHash.slice(2)}`), Number(posted.cipherSize))) as Uint8Array;
  return decryptDocument({ epochKey, registry: REGISTRY_ADDRESS, boardRef, epoch: posted.epoch, docRef: posted.docRef, ciphertext, expectedHash: posted.cipherHash, expectedSize: posted.cipherSize });
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

  it("counts a challenge against the hour's total only once its body is valid, while junk still counts against its own IP", async () => {
    const { ctx } = await setup();
    ctx.limits = { ...ROOMY, challenge: { perIp: 3, total: 2, windowSeconds: 3600 } };
    const from = (n: number) => ({ ...ctx, clientIp: `198.51.100.${n}` });
    for (let n = 1; n <= 5; n++) expect((await handleDemoChallenge(post("challenge", { guest: "qor1nope" }), from(n))).status).toBe(400);
    await challengeFor(from(6), g1);
    await challengeFor(from(7), g2);
    expect((await handleDemoChallenge(post("challenge", { guest: g3.evm }), from(8))).status).toBe(429);

    for (let n = 0; n < 3; n++) expect((await handleDemoChallenge(post("challenge", { guest: "qor1nope" }), from(9))).status).toBe(400);
    expect((await handleDemoChallenge(post("challenge", { guest: "qor1nope" }), from(9))).status).toBe(429);
  });
});

describe("handleDemoJoin", () => {
  it("admits a guest whose fresh challenge is signed by its proven key, sealing the current epoch key to that guest alone", async () => {
    const { ctx, relay, blobs, epochKey, state, store } = await setup();
    const result = await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))));
    expect(result).toEqual({ status: 202, body: { txHash: `0x${"1".padStart(64, "0")}` } });
    expect(relay.sends).toHaveLength(1);
    expect(relay.sends[0]?.to).toBe(REGISTRY_ADDRESS);
    expect(await store.get(admittedKey(g1.account))).toBe(`${NOW}:0x${"1".padStart(64, "0")}`);

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
    expect(await store.get(challengeKey(g1.account))).toMatch(/^consumed:[0-9a-f-]{36}$/);
    expect(relay.sends).toHaveLength(1);
  });

  it("admits a guest whose challenge was consumed though the store lost its reply and the retried write answered no, and serves that challenge to no second join", async () => {
    const { ctx, store, relay } = await setup();
    const retried = { ...ctx, store: retriedWrites(store, (write, key) => write !== "setIfAbsent" && key === challengeKey(g1.account)) };
    const body = joinBody(g1, await challengeFor(retried, g1));
    expect(await answer(await join(retried, body))).toMatchObject({ status: 202 });
    expect(relay.sends).toHaveLength(1);
    expect(await answer(await join(retried, body))).toEqual({ status: 409, body: { error: "no_challenge" } });
    // A consumed challenge gives way to a fresh one at once.
    expect((await challengeFor(retried, g1)).botNonce).not.toBe(body.botNonce);
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

  it("answers a join at a full board with 503 board_full: nothing sent, no one removed, nothing taken from the guest, the day or the hour, and a pressure pass scheduled", async () => {
    const { ctx, state, store, relay, blobs } = await boardOf(DEMO_GUEST_CAP);
    const { scheduled, background } = collector();
    ctx.background = background;
    vi.mocked(handleUpload).mockClear();
    const before = [...state.members];

    const full = await join(ctx, joinBody(g1, await challengeFor(ctx, g1)));
    expect(await answer(full)).toEqual({ status: 503, body: { error: "board_full" } });
    expect(full.headers.get("retry-after")).toBe("30");
    expect(scheduled).toHaveLength(1);
    expect(relay.sends).toHaveLength(0);
    expect(relay.preflights).toHaveLength(0);
    expect(handleUpload).not.toHaveBeenCalled();
    expect(blobs.pulled).toBe(0);
    expect(state.members).toEqual(before);
    expect(await store.get(admittedKey(g1.account))).toBeNull();
    expect(await store.get(`demo:failed:${bytesToHex(g1.account)}:2026-11-19`)).toBeNull();
    expect(await store.get("demo:join:count:2026-11-19")).toBeNull();

    // With no background runner nothing is scheduled: the scheduled sweep does the work.
    delete ctx.background;
    expect(await answer(await join(ctx, joinBody(g2, await challengeFor(ctx, g2))))).toEqual({ status: 503, body: { error: "board_full" } });
    expect(scheduled).toHaveLength(1);
    expect(relay.sends).toHaveLength(0);
    expect(await hourLeft(store)).toBe(DEMO_RELAYS_PER_HOUR);
  });

  it("answers board_full at once to a join that arrives just after another join filled the board, counting no hourly join and keeping its challenge", async () => {
    const { ctx, store, relay } = await boardOf(DEMO_GUEST_CAP - 1);
    const second = joinBody(g2, await challengeFor(ctx, g2));
    expect((await join(ctx, joinBody(g1, await challengeFor(ctx, g1)))).status).toBe(202);
    expect(await answer(await join(ctx, second))).toEqual({ status: 503, body: { error: "board_full" } });
    expect(await store.get("rate:demo-join:ip:203.0.113.9")).toBe("1");
    expect(await store.get(challengeKey(g2.account))).not.toMatch(/^consumed:/);
    expect(calls(relay.sends)).toEqual(["addMember"]);
  });

  it("answers board_full at once to a join that arrives after a late add filled the board, though a join refused just before stored the size it read one seat short", async () => {
    const { ctx, store, state, kems } = await boardOf(DEMO_GUEST_CAP - 1);
    kems.delete(g3.evm.toLowerCase());
    const second = joinBody(g2, await challengeFor(ctx, g2));
    expect(await answer(await join(ctx, joinBody(g3, await challengeFor(ctx, g3))))).toEqual({ status: 403, body: { error: "no_kem_key" } });
    // An add whose broadcast reply was lost lands now, after that join read the board.
    state.members.push(toHex(Uint8Array.from({ length: 20 }, () => 0xee)));
    expect(await answer(await join(ctx, second))).toEqual({ status: 503, body: { error: "board_full" } });
    expect(await store.get("rate:demo-join:ip:203.0.113.9")).toBe("1");
    expect(await store.get(challengeKey(g2.account))).not.toMatch(/^consumed:/);
  });

  it("answers board_full before it reads the body, counts the IP or takes the challenge, so the judge's retry of the very same join is seated once the pass has run", async () => {
    const { ctx, store, relay, demo } = await boardOf(DEMO_GUEST_CAP);
    const { scheduled, background } = collector();
    ctx.background = background;
    ctx.limits = { ...ROOMY, join: { perIp: 3, windowSeconds: 3600, perDay: 100 } };
    const body = joinBody(g1, await challengeFor(ctx, g1));
    const statusReads = demo.counts.keyStatus;
    // More tries than the IP's three joins an hour: none of them is counted.
    for (let n = 0; n < 5; n++) expect(await answer(await join(ctx, body))).toEqual({ status: 503, body: { error: "board_full" } });
    expect(await store.get(challengeKey(g1.account))).not.toBeNull();
    expect(await store.get("rate:demo-join:ip:203.0.113.9")).toBeNull();
    expect(await store.get(`demo:failed:${bytesToHex(g1.account)}:2026-11-19`)).toBeNull();
    expect(demo.counts.keyStatus).toBe(statusReads);
    // One board read and one pass for the five, not one each.
    expect(demo.counts.board).toBe(1);
    expect(scheduled).toHaveLength(1);

    await scheduled[0]?.();
    expect(await answer(await join(ctx, body))).toMatchObject({ status: 202 });
    expect(calls(relay.sends)).toEqual([...Array.from({ length: DEMO_FREE_SEATS }, () => "removeMember"), "postDocument", "addMember"]);
  });

  it("admits a join at 34 members with one relay and schedules a pressure pass, which brings the board back to 34; a join at 33 schedules no pass, only the pack check", async () => {
    expect(DEMO_GUEST_CAP - DEMO_FREE_SEATS).toBe(34);
    const at34 = await boardOf(DEMO_GUEST_CAP - DEMO_FREE_SEATS);
    const { scheduled, background } = collector();
    at34.ctx.background = background;
    expect((await join(at34.ctx, joinBody(g1, await challengeFor(at34.ctx, g1)))).status).toBe(202);
    expect(calls(at34.relay.sends)).toEqual(["addMember"]);
    expect(at34.state.members).toHaveLength(35);
    expect(scheduled).toHaveLength(1);

    const oldest = at34.guests.at(-1) as Member;
    expect(await scheduled[0]?.()).toMatchObject({ removed: [{ member: oldest.evm, reason: "pressure", landed: true }], stopped: { done: "room" } });
    expect(at34.state.members).toHaveLength(34);
    expect(at34.state.members).toContain(g1.evm);
    expect(at34.state.members).not.toContain(oldest.evm);

    const at33 = await boardOf(DEMO_GUEST_CAP - DEMO_FREE_SEATS - 1);
    const quiet = collector();
    at33.ctx.background = quiet.background;
    expect((await join(at33.ctx, joinBody(g1, await challengeFor(at33.ctx, g1)))).status).toBe(202);
    expect(at33.state.members).toHaveLength(34);
    expect(quiet.scheduled).toHaveLength(1);
    expect(await quiet.scheduled[0]?.()).toEqual({ done: "current" });
    expect(calls(at33.relay.sends)).toEqual(["addMember"]);
  });

  it("seats a judge who met a full board once the pass it scheduled has freed seats, by the sweep's own removal, sealing the new epoch away from the guest removed", async () => {
    // Admitted 1 to 37 minutes ago: none is past its six hours, so only the pressure pass can remove one.
    const { ctx, state, relay, blobs, guests } = await boardOf(DEMO_GUEST_CAP);
    const { scheduled, background } = collector();
    ctx.background = background;
    const oldest = guests.at(-1) as Member;

    expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 503, body: { error: "board_full" } });
    expect(relay.sends).toHaveLength(0);
    await scheduled[0]?.();
    expect(calls(relay.sends)).toEqual([...Array.from({ length: DEMO_FREE_SEATS }, () => "removeMember"), "postDocument"]);
    const removal = decodeFunctionData({ abi: boardRegistryAbi, data: (relay.sends[0] as EvmSend).data }).args as unknown as readonly [bigint, Hex, Hex, number, bigint];
    expect([removal[1], removal[4]]).toEqual([oldest.evm, 4n]);
    const sealed = (await blobs.read(new URL(`${ORIGIN}/envelope/${removal[2].slice(2)}`), removal[3])) as Uint8Array;
    const open = (keys: Member["seal"]) => openEpochKey({ registry: REGISTRY_ADDRESS, boardRef: state.boardRef, epoch: 4n, envelope: sealed, expectedHash: removal[2], expectedSize: removal[3], sealKeys: keys });
    expect(open((guests[0] as Member).seal)).toEqual(open(chair.seal));
    expect(codeOf(() => open(oldest.seal))).toBe("NOT_A_RECIPIENT");

    // The judge's retry, on a fresh challenge, is one addMember.
    expect((await join(ctx, joinBody(g1, await challengeFor(ctx, g1)))).status).toBe(202);
    expect(calls(relay.sends).slice(DEMO_FREE_SEATS + 1)).toEqual(["addMember"]);
    expect(state.members).toHaveLength(DEMO_GUEST_CAP - DEMO_FREE_SEATS + 1);
    expect(state.members).toContain(g1.evm);
    expect(state.members).not.toContain(oldest.evm);
  });

  it("seats a judge at a full board after 19 junk relays and 19 junk uploads from the judge's own IP: the bot's own are never counted against it", async () => {
    const { ctx, state, store, relay, blobs } = await boardOf(DEMO_GUEST_CAP);
    const { scheduled, background } = collector();
    ctx.background = background;
    const headers = { "content-type": "application/json", "x-ava": "1" };
    const junkRelay = () => handleRelay(new Request("http://localhost/api/relay", { method: "POST", headers, body: "{}" }), { clientIp: ctx.clientIp, now: NOW, store, relayer: RELAYER, chain: relay.chain });
    const junkUpload = () =>
      handleUpload(new Request("http://localhost/api/upload?kind=junk", { method: "POST", headers: { "content-type": "application/octet-stream", "x-ava": "1" }, body: "x" }), { clientIp: ctx.clientIp, now: NOW, store, blobs, blobOrigin: ORIGIN });
    for (let n = 0; n < 19; n++) {
      expect((await junkRelay()).status).toBe(400);
      expect((await junkUpload()).status).toBe(400);
    }

    expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 503, body: { error: "board_full" } });
    await scheduled[0]?.();
    expect((await join(ctx, joinBody(g1, await challengeFor(ctx, g1)))).status).toBe(202);
    expect(calls(relay.sends)).toEqual([...Array.from({ length: DEMO_FREE_SEATS }, () => "removeMember"), "postDocument", "addMember"]);
    expect(state.members).toContain(g1.evm);
    // The IP still has exactly one of its 20 left on each: the bot's eight relays and seven envelope uploads took none.
    expect((await junkRelay()).status).toBe(400);
    expect((await junkRelay()).status).toBe(429);
    expect((await junkUpload()).status).toBe(400);
    expect((await junkUpload()).status).toBe(429);
  });

  it("removes no one at a board with one seat left for a guest whose ML-KEM key is missing or unusable, and uploads nothing", async () => {
    // A full board answers board_full before any check of the guest, so one seat is left here.
    const guests = fillers(DEMO_GUEST_CAP - 4);
    const { ctx, state, store, relay, blobs, kems, demo } = await setup({ members: [chair, asha, ben, ...guests], landSends: true });
    await Promise.all(guests.map((g, i) => store.setIfAbsent(admittedKey(hexToBytes(g.evm)), String(NOW - (i + 1) * 60_000), 86_400)));
    kems.delete(g1.evm.toLowerCase());
    kems.set(g2.evm.toLowerCase(), new Uint8Array(1568));
    vi.mocked(handleUpload).mockClear();

    expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 403, body: { error: "no_kem_key" } });
    expect(await answer(await join(ctx, joinBody(g2, await challengeFor(ctx, g2))))).toEqual({ status: 403, body: { error: "bad_kem_key" } });
    expect(relay.sends).toHaveLength(0);
    expect(relay.preflights).toHaveLength(0);
    expect(handleUpload).not.toHaveBeenCalled();
    expect(blobs.pulled).toBe(0);
    // Each join's fullness check reads the board itself: a size under the cap is never kept.
    expect(demo.counts.board).toBe(2);
    expect(state.members).toHaveLength(DEMO_GUEST_CAP - 1);
    expect(state.members).toContain((guests.at(-1) as Member).evm);
    expect(await store.get(admittedKey(g1.account))).toBeNull();
    expect(await store.get(admittedKey(g2.account))).toBeNull();
  });

  it("refuses with 403 key_shared a guest whose ML-KEM key a current member published, before the day, the lock or any removal, and counts it against the guest", async () => {
    // One seat left, because a full board answers board_full before any check of the guest.
    const guests = fillers(DEMO_GUEST_CAP - 4);
    const { ctx, state, store, relay, kems } = await setup({ members: [chair, asha, ben, ...guests], landSends: true });
    await Promise.all(guests.map((g, i) => store.setIfAbsent(admittedKey(hexToBytes(g.evm)), String(NOW - (i + 1) * 60_000), 86_400)));
    kems.set(g1.evm.toLowerCase(), asha.seal.mlkemPublicKey);
    kems.set(g2.evm.toLowerCase(), (guests[0] as Member).seal.mlkemPublicKey);
    const locked = vi.spyOn(store, "withLock");
    vi.mocked(handleUpload).mockClear();

    for (const guest of [g1, g2]) {
      expect(await answer(await join(ctx, joinBody(guest, await challengeFor(ctx, guest))))).toEqual({ status: 403, body: { error: "key_shared" } });
      expect(await store.get(`demo:failed:${bytesToHex(guest.account)}:2026-11-19`)).toBe("1");
      expect(await store.get(admittedKey(guest.account))).toBeNull();
    }
    expect(locked).not.toHaveBeenCalled();
    expect(handleUpload).not.toHaveBeenCalled();
    expect(relay.sends).toHaveLength(0);
    expect(state.members).toHaveLength(DEMO_GUEST_CAP - 1);
    expect(await store.get("demo:join:count:2026-11-19")).toBeNull();
  });

  it("admits a guest while another member's key lookup is unreadable, and still refuses a guest whose key a readable member published", async () => {
    const { ctx, relay, kems, kemFailures } = await setup({ members: [chair, asha, ben, g2] });
    kemFailures.set(g2.evm.toLowerCase(), "MALFORMED");
    expect((await join(ctx, joinBody(g1, await challengeFor(ctx, g1)))).status).toBe(202);
    expect(relay.sends).toHaveLength(1);

    kems.set(g3.evm.toLowerCase(), asha.seal.mlkemPublicKey);
    expect(await answer(await join(ctx, joinBody(g3, await challengeFor(ctx, g3))))).toEqual({ status: 403, body: { error: "key_shared" } });
    expect(relay.sends).toHaveLength(1);
  });

  it("reserves a join's one relay before anything is sealed or sent: an hour with none left answers 503 demo_busy, sends nothing and counts nothing against the guest", async () => {
    const { ctx, state, store, relay } = await setup({ landSends: true });
    for (let n = 0; n < DEMO_RELAYS_PER_HOUR; n++) expect(await reserveDemoRelays(store, NOW, 1)).toBe(true);
    const before = [...state.members];
    vi.mocked(handleUpload).mockClear();

    const busy = await join(ctx, joinBody(g1, await challengeFor(ctx, g1)));
    expect(await answer(busy)).toEqual({ status: 503, body: { error: "demo_busy" } });
    expect(busy.headers.get("retry-after")).toBe("3600");
    expect(relay.sends).toHaveLength(0);
    expect(handleUpload).not.toHaveBeenCalled();
    expect(state.members).toEqual(before);
    expect(await store.get(`demo:failed:${bytesToHex(g1.account)}:2026-11-19`)).toBeNull();
    expect(await store.get(admittedKey(g1.account))).toBeNull();
    expect(await store.get("demo:join:count:2026-11-19")).toBeNull();

    // The next clock hour has room, and the same judge is seated with one addMember.
    const next = { ...ctx, now: NOW + HOUR };
    expect((await join(next, joinBody(g1, await challengeFor(next, g1)))).status).toBe(202);
    expect(calls(relay.sends)).toEqual(["addMember"]);

    // A full board answers board_full before the hour is asked for anything.
    const full = await boardOf(DEMO_GUEST_CAP);
    for (let n = 0; n < DEMO_RELAYS_PER_HOUR; n++) expect(await reserveDemoRelays(full.store, NOW, 1)).toBe(true);
    expect(await answer(await join(full.ctx, joinBody(g1, await challengeFor(full.ctx, g1))))).toEqual({ status: 503, body: { error: "board_full" } });
    expect(full.relay.sends).toHaveLength(0);
  });

  it("holds the admission mark only for the lock's lifetime until the addMember is about to be relayed, so a failed join whose release is lost locks no one out", async () => {
    let storeClock = NOW;
    const { ctx, store, relay } = await setup({ storeNow: () => storeClock });
    const releaseLost: SharedStore = {
      get: (key) => store.get(key),
      setIfAbsent: (key, value, ttl) => store.setIfAbsent(key, value, ttl),
      delete: async (key) => {
        if (key.startsWith("demo:admitted:")) throw new Error("store unreachable");
        return store.delete(key);
      },
      withLock: (key, ttl, fn, options) => store.withLock(key, ttl, fn, options),
      incrWindow: (key, windowSeconds, amount) => store.incrWindow(key, windowSeconds, amount),
      compareAndSet: (key, expected, next, ttl) => store.compareAndSet(key, expected, next, ttl),
    };
    const lossy = { ...ctx, store: releaseLost };
    // No demo relay is left this hour, so the join stops after the mark with nothing sent, and taking the mark back fails.
    for (let n = 0; n < DEMO_RELAYS_PER_HOUR; n++) expect(await reserveDemoRelays(store, NOW, 1)).toBe(true);
    expect(await answer(await join(lossy, joinBody(g1, await challengeFor(lossy, g1))))).toEqual({ status: 503, body: { error: "demo_busy" } });
    expect(relay.sends).toHaveLength(0);
    storeClock += 151_000;
    expect(await store.get(admittedKey(g1.account))).toBeNull();

    const next = { ...ctx, now: NOW + HOUR };
    const admitted = await join(next, joinBody(g1, await challengeFor(next, g1)));
    expect(admitted.status).toBe(202);
    // Once the addMember is signed the mark is for good, and names that transaction.
    storeClock += 86_400_000;
    expect(await store.get(admittedKey(g1.account))).toBe(`${NOW + HOUR}:${((await admitted.json()) as { txHash: string }).txHash}`);
  });

  it("keeps the admission mark, dated now, when the bot's addMember reverts but the board shows the guest a member", async () => {
    // A copy of the bot's signed addMember landed first, so the guest is a member and the bot's own transaction reverts.
    const { ctx, store, relay, state } = await setup({ landSends: true, receipt: "reverted" });
    expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 502, body: { error: "reverted" } });
    expect(state.members).toContain(g1.evm);
    expect(await store.get(admittedKey(g1.account))).toBe(String(NOW));
    expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 409, body: { error: "already_admitted" } });
    expect(relay.sends).toHaveLength(1);

    const gone = await setup({ receipt: "reverted" });
    expect((await join(gone.ctx, joinBody(g1, await challengeFor(gone.ctx, g1)))).status).toBe(502);
    expect(gone.state.members).not.toContain(g1.evm);
    expect(await gone.store.get(admittedKey(g1.account))).toBeNull();
  });

  /**
   * A join answered 202 whose receipt the bot never saw, then what the chain says of that addMember:
   * "dropped" (the chain knows no such transaction), "reverted" (it landed and reverted), or "pending".
   */
  async function unseenAdmission(fate: "dropped" | "reverted" | "pending") {
    const board = await setup();
    const { ctx, relay, demo } = board;
    // No receipt is seen during the first join; every later addMember's receipt is.
    let lost: Hex | undefined;
    ctx.chain = { ...demo.chain, receipt: async (hash) => (lost === undefined || hash === lost ? undefined : "success") };
    const first = await join(ctx, joinBody(g1, await challengeFor(ctx, g1)));
    expect(first.status).toBe(202);
    const { txHash } = (await first.json()) as { txHash: Hex };
    lost = txHash;
    const standing = relay.chain.txStatus?.bind(relay.chain);
    const says = (status: "unknown" | "reverted" | "pending") => async (kind: "evm" | "native", hash: string) => (hash === txHash ? status : (standing?.(kind, hash) ?? "unknown"));
    // A dropped transaction never used the relayer's nonce either, so the next send takes that nonce again.
    if (fate === "dropped") ctx.relayChain = { ...relay.chain, nonce: async () => BigInt(relay.sends.length - 1), txStatus: says("unknown") };
    if (fate === "reverted") ctx.relayChain = { ...relay.chain, txStatus: says("reverted") };
    if (fate === "pending") ctx.relayChain = { ...relay.chain, txStatus: says("pending") };
    return { ...board, txHash };
  }

  it("frees a guest whose addMember, answered 202 without a receipt, the chain does not know or holds reverted, and still holds one whose addMember is pending", async () => {
    for (const [fate, again] of [
      ["dropped", 202],
      ["reverted", 202],
      ["pending", 503],
    ] as const) {
      const { ctx, store, relay, txHash } = await unseenAdmission(fate);
      expect(await store.get(admittedKey(g1.account))).toBe(`${NOW}:${txHash}`);
      const retry = await join(ctx, joinBody(g1, await challengeFor(ctx, g1)));
      expect({ fate, status: retry.status }).toEqual({ fate, status: again });
      if (again === 503) expect(await retry.json()).toEqual({ error: "admission_unsettled" });
      expect(relay.sends).toHaveLength(again === 202 ? 2 : 1);
    }
  });

  it("answers 503 admission_unsettled, counting nothing against the guest and keeping its mark, while its addMember is pending or its standing cannot be read, before or under the lock", async () => {
    const failedKey = `demo:failed:${bytesToHex(g1.account)}:2026-11-19`;
    const pending = await unseenAdmission("pending");
    const asked = await join(pending.ctx, joinBody(g1, await challengeFor(pending.ctx, g1)));
    expect(await answer(asked)).toEqual({ status: 503, body: { error: "admission_unsettled" } });
    expect(asked.headers.get("retry-after")).toBe("30");
    expect(await pending.store.get(failedKey)).toBeNull();
    expect(await pending.store.get(admittedKey(g1.account))).toBe(`${NOW}:${pending.txHash}`);

    // The board read that says whether the guest sits on the board fails, so the mark's standing is unsure.
    const unread = await unseenAdmission("reverted");
    unread.ctx.chain = {
      ...unread.ctx.chain,
      board: async () => {
        throw new Error("the board read timed out");
      },
    };
    expect(await answer(await join(unread.ctx, joinBody(g1, await challengeFor(unread.ctx, g1))))).toEqual({ status: 503, body: { error: "admission_unsettled" } });
    expect(await unread.store.get(failedKey)).toBeNull();
    expect(await unread.store.get(admittedKey(g1.account))).toBe(`${NOW}:${unread.txHash}`);

    // Stale at the first look, unsure at the second, under the lock.
    const turned = await unseenAdmission("reverted");
    const standing = turned.ctx.relayChain.txStatus?.bind(turned.ctx.relayChain);
    let looks = 0;
    turned.ctx.relayChain = { ...turned.ctx.relayChain, txStatus: async (kind, hash) => (hash === turned.txHash ? (++looks === 1 ? "reverted" : "pending") : (standing?.(kind, hash) ?? "unknown")) };
    expect(await answer(await join(turned.ctx, joinBody(g1, await challengeFor(turned.ctx, g1))))).toEqual({ status: 503, body: { error: "admission_unsettled" } });
    expect(looks).toBe(2);
    expect(await turned.store.get(failedKey)).toBeNull();
    expect(await turned.store.get(admittedKey(g1.account))).toBe(`${NOW}:${turned.txHash}`);
    expect(turned.relay.sends).toHaveLength(1);
  });

  it("answers a second join of a guest whose first join is still under way 503 admission_unsettled, counting nothing, and seats the guest once", async () => {
    const { ctx, store, relay } = await setup();
    let open: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => (open = resolve));
    let reached: () => void = () => undefined;
    const signing = new Promise<void>((resolve) => (reached = resolve));
    ctx.relayChain = {
      ...relay.chain,
      send: async (tx, deadline, beforeBroadcast) => {
        reached();
        await gate;
        return relay.chain.send(tx, deadline, beforeBroadcast);
      },
    };
    const first = join(ctx, joinBody(g1, await challengeFor(ctx, g1)));
    // The first join holds the lock and the guest's mark, and has not signed its addMember yet.
    await signing;
    const second = await join(ctx, joinBody(g1, await challengeFor(ctx, g1)));
    expect(await answer(second)).toEqual({ status: 503, body: { error: "admission_unsettled" } });
    expect(second.headers.get("retry-after")).toBe("30");
    expect(await store.get(`demo:failed:${bytesToHex(g1.account)}:2026-11-19`)).toBeNull();
    open();
    expect((await first).status).toBe(202);
    expect(relay.sends).toHaveLength(1);
    expect(await store.get(admittedKey(g1.account))).toMatch(new RegExp(`^${NOW}:0x[0-9a-f]{64}$`));
  });

  it("seats a guest whose stale mark gave way though the store lost its reply to the new mark and the retried write answered no", async () => {
    const { ctx, store, relay } = await unseenAdmission("dropped");
    const retried = { ...ctx, store: retriedWrites(store, (write, key) => write === "setIfAbsent" && key === admittedKey(g1.account)) };
    const again = await join(retried, joinBody(g1, await challengeFor(retried, g1)));
    expect(again.status).toBe(202);
    expect(relay.sends).toHaveLength(2);
    expect(await store.get(admittedKey(g1.account))).toBe(`${NOW}:${((await again.json()) as { txHash: string }).txHash}`);
  });

  it("keeps the mark of a guest whose addMember the receipt shows landed, even once that guest is no longer a member", async () => {
    const { ctx, store, relay, demo } = await setup();
    const first = await join(ctx, joinBody(g1, await challengeFor(ctx, g1)));
    expect(first.status).toBe(202);
    expect(demo.counts.board).toBeGreaterThan(0);
    expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 409, body: { error: "already_admitted" } });
    expect(await store.get(admittedKey(g1.account))).toMatch(new RegExp(`^${NOW}:0x[0-9a-f]{64}$`));
    expect(relay.sends).toHaveLength(1);
  });

  it("lets the scheduled sweep release the mark of a guest whose unseen addMember the chain does not know, and keep one still pending", async () => {
    for (const [fate, kept] of [
      ["dropped", false],
      ["reverted", false],
      ["pending", true],
    ] as const) {
      const { ctx, store, txHash } = await unseenAdmission(fate);
      expect(await sweepDemoGuests(ctx)).toEqual({ done: "nothing_due", guests: 0, unknown: 0 });
      expect({ fate, mark: await store.get(admittedKey(g1.account)) }).toEqual({ fate, mark: kept ? `${NOW}:${txHash}` : null });
    }
  });

  it("answers board_full at a full board no one can be removed from, takes the admission mark back, and the pass it schedules removes no one and signs nothing", async () => {
    const { ctx, state, store, relay, kems } = await boardOf(DEMO_GUEST_CAP);
    const { scheduled, background } = collector();
    ctx.background = background;
    kems.delete(chair.evm.toLowerCase());
    expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 503, body: { error: "board_full" } });
    expect(await store.get(admittedKey(g1.account))).toBeNull();
    expect(await scheduled[0]?.()).toEqual({ removed: [], stopped: { done: "refused", reason: "protected_key_unusable" } });
    expect(logged.some((line) => line.includes("demo_sweep_alert") && line.includes(chair.evm))).toBe(true);
    expect(state.members).toHaveLength(DEMO_GUEST_CAP);
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

  it("counts joins per IPv6 /48 too, so 81 /64s of one /48 hit the limit at 4 times the per-IP figure", async () => {
    const { ctx, untouched } = await setup();
    ctx.limits = { ...ROOMY, join: { perIp: 20, windowSeconds: 3600, perDay: 100 } };
    const from = (n: number) => ({ ...ctx, clientIp: `2001:db8:1:${n.toString(16)}::1` });
    for (let n = 0; n < 80; n++) expect((await join(from(n), { guest: g1.evm })).status).toBe(400);
    const limited = await join(from(80), { guest: g1.evm });
    expect(await answer(limited)).toEqual({ status: 429, body: { error: "rate_limited" } });
    expect(limited.headers.get("retry-after")).toBe("3600");
    expect(logged.some((line) => line.includes("demo_refused") && line.includes("per_net48"))).toBe(true);
    expect((await join({ ...ctx, clientIp: "2001:db8:2::1" }, { guest: g1.evm })).status).toBe(400);
    expect(untouched()).toBe(true);
  });

  it("takes nothing from the day for a guest with no ML-KEM key, however often it tries", async () => {
    const { ctx, kems, store, relay, blobs } = await setup();
    ctx.limits = { ...ROOMY, join: { perIp: 100, windowSeconds: 3600, perDay: 1 } };
    kems.delete(g1.evm.toLowerCase());
    for (let n = 0; n < 3; n++) {
      expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 403, body: { error: "no_kem_key" } });
    }
    expect(await store.get("demo:join:count:2026-11-19")).toBeNull();
    expect(await store.get(admittedKey(g1.account))).toBeNull();
    expect(blobs.blobs.size).toBe(1);
    expect(relay.sends).toHaveLength(0);
  });

  it("never counts a refusal the guest did not cause, so six 503 daily_limit answers still leave the guest free to join", async () => {
    const { ctx, store, relay } = await setup();
    ctx.limits = { ...ROOMY, join: { perIp: 100, windowSeconds: 3600, perDay: 0 } };
    for (let n = 0; n < 6; n++) {
      expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 503, body: { error: "daily_limit" } });
    }
    expect(await store.get(`demo:failed:${bytesToHex(g1.account)}:2026-11-19`)).toBeNull();
    ctx.limits = ROOMY;
    expect((await join(ctx, joinBody(g1, await challengeFor(ctx, g1)))).status).toBe(202);
    expect(relay.sends).toHaveLength(1);
  });

  it("answers the sixth failed join from one address in a UTC day with 429 too_many_failures, counting only refusals after the signature check", async () => {
    const { ctx, kems, store, demo } = await setup();
    kems.delete(g1.evm.toLowerCase());
    kems.delete(g2.evm.toLowerCase());
    const failedKey = `demo:failed:${bytesToHex(g1.account)}:2026-11-19`;
    for (let n = 0; n < 3; n++) expect((await join(ctx, joinBody(g1, await challengeFor(ctx, g1), g3))).status).toBe(403);
    expect(await store.get(failedKey)).toBeNull();

    for (let n = 0; n < 5; n++) {
      expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 403, body: { error: "no_kem_key" } });
    }
    expect(await store.get(failedKey)).toBe("5");
    const lookups = demo.counts.kem;
    const sixth = await join(ctx, joinBody(g1, await challengeFor(ctx, g1)));
    expect(await answer(sixth)).toEqual({ status: 429, body: { error: "too_many_failures" } });
    expect(sixth.headers.get("retry-after")).toBe(String(12 * 3600));
    expect(demo.counts.kem).toBe(lookups);

    expect(await answer(await join(ctx, joinBody(g2, await challengeFor(ctx, g2))))).toEqual({ status: 403, body: { error: "no_kem_key" } });
    // The store's clock stays at NOW, so the challenge the 429 left in place is cleared by hand.
    await store.delete(challengeKey(g1.account));
    const tomorrow = { ...ctx, now: NOW + 86_400_000 };
    expect(await answer(await join(tomorrow, joinBody(g1, await challengeFor(tomorrow, g1))))).toEqual({ status: 403, body: { error: "no_kem_key" } });
  });

  it("stops at a swapped envelope that opens fine but is not the one recorded on chain, before its key is used", async () => {
    const { ctx, state, blobs, relay, store } = await setup();
    const path = `envelope/${state.grants[0]?.envelopeHash.slice(2)}`;
    // The attack C12 exists for: a valid envelope of the same size, sealed to the same members under a key the attacker knows.
    const recipients = [chair, asha, ben].map((m) => published(m.evm, m.seal.mlkemPublicKey));
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
    const { ctx, state, store, relay, blobs } = await setup({ members: [chair, asha, ben, g1, g2, g3, g4], landSends: true });
    const at = (who: Identity, hoursAgo: number) => store.setIfAbsent(admittedKey(who.account), String(NOW - hoursAgo * HOUR), 86_400);
    await Promise.all([at(chair, 10), at(asha, 10), at(g2, 6.5), at(g1, 7), at(g3, 1)]);

    const first = await sweepDemoGuests(ctx);
    expect(first).toMatchObject({ done: "removed", member: g1.evm, epochAfter: "4", landed: true });
    expect(calls(relay.sends)).toEqual(["removeMember", "postDocument"]);
    const decoded = decodeFunctionData({ abi: boardRegistryAbi, data: (relay.sends[0] as EvmSend).data });
    expect(decoded.functionName).toBe("removeMember");
    const [boardId, member, envelopeHash, envelopeSize, epochAfter] = decoded.args as unknown as readonly [bigint, Hex, Hex, number, bigint];
    expect([boardId, member, epochAfter]).toEqual([BOARD_ID, g1.evm, 4n]);
    const sealed = (await blobs.read(new URL(`${ORIGIN}/envelope/${envelopeHash.slice(2)}`), envelopeSize)) as Uint8Array;
    const open = (who: Identity) => openEpochKey({ registry: REGISTRY_ADDRESS, boardRef: state.boardRef, epoch: 4n, envelope: sealed, expectedHash: envelopeHash, expectedSize: envelopeSize, sealKeys: who.seal });
    const fresh = open(chair);
    for (const who of [asha, ben, g2, g3, g4]) expect(open(who)).toEqual(fresh);
    expect(codeOf(() => open(g1))).toBe("NOT_A_RECIPIENT");

    // The removal landed: the board is at epoch 4 without g1.
    expect(state).toMatchObject({ epoch: 4n, grants: [{ envelopeHash, envelopeSize, mode: Mode.ROTATE, member: ZERO }] });
    expect(state.members).not.toContain(g1.evm);
    expect(await sweepDemoGuests(ctx)).toMatchObject({ done: "removed", member: g2.evm, epochAfter: "5" });

    expect(await sweepDemoGuests(ctx)).toEqual({ done: "nothing_due", guests: 2, unknown: 0 });
    expect(calls(relay.sends)).toEqual(["removeMember", "postDocument", "removeMember", "postDocument"]);
  });

  it("frees seats on a full board with no background runner: after its own expiry step it runs the pressure pass down to 34, so a judge's retry is seated", async () => {
    // Admitted 1 to 37 minutes ago: nobody has expired, and no join has a runner to hand a pass to.
    const { ctx, state, relay, guests } = await boardOf(DEMO_GUEST_CAP);
    delete ctx.background;
    expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 503, body: { error: "board_full" } });

    const swept = await sweepDemoGuests(ctx);
    expect(swept).toMatchObject({ done: "nothing_due", guests: DEMO_GUEST_CAP - 3, pressure: { stopped: { done: "limit" } } });
    expect(swept.pressure?.removed.map((r) => [r.member, r.reason])).toEqual(guests.slice(-DEMO_FREE_SEATS).reverse().map((g) => [g.evm, "pressure"]));
    expect(state.members).toHaveLength(DEMO_GUEST_CAP - DEMO_FREE_SEATS);
    expect((await join(ctx, joinBody(g1, await challengeFor(ctx, g1)))).status).toBe(202);

    // The judge made it 35, so the next sweep's pass takes one; at 34 the pass finds room at once and reports nothing.
    expect(await sweepDemoGuests(ctx)).toMatchObject({ done: "nothing_due", guests: DEMO_GUEST_CAP - DEMO_FREE_SEATS - 2, pressure: { removed: [{ reason: "pressure" }], stopped: { done: "room" } } });
    expect(await sweepDemoGuests(ctx)).toEqual({ done: "nothing_due", guests: DEMO_GUEST_CAP - DEMO_FREE_SEATS - 3, unknown: 0 });
    expect(state.members).toHaveLength(DEMO_GUEST_CAP - DEMO_FREE_SEATS);
    expect(calls(relay.sends)).toEqual([...Array.from({ length: DEMO_FREE_SEATS }, () => "removeMember"), "postDocument", "addMember", "removeMember", "postDocument"]);
  });

  it("removes no one when the hour has no demo relay left, and answers demo_busy", async () => {
    const { ctx, state, store, relay } = await setup({ members: [chair, asha, ben, g1], landSends: true });
    await store.setIfAbsent(admittedKey(g1.account), String(NOW - 7 * HOUR), 86_400);
    for (let n = 0; n < DEMO_RELAYS_PER_HOUR; n++) expect(await reserveDemoRelays(store, NOW, 1)).toBe(true);
    expect(await sweepDemoGuests(ctx)).toEqual({ done: "refused", reason: "demo_busy" });
    expect(relay.sends).toHaveLength(0);
    expect(state.members).toContain(g1.evm);
    expect(await sweepDemoGuests({ ...ctx, now: NOW + HOUR, wallClock: () => NOW + HOUR })).toMatchObject({ done: "removed", member: g1.evm, reason: "expired" });
  });
});

describe("sweepDemoGuests: every guest member has an admission time", () => {
  it("dates a guest member with no admission record from its latest EnvelopeGranted block, stores that time, and removes it once six hours have passed", async () => {
    const { ctx, store, relay, grantTimes } = await setup({ members: [chair, asha, ben, g1, g2] });
    grantTimes.set(g1.evm.toLowerCase(), BigInt(NOW / 1000 - 7 * 3600));
    grantTimes.set(g2.evm.toLowerCase(), BigInt(NOW / 1000 - 3600));
    expect(await sweepDemoGuests(ctx)).toMatchObject({ done: "removed", member: g1.evm, reason: "expired" });
    expect(relay.sends).toHaveLength(1);
    expect(await store.get(admittedKey(g1.account))).toBe(String(NOW - 7 * HOUR));
    expect(await store.get(admittedKey(g2.account))).toBe(String(NOW - HOUR));
    expect(await store.get(admittedKey(ben.account))).toBeNull();
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

  it("makes a guest whose ML-KEM lookup is unreadable on three sweeps in a row the target, and keeps alerting for a protected member in that state", async () => {
    const { ctx, state, store, relay, blobs, kemFailures } = await setup({ members: [chair, asha, ben, g1, g2, g3] });
    await Promise.all([admitted(store, g1, 7), admitted(store, g2, 1), admitted(store, g3, 1)]);
    kemFailures.set(g2.evm.toLowerCase(), "TIMEOUT");
    expect(await sweepDemoGuests(ctx)).toEqual({ done: "refused", reason: "kem_unavailable" });
    expect(await sweepDemoGuests(ctx)).toEqual({ done: "refused", reason: "kem_unavailable" });
    expect(relay.sends).toHaveLength(0);
    const third = await sweepDemoGuests(ctx);
    expect(third).toMatchObject({ done: "removed", member: g2.evm, reason: "key_unreadable", epochAfter: "4" });
    const [, , envelopeHash, envelopeSize] = decodeFunctionData({ abi: boardRegistryAbi, data: (relay.sends[0] as EvmSend).data }).args as unknown as readonly [bigint, Hex, Hex, number];
    const sealed = (await blobs.read(new URL(`${ORIGIN}/envelope/${envelopeHash.slice(2)}`), envelopeSize)) as Uint8Array;
    const open = (who: Identity) => openEpochKey({ registry: REGISTRY_ADDRESS, boardRef: state.boardRef, epoch: 4n, envelope: sealed, expectedHash: envelopeHash, expectedSize: envelopeSize, sealKeys: who.seal });
    for (const who of [asha, ben, g1, g3]) expect(open(who)).toEqual(open(chair));
    expect(codeOf(() => open(g2))).toBe("NOT_A_RECIPIENT");

    // A readable answer in between starts the count again, so only three unreadable sweeps in a row make a target.
    const again = await setup({ members: [chair, asha, ben, g1, g2] });
    await Promise.all([admitted(again.store, g1, 1), admitted(again.store, g2, 1)]);
    again.kemFailures.set(g2.evm.toLowerCase(), "NETWORK");
    for (let n = 0; n < 2; n++) expect(await sweepDemoGuests(again.ctx)).toEqual({ done: "refused", reason: "kem_unavailable" });
    again.kemFailures.delete(g2.evm.toLowerCase());
    expect(await sweepDemoGuests(again.ctx)).toMatchObject({ done: "nothing_due" });
    again.kemFailures.set(g2.evm.toLowerCase(), "NETWORK");
    for (let n = 0; n < 2; n++) expect(await sweepDemoGuests(again.ctx)).toEqual({ done: "refused", reason: "kem_unavailable" });
    expect(again.relay.sends).toHaveLength(0);

    const guarded = await setup({ members: [chair, asha, ben, g1] });
    await admitted(guarded.store, g1, 7);
    guarded.kemFailures.set(asha.evm.toLowerCase(), "MALFORMED");
    for (let n = 0; n < 4; n++) expect(await sweepDemoGuests(guarded.ctx)).toEqual({ done: "refused", reason: "protected_key_unusable" });
    expect(logged.filter((line) => line.includes("demo_sweep_alert") && line.includes(asha.evm))).toHaveLength(4);
    expect(guarded.relay.sends).toHaveLength(0);
  });

  it("removes a guest that published a seeded director's ML-KEM key first, then the expired guest, so no reseal holds one key twice", async () => {
    const { ctx, state, store, relay, blobs, kems } = await setup({ members: [chair, asha, ben, g1, g2], landSends: true });
    await Promise.all([admitted(store, g1, 7), admitted(store, g2, 1)]);
    kems.set(g2.evm.toLowerCase(), asha.seal.mlkemPublicKey);

    expect(await sweepDemoGuests(ctx)).toMatchObject({ done: "removed", member: g2.evm, reason: "key_shared", epochAfter: "4", landed: true });
    const [, , envelopeHash, envelopeSize] = decodeFunctionData({ abi: boardRegistryAbi, data: (relay.sends[0] as EvmSend).data }).args as unknown as readonly [bigint, Hex, Hex, number];
    const sealed = (await blobs.read(new URL(`${ORIGIN}/envelope/${envelopeHash.slice(2)}`), envelopeSize)) as Uint8Array;
    const open = (who: Identity) => openEpochKey({ registry: REGISTRY_ADDRESS, boardRef: state.boardRef, epoch: 4n, envelope: sealed, expectedHash: envelopeHash, expectedSize: envelopeSize, sealKeys: who.seal });
    for (const who of [asha, ben, g1]) expect(open(who)).toEqual(open(chair));
    expect(codeOf(() => open(g2))).toBe("NOT_A_RECIPIENT");

    expect(await sweepDemoGuests(ctx)).toMatchObject({ done: "removed", member: g1.evm, reason: "expired", epochAfter: "5", landed: true });
    expect(state.members).toEqual([chair.evm, asha.evm, ben.evm]);

    // Two protected members on one key: neither can go, so the sweep alerts and removes no one.
    const pair = await setup({ members: [chair, asha, ben, g1] });
    await admitted(pair.store, g1, 7);
    pair.kems.set(ben.evm.toLowerCase(), asha.seal.mlkemPublicKey);
    expect(await sweepDemoGuests(pair.ctx)).toEqual({ done: "refused", reason: "protected_key_unusable" });
    expect(logged.some((line) => line.includes("demo_sweep_alert") && line.includes("key_shared"))).toBe(true);
    expect(pair.relay.sends).toHaveLength(0);
  });

  it("forgets a removed member's unreadable run once its removal lands", async () => {
    const { ctx, store, kemFailures } = await setup({ members: [chair, asha, ben, g1, g2] });
    await Promise.all([admitted(store, g1, 1), admitted(store, g2, 1)]);
    kemFailures.set(g2.evm.toLowerCase(), "TIMEOUT");
    const run = `demo:kem-unreadable:${bytesToHex(g2.account)}`;
    for (let n = 0; n < 2; n++) expect(await sweepDemoGuests(ctx)).toEqual({ done: "refused", reason: "kem_unavailable" });
    expect(await store.get(run)).toMatch(/^2:/);
    expect(await sweepDemoGuests(ctx)).toMatchObject({ done: "removed", member: g2.evm, reason: "key_unreadable", landed: true });
    expect(await store.get(run)).toBeNull();
  });

  it("adds one unreadable run per sweep even when the store applies each write to that count twice", async () => {
    const { ctx, store, relay, kemFailures } = await setup({ members: [chair, asha, ben, g1, g2] });
    await Promise.all([admitted(store, g1, 1), admitted(store, g2, 1)]);
    kemFailures.set(g2.evm.toLowerCase(), "TIMEOUT");
    // A retried request the store had already applied: the write lands twice, and a compare-and-set's retry answers false.
    const twice = (key: string) => key.startsWith("demo:kem-unreadable:");
    const doubled: SharedStore = {
      get: (key) => store.get(key),
      setIfAbsent: (key, value, ttl) => store.setIfAbsent(key, value, ttl),
      delete: (key) => store.delete(key),
      withLock: (key, ttl, fn, options) => store.withLock(key, ttl, fn, options),
      incrWindow: async (key, windowSeconds, amount) => {
        if (twice(key)) await store.incrWindow(key, windowSeconds, amount);
        return store.incrWindow(key, windowSeconds, amount);
      },
      compareAndSet: async (key, expected, next, ttl) => {
        if (twice(key)) await store.compareAndSet(key, expected, next, ttl);
        return store.compareAndSet(key, expected, next, ttl);
      },
    };
    const retried = { ...ctx, store: doubled };
    for (let n = 0; n < 2; n++) expect(await sweepDemoGuests(retried)).toEqual({ done: "refused", reason: "kem_unavailable" });
    expect(relay.sends).toHaveLength(0);
    expect(await sweepDemoGuests(retried)).toMatchObject({ done: "removed", member: g2.evm, reason: "key_unreadable" });
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

describe("freeDemoSeats: the pressure pass", () => {
  it("removes the oldest guests one relay each until the board is back to 34, and stops at the first refused reservation", async () => {
    const { ctx, state, relay, guests } = await boardOf(DEMO_GUEST_CAP);
    const oldestFirst = guests.slice(-DEMO_FREE_SEATS).reverse();
    const outcome = await freeDemoSeats(ctx);
    expect(outcome.removed.map((r) => [r.member, r.reason, r.landed])).toEqual(oldestFirst.map((g) => [g.evm, "pressure", true]));
    // A full board needs exactly DEMO_FREE_SEATS removals, so the pass stops at its limit, not at a seventh board read.
    expect(outcome.stopped).toEqual({ done: "limit" });
    expect(calls(relay.sends)).toEqual(Array.from({ length: DEMO_FREE_SEATS }, () => "removeMember"));
    expect(state.members).toHaveLength(DEMO_GUEST_CAP - DEMO_FREE_SEATS);
    for (const g of oldestFirst) expect(state.members).not.toContain(g.evm);
    expect(await freeDemoSeats(ctx)).toEqual({ removed: [], stopped: { done: "room" } });
    expect(relay.sends).toHaveLength(DEMO_FREE_SEATS);

    // The hour has two demo relays left: the two oldest go, the third reservation is refused, and everyone else stays.
    const tight = await boardOf(DEMO_GUEST_CAP);
    for (let n = 0; n < DEMO_RELAYS_PER_HOUR - 2; n++) expect(await reserveDemoRelays(tight.store, NOW, 1)).toBe(true);
    const stopped = await freeDemoSeats(tight.ctx);
    expect(stopped.removed.map((r) => r.member)).toEqual(tight.guests.slice(-2).reverse().map((g) => g.evm));
    expect(stopped.stopped).toEqual({ done: "refused", reason: "demo_busy" });
    expect(tight.relay.sends).toHaveLength(2);
    expect(tight.state.members).toHaveLength(DEMO_GUEST_CAP - 2);
  });

  it("leaves every guest seated when a pass is refused or fails, and never adds to an unreadable run", async () => {
    const refused = await boardOf(DEMO_GUEST_CAP);
    const seated = [...refused.state.members];
    refused.kemFailures.set((refused.guests[0] as Member).evm.toLowerCase(), "TIMEOUT");
    // Three passes in a row: only the scheduled sweep, minutes apart, counts towards key_unreadable (C42).
    for (let n = 0; n < 3; n++) expect(await freeDemoSeats(refused.ctx)).toEqual({ removed: [], stopped: { done: "refused", reason: "kem_unavailable" } });
    expect(refused.state.members).toEqual(seated);
    expect(refused.relay.sends).toHaveLength(0);
    expect(await hourLeft(refused.store)).toBe(DEMO_RELAYS_PER_HOUR);

    const failed = await boardOf(DEMO_GUEST_CAP);
    const admissions = await Promise.all(failed.guests.map((g) => failed.store.get(admittedKey(hexToBytes(g.evm)))));
    vi.mocked(handleUpload).mockResolvedValueOnce(Response.json({ error: "store_unavailable" }, { status: 503 }));
    expect(await freeDemoSeats(failed.ctx)).toEqual({ removed: [], stopped: { done: "refused", reason: "upload_failed" } });
    expect(failed.state.members).toHaveLength(DEMO_GUEST_CAP);
    expect(failed.relay.sends).toHaveLength(0);
    expect(await Promise.all(failed.guests.map((g) => failed.store.get(admittedKey(hexToBytes(g.evm)))))).toEqual(admissions);
  });

  it("runs one pass at a time: ten board_full answers schedule one, a second pass waits for it, and its mark goes once it has run", async () => {
    let storeClock = NOW;
    const guests = fillers(DEMO_GUEST_CAP - 3);
    const { ctx, state, store, demo } = await setup({ members: [chair, asha, ben, ...guests], landSends: true, storeNow: () => storeClock });
    await Promise.all(guests.map((g, i) => store.setIfAbsent(admittedKey(hexToBytes(g.evm)), String(NOW - (i + 1) * 60_000), 86_400)));
    const { scheduled, background } = collector();
    ctx.background = background;
    const body = joinBody(g1, await challengeFor(ctx, g1));
    for (let n = 0; n < 10; n++) {
      // The stored board size lives five seconds, so each of these answers reads the board afresh.
      storeClock += 5_000;
      expect(await answer(await join(ctx, body))).toEqual({ status: 503, body: { error: "board_full" } });
    }
    expect(demo.counts.board).toBe(10);
    expect(scheduled).toHaveLength(1);
    expect(await freeDemoSeats(ctx)).toEqual({ removed: [], stopped: { done: "refused", reason: "pass_running" } });
    expect(state.members).toHaveLength(DEMO_GUEST_CAP);

    expect(await scheduled[0]?.()).toMatchObject({ stopped: { done: "limit" } });
    expect(state.members).toHaveLength(DEMO_GUEST_CAP - DEMO_FREE_SEATS);
    expect(await store.get("demo:pass")).toBeNull();
  });

  it("reads the hour's demo room before any key lookup, so a pass with none left looks nothing up and removes no one", async () => {
    const { ctx, state, store, relay, demo } = await boardOf(DEMO_GUEST_CAP);
    for (let n = 0; n < DEMO_RELAYS_PER_HOUR; n++) expect(await reserveDemoRelays(store, NOW, 1)).toBe(true);
    const lookups = demo.counts.kem;
    expect(await freeDemoSeats(ctx)).toEqual({ removed: [], stopped: { done: "refused", reason: "demo_busy" } });
    expect(demo.counts.kem).toBe(lookups);
    expect(state.members).toHaveLength(DEMO_GUEST_CAP);
    expect(relay.sends).toHaveLength(0);
  });

  it("books each removal on the clock hour it runs in, not the hour of the join that scheduled it", async () => {
    // The guests boardOf seats were admitted in the hour before NOW, so the newcomer is the youngest.
    const joinedAt = Date.parse("2026-11-19T12:59:58Z");
    const passAt = Date.parse("2026-11-19T13:00:20Z");
    const { ctx, state, store, guests } = await boardOf(DEMO_GUEST_CAP - DEMO_FREE_SEATS);
    const { scheduled, background } = collector();
    const late = { ...ctx, now: joinedAt, background, wallClock: () => passAt };
    for (let n = 0; n < DEMO_RELAYS_PER_HOUR - 1; n++) expect(await reserveDemoRelays(store, joinedAt, 1)).toBe(true);
    expect((await join(late, joinBody(g1, await challengeFor(late, g1)))).status).toBe(202);
    expect(await reserveDemoRelays(store, joinedAt, 1)).toBe(false);
    expect(scheduled).toHaveLength(1);

    const oldest = guests.at(-1) as Member;
    expect(await scheduled[0]?.()).toMatchObject({ removed: [{ member: oldest.evm, reason: "pressure", landed: true }], stopped: { done: "room" }, pack: { done: "posted", epoch: 4n } });
    expect(state.members).toHaveLength(DEMO_GUEST_CAP - DEMO_FREE_SEATS);
    // The pass's one removal and the pack's post.
    expect(await hourLeft(store, passAt)).toBe(DEMO_RELAYS_PER_HOUR - 2);
  });

  it("still removes a guest whose ML-KEM key is gone first, whatever its age, then the oldest", async () => {
    const { ctx, state, kems, guests } = await boardOf(DEMO_GUEST_CAP);
    const youngest = guests[0] as Member;
    kems.delete(youngest.evm.toLowerCase());
    const outcome = await freeDemoSeats(ctx);
    expect(outcome.removed.map((r) => [r.member, r.reason])).toEqual([
      [youngest.evm, "key_missing"],
      ...guests
        .slice(-(DEMO_FREE_SEATS - 1))
        .reverse()
        .map((g) => [g.evm, "pressure"]),
    ]);
    expect(state.members).toHaveLength(DEMO_GUEST_CAP - DEMO_FREE_SEATS);
  });
});

describe("ensureCurrentPack: the demo pack", () => {
  it("posts the pack once for a current epoch that has none, so a guest admitted at that epoch opens it to the pack text's bytes", async () => {
    const { ctx, state, store, relay, blobs } = await setup({ landSends: true });
    // The board's packs are all from the epoch before, so none is for the epoch a judge joins at.
    Object.assign(state, { documentCount: 3, latestDocumentEpoch: state.epoch - 1n });
    expect((await join(ctx, joinBody(g1, await challengeFor(ctx, g1)))).status).toBe(202);
    const nonce = state.nonce;

    expect(await ensureCurrentPack(ctx)).toEqual({ done: "posted", txHash: expect.stringMatching(/^0x[0-9a-f]{64}$/), epoch: 3n });
    expect(calls(relay.sends)).toEqual(["addMember", "postDocument"]);
    const posted = postArgs(relay.sends[1] as EvmSend);
    expect(posted).toMatchObject({ boardId: BOARD_ID, epoch: 3n, cipherSize: BigInt(12 + PACK.length + 16), deadline: BigInt(NOW / 1000 + 600) });
    // The relay posts a document only at the size its verified mark holds.
    expect(await store.get(`verified:${posted.cipherHash.slice(2)}`)).toBe(posted.cipherSize.toString());
    const message = actionMessage({ registry: REGISTRY_ADDRESS, action: Action.POST, boardId: BOARD_ID, paramsHash: paramsPost(posted), nonce, deadline: posted.deadline });
    expect(verifyAction(chair.mldsa.publicKey, message, hexToBytes(posted.signature))).toBe(true);
    expect(state).toMatchObject({ documentCount: 4, latestDocumentEpoch: 3n });

    const own = state.grants.find((g) => g.member === g1.evm) as Grant;
    const read = await readPack(blobs, state.boardRef, own, g1.seal, posted);
    expect(read).toEqual(PACK);
    expect(new TextDecoder().decode(read).split("\n")[0]).toBe("Ava demo board: board pack");
    expect(await readPack(blobs, state.boardRef, state.grants[0] as Grant, asha.seal, posted)).toEqual(PACK);
    await expect(readPack(blobs, state.boardRef, own, g2.seal, posted)).rejects.toMatchObject({ code: "NOT_A_RECIPIENT" });
  });

  it("refuses pack_unavailable, touching nothing, when the pack text is empty", async () => {
    vi.resetModules();
    vi.doMock("../src/demoPack.ts", () => ({ DEMO_PACK_TEXT: "" }));
    try {
      const fresh = await import("../src/demo.ts");
      const { ctx, state, untouched } = await setup({ landSends: true });
      Object.assign(state, { documentCount: 0, latestDocumentEpoch: undefined });
      expect(await fresh.ensureCurrentPack(ctx)).toEqual({ done: "refused", reason: "pack_unavailable" });
      expect(untouched()).toBe(true);
    } finally {
      vi.doUnmock("../src/demoPack.ts");
      vi.resetModules();
    }
  });

  it("posts nothing, reserves nothing and reads no envelope when the current epoch already has a pack", async () => {
    const { ctx, store, untouched } = await setup();
    expect(await ensureCurrentPack(ctx)).toEqual({ done: "current" });
    expect(untouched()).toBe(true);
    expect(await hourLeft(store)).toBe(DEMO_RELAYS_PER_HOUR);
  });

  it("posts once when two runs race for the same epoch: the second waits for the lock and finds the first one's pack", async () => {
    const { ctx, state, relay } = await setup({ landSends: true });
    Object.assign(state, { documentCount: 0, latestDocumentEpoch: undefined });
    const outcomes = await Promise.all([ensureCurrentPack(ctx), ensureCurrentPack(ctx)]);
    expect(outcomes.map((o) => o.done).sort()).toEqual(["current", "posted"]);
    expect(calls(relay.sends)).toEqual(["postDocument"]);
    expect(state).toMatchObject({ documentCount: 1, latestDocumentEpoch: 3n });
  });

  it("answers refused demo_busy when the hour has no demo relay left, and stores, signs and changes nothing", async () => {
    const { ctx, state, store, untouched } = await setup({ landSends: true });
    Object.assign(state, { documentCount: 0, latestDocumentEpoch: undefined });
    for (let n = 0; n < DEMO_RELAYS_PER_HOUR; n++) expect(await reserveDemoRelays(store, NOW, 1)).toBe(true);
    const before = structuredClone(state);
    expect(await ensureCurrentPack(ctx)).toEqual({ done: "refused", reason: "demo_busy" });
    expect(untouched()).toBe(true);
    expect(state).toEqual(before);
    // The next clock hour has room, and the pack goes out then.
    expect(await ensureCurrentPack({ ...ctx, wallClock: () => NOW + HOUR })).toMatchObject({ done: "posted", epoch: 3n });
  });

  it("follows a join's pressure pass, which moved the epoch six times, with one post for the final epoch that every guest left on the board can open", async () => {
    const { ctx, state, relay, blobs, guests } = await boardOf(DEMO_GUEST_CAP);
    const { scheduled, background } = collector();
    ctx.background = background;
    expect(await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))))).toEqual({ status: 503, body: { error: "board_full" } });
    expect(scheduled).toHaveLength(1);

    const final = 3n + BigInt(DEMO_FREE_SEATS);
    expect(await scheduled[0]?.()).toMatchObject({ stopped: { done: "limit" }, pack: { done: "posted", epoch: final } });
    expect(calls(relay.sends)).toEqual([...Array.from({ length: DEMO_FREE_SEATS }, () => "removeMember"), "postDocument"]);
    const posted = postArgs(relay.sends.at(-1) as EvmSend);
    expect(posted.epoch).toBe(final);
    const rotation = state.grants[0] as Grant;
    for (const guest of guests.slice(0, -DEMO_FREE_SEATS)) expect(await readPack(blobs, state.boardRef, rotation, guest.seal, posted)).toEqual(PACK);
    await expect(readPack(blobs, state.boardRef, rotation, (guests.at(-1) as Member).seal, posted)).rejects.toMatchObject({ code: "NOT_A_RECIPIENT" });
    expect(await ensureCurrentPack(ctx)).toEqual({ done: "current" });
    expect(relay.sends).toHaveLength(DEMO_FREE_SEATS + 1);
  });

  it("follows every admitted join with it in the background, so a guest joining a quiet board whose epoch has no pack gets one post it opens, and the next guest none", async () => {
    // Twenty members, far from the pressure threshold, and the newest pack is from an earlier epoch.
    const { ctx, state, relay, blobs } = await boardOf(20);
    Object.assign(state, { documentCount: 3, latestDocumentEpoch: state.epoch - 1n });
    const { scheduled, background } = collector();
    ctx.background = background;
    expect((await join(ctx, joinBody(g1, await challengeFor(ctx, g1)))).status).toBe(202);
    expect(scheduled).toHaveLength(1);
    expect(await scheduled[0]?.()).toEqual({ done: "posted", txHash: expect.stringMatching(/^0x[0-9a-f]{64}$/), epoch: 3n });
    expect(calls(relay.sends)).toEqual(["addMember", "postDocument"]);
    const own = state.grants.find((g) => g.member === g1.evm) as Grant;
    expect(await readPack(blobs, state.boardRef, own, g1.seal, postArgs(relay.sends[1] as EvmSend))).toEqual(PACK);

    expect((await join(ctx, joinBody(g2, await challengeFor(ctx, g2)))).status).toBe(202);
    expect(scheduled).toHaveLength(2);
    expect(await scheduled[1]?.()).toEqual({ done: "current" });
    expect(calls(relay.sends)).toEqual(["addMember", "postDocument", "addMember"]);
  });

  it("ends every scheduled sweep: a sweep whose removal moved the epoch posts that epoch's pack, and one with nothing new to seal posts nothing", async () => {
    const { ctx, state, store, relay, blobs } = await setup({ members: [chair, asha, ben, g1, g2], landSends: true });
    await store.setIfAbsent(admittedKey(g1.account), String(NOW - 7 * HOUR), 86_400);
    await store.setIfAbsent(admittedKey(g2.account), String(NOW - HOUR), 86_400);

    const swept = await sweepDemoGuests(ctx);
    expect(swept).toMatchObject({ done: "removed", member: g1.evm, epochAfter: "4", landed: true, pack: { done: "posted", epoch: 4n } });
    expect(calls(relay.sends)).toEqual(["removeMember", "postDocument"]);
    const posted = postArgs(relay.sends[1] as EvmSend);
    expect(await readPack(blobs, state.boardRef, state.grants[0] as Grant, g2.seal, posted)).toEqual(PACK);
    await expect(readPack(blobs, state.boardRef, state.grants[0] as Grant, g1.seal, posted)).rejects.toMatchObject({ code: "NOT_A_RECIPIENT" });

    expect(await sweepDemoGuests(ctx)).toEqual({ done: "nothing_due", guests: 1, unknown: 0 });
    expect(relay.sends).toHaveLength(2);
    // An epoch left with no pack, though no one is due, gets one from the next sweep.
    Object.assign(state, { documentCount: 0, latestDocumentEpoch: undefined });
    expect(await sweepDemoGuests(ctx)).toMatchObject({ done: "nothing_due", pack: { done: "posted", epoch: 4n } });
    expect(calls(relay.sends)).toEqual(["removeMember", "postDocument", "postDocument"]);
  });
});

describe("demo endpoints and the browser", () => {
  it("refuses with 403 what a cross-site page can send to the challenge or the join, before it counts, reads the body or reaches the store", async () => {
    const { ctx, store, untouched } = await setup();
    const touched = [vi.spyOn(store, "incrWindow"), vi.spyOn(store, "get"), vi.spyOn(store, "setIfAbsent")];
    for (const headers of CROSS_SITE_HEADERS) {
      for (const handler of [handleDemoChallenge, handleDemoJoin]) {
        const request = new Request("http://localhost/api/demo/x", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ guest: g1.evm }) });
        const response = await handler(request, ctx);
        expect({ handler: handler.name, headers, status: response.status }).toEqual({ handler: handler.name, headers, status: 403 });
        expect(await response.json()).toEqual({ error: "cross_site" });
        expect(request.bodyUsed).toBe(false);
      }
    }
    for (const spy of touched) expect(spy).not.toHaveBeenCalled();
    expect(untouched()).toBe(true);
  });

  it("gives up with 408 on a challenge or join body that has not ended after 20 seconds", async () => {
    const { ctx } = await setup();
    vi.useFakeTimers();
    for (const handler of [handleDemoChallenge, handleDemoJoin]) {
      const body = stalledBody();
      const request = new Request("http://localhost/api/demo/x", { method: "POST", headers: { "content-type": "application/json", "x-ava": "1" }, body: body.stream, duplex: "half" } as RequestInit);
      const pending = handler(request, ctx);
      for (let i = 0; i < 1_000 && !body.waiting(); i++) await Promise.resolve();
      expect(body.waiting()).toBe(true);
      await vi.advanceTimersByTimeAsync(20_000);
      expect(await answer(await pending)).toEqual({ status: 408, body: { error: "body_timeout" } });
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

describe("handleDemoLeave: a guest leaves by its own signature", () => {
  const LATEST = BigInt(Math.floor(NOW / 1000));
  const lower = (members: readonly Hex[]) => members.map((m) => m.toLowerCase());

  async function leaveChallengeFor(ctx: DemoContext, guest: Identity): Promise<Challenge> {
    const response = await handleDemoLeaveChallenge(post("leave/challenge", { guest: guest.qor1 }), ctx);
    expect(response.status).toBe(200);
    return (await response.json()) as Challenge;
  }

  function leaveBody(guest: Identity, c: Challenge, signer: Identity = guest) {
    const signed = signLeave(signer.mldsa.secretKey, { registry: REGISTRY_ADDRESS, boardId: BigInt(c.boardId), guest: guest.evm, botNonce: c.botNonce, expiry: BigInt(c.expiry), latestBlockTimestamp: LATEST });
    return { guest: guest.evm, botNonce: c.botNonce, expiry: c.expiry, signature: bytesToHex(signed.signature) };
  }

  const leave = (ctx: DemoContext, body: unknown) => handleDemoLeave(post("leave", body), ctx);

  function removeArgs(send: EvmSend) {
    const decoded = decodeFunctionData({ abi: boardRegistryAbi, data: send.data });
    expect(decoded.functionName).toBe("removeMember");
    const [boardId, member, envelopeHash, envelopeSize, epochAfter] = decoded.args as unknown as readonly [bigint, Hex, Hex, number, bigint];
    return { boardId, member, envelopeHash, envelopeSize, epochAfter };
  }

  const withGuests = () => setup({ members: [chair, asha, ben, g1, g2], landSends: true });

  it("issues a leave request that is the spec's bytes, one live per guest, and never the join challenge", async () => {
    const { ctx, store } = await withGuests();
    const c = await leaveChallengeFor(ctx, g1);
    const expected = leaveMessage({ registry: REGISTRY_ADDRESS, boardId: BOARD_ID, guest: g1.evm, botNonce: c.botNonce, expiry: BigInt(c.expiry) });
    expect(c.message).toBe(bytesToHex(expected));
    expect(BigInt(c.expiry)).toBe(LATEST + 300n);
    expect((await leaveChallengeFor(ctx, g1)).botNonce).toBe(c.botNonce);
    const joinChallenge = await challengeFor(ctx, g1);
    expect(joinChallenge.botNonce).not.toBe(c.botNonce);
    expect(joinChallenge.message).not.toBe(c.message);
    expect(await store.get(leaveKey(g1.account))).not.toBe(await store.get(challengeKey(g1.account)));
  });

  it("removes exactly the guest who signed, seals the next epoch to everyone else, and the next pack stays shut to the one who left", async () => {
    const board = await withGuests();
    const tasks = collector();
    const ctx = { ...board.ctx, background: tasks.background };
    const epochBefore = board.state.epoch;
    const result = await answer(await leave(ctx, leaveBody(g1, await leaveChallengeFor(ctx, g1))));
    expect(result.status).toBe(202);
    expect(result.body).toEqual({ txHash: expect.stringMatching(/^0x[0-9a-f]{64}$/), epochAfter: String(epochBefore + 1n) });
    expect(calls(board.relay.sends)).toEqual(["removeMember"]);
    const removed = removeArgs(board.relay.sends[0] as EvmSend);
    expect(removed.member.toLowerCase()).toBe(g1.evm.toLowerCase());
    expect(removed.epochAfter).toBe(epochBefore + 1n);
    expect(lower(board.state.members)).toEqual(lower([chair.evm, asha.evm, ben.evm, g2.evm]));

    const grant = board.state.grants[0] as Grant;
    const envelope = (await board.blobs.read(new URL(`${ORIGIN}/envelope/${grant.envelopeHash.slice(2)}`), grant.envelopeSize)) as Uint8Array;
    const open = (keys: Member["seal"]) =>
      openEpochKey({ registry: REGISTRY_ADDRESS, boardRef: board.state.boardRef, epoch: board.state.epoch, envelope, expectedHash: grant.envelopeHash, expectedSize: grant.envelopeSize, sealKeys: keys });
    expect(() => open(g1.seal)).toThrow();
    for (const stays of [chair, asha, ben, g2]) expect(open(stays.seal)).toHaveLength(32);

    expect(tasks.scheduled).toHaveLength(1);
    await (tasks.scheduled[0] as () => Promise<unknown>)();
    expect(calls(board.relay.sends)).toEqual(["removeMember", "postDocument"]);
    const posted = postArgs(board.relay.sends[1] as EvmSend);
    expect(posted.epoch).toBe(epochBefore + 1n);
    expect(await readPack(board.blobs, board.state.boardRef, grant, g2.seal, posted)).toEqual(PACK);
    await expect(readPack(board.blobs, board.state.boardRef, grant, g1.seal, posted)).rejects.toThrow();
  });

  it("keeps the admission used: the guest who left cannot join again", async () => {
    const board = await withGuests();
    const ctx = board.ctx;
    expect(await board.store.get(admittedKey(g1.account))).toBeNull();
    expect((await answer(await leave(ctx, leaveBody(g1, await leaveChallengeFor(ctx, g1))))).status).toBe(202);
    expect(await board.store.get(admittedKey(g1.account))).not.toBeNull();
    const again = await answer(await join(ctx, joinBody(g1, await challengeFor(ctx, g1))));
    expect(again).toEqual({ status: 409, body: { error: "already_admitted" } });
    expect(calls(board.relay.sends)).toEqual(["removeMember"]);
  });

  it("refuses a leave signed by anyone but the guest it names, and changes nothing", async () => {
    const board = await withGuests();
    const c = await leaveChallengeFor(board.ctx, g1);
    for (const signer of [g2, chair, g3]) {
      expect(await answer(await leave(board.ctx, leaveBody(g1, c, signer)))).toEqual({ status: 403, body: { error: "bad_signature" } });
    }
    expect(board.relay.sends).toHaveLength(0);
    expect(lower(board.state.members)).toContain(g1.evm.toLowerCase());
    expect(await hourLeft(board.store)).toBe(DEMO_RELAYS_PER_HOUR);
  });

  it("takes no join signature as a leave and no leave signature as a join", async () => {
    const board = await withGuests();
    const c = await leaveChallengeFor(board.ctx, g1);
    const asJoin = challengeMessage({ registry: REGISTRY_ADDRESS, boardId: BOARD_ID, guest: g1.evm, botNonce: c.botNonce, expiry: BigInt(c.expiry) });
    const joinSigned = { guest: g1.evm, botNonce: c.botNonce, expiry: c.expiry, signature: bytesToHex(signAction(g1.mldsa.secretKey, asJoin)) };
    expect(await answer(await leave(board.ctx, joinSigned))).toEqual({ status: 403, body: { error: "bad_signature" } });

    const j = await challengeFor(board.ctx, g3);
    const leaveSigned = signLeave(g3.mldsa.secretKey, { registry: REGISTRY_ADDRESS, boardId: BOARD_ID, guest: g3.evm, botNonce: j.botNonce, expiry: BigInt(j.expiry), latestBlockTimestamp: LATEST });
    const asLeave = { guest: g3.evm, botNonce: j.botNonce, expiry: j.expiry, signature: bytesToHex(leaveSigned.signature) };
    expect(await answer(await join(board.ctx, asLeave))).toEqual({ status: 403, body: { error: "bad_signature" } });
    expect(board.relay.sends).toHaveLength(0);
  });

  it("keeps join challenges and leave requests apart: one cannot stand in for the other", async () => {
    const board = await withGuests();
    const j = await challengeFor(board.ctx, g1);
    const withJoinNonce = signLeave(g1.mldsa.secretKey, { registry: REGISTRY_ADDRESS, boardId: BOARD_ID, guest: g1.evm, botNonce: j.botNonce, expiry: BigInt(j.expiry), latestBlockTimestamp: LATEST });
    const body = { guest: g1.evm, botNonce: j.botNonce, expiry: j.expiry, signature: bytesToHex(withJoinNonce.signature) };
    expect(await answer(await leave(board.ctx, body))).toEqual({ status: 409, body: { error: "no_challenge" } });
    expect(board.relay.sends).toHaveLength(0);
  });

  it("never removes the chair or a seeded director this way, even with their own signature", async () => {
    const board = await withGuests();
    for (const who of [asha, chair]) {
      const refused = await answer(await leave(board.ctx, leaveBody(who, await leaveChallengeFor(board.ctx, who))));
      expect(refused).toEqual({ status: 403, body: { error: "protected_member" } });
    }
    expect(board.relay.sends).toHaveLength(0);
    expect(board.state.members).toHaveLength(5);
  });

  it("refuses a valid request from an account that is not on the board, reserving and sending nothing", async () => {
    const board = await withGuests();
    const refused = await answer(await leave(board.ctx, leaveBody(g3, await leaveChallengeFor(board.ctx, g3))));
    expect(refused).toEqual({ status: 409, body: { error: "not_a_member" } });
    expect(board.relay.sends).toHaveLength(0);
    expect(await hourLeft(board.store)).toBe(DEMO_RELAYS_PER_HOUR);
  });

  it("serves one leave request once, even when the store lost the reply of the write that used it up", async () => {
    const board = await withGuests();
    const retried = { ...board.ctx, store: retriedWrites(board.store, (write, key) => write !== "setIfAbsent" && key === leaveKey(g1.account)) };
    const body = leaveBody(g1, await leaveChallengeFor(retried, g1));
    expect((await answer(await leave(retried, body))).status).toBe(202);
    expect(await answer(await leave(retried, body))).toEqual({ status: 409, body: { error: "no_challenge" } });
    expect(calls(board.relay.sends)).toEqual(["removeMember"]);
  });

  it("removes nobody when the hour has no demo relay left, and says when to come back", async () => {
    const board = await withGuests();
    expect(await hourLeft(board.store)).toBe(DEMO_RELAYS_PER_HOUR);
    const response = await leave(board.ctx, leaveBody(g1, await leaveChallengeFor(board.ctx, g1)));
    expect(response.headers.get("retry-after")).not.toBeNull();
    expect(await answer(response)).toEqual({ status: 503, body: { error: "demo_busy" } });
    expect(board.relay.sends).toHaveLength(0);
    expect(lower(board.state.members)).toContain(g1.evm.toLowerCase());
  });

  it("removes nobody while another member's key cannot be read, because the next epoch could not be sealed to it", async () => {
    const board = await withGuests();
    board.kemFailures.set(g2.evm.toLowerCase(), "TIMEOUT");
    const refused = await answer(await leave(board.ctx, leaveBody(g1, await leaveChallengeFor(board.ctx, g1))));
    expect(refused).toEqual({ status: 503, body: { error: "kem_unavailable" } });
    expect(board.relay.sends).toHaveLength(0);
    expect(lower(board.state.members)).toContain(g1.evm.toLowerCase());
  });

  it("counts leaves per address, refuses a cross-site request before anything, and answers not_ready before the board is seeded", async () => {
    const board = await withGuests();
    const tight = { ...board.ctx, limits: { ...ROOMY, leave: { perIp: 2, windowSeconds: 3600 } } };
    const body = leaveBody(g3, await leaveChallengeFor(tight, g3));
    expect((await leave(tight, body)).status).toBe(409);
    expect((await leave(tight, body)).status).toBe(409);
    expect(await answer(await leave(tight, body))).toEqual({ status: 429, body: { error: "rate_limited" } });

    for (const headers of CROSS_SITE_HEADERS) {
      for (const handler of [handleDemoLeaveChallenge, handleDemoLeave]) {
        const request = new Request("http://localhost/api/demo/x", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ guest: g1.evm }) });
        const response = await handler(request, board.ctx);
        expect(response.status).toBe(403);
        expect(request.bodyUsed).toBe(false);
      }
    }
    const unseeded = await setup({ boardId: undefined });
    expect((await handleDemoLeaveChallenge(post("leave/challenge", { guest: g1.qor1 }), unseeded.ctx)).status).toBe(503);
    expect((await leave(unseeded.ctx, body)).status).toBe(503);
    expect(board.relay.sends).toHaveLength(0);
  });
});
