import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import {
  Action,
  KemKeyUnavailable,
  Mode,
  actionMessage,
  decryptDocument,
  generateMnemonic,
  identityFromMnemonic,
  openEpochKey,
  paramsAdd,
  paramsPost,
  paramsRemove,
  sealEpochKey,
  newEpochKey,
  sha256,
  toHex,
  verifyAction,
  type Identity,
  type KemRecipient,
} from "@ava/core";
import { evmWindowCost, weiToUqorCeil, type EvmWindow } from "@qorechain/evm";
import { generateSealKeys, type SealKeyPair } from "@qorechain/qoreseal";
import type { Scheduler } from "fast-check";
import { bytesToHex, decodeFunctionData, encodeErrorResult, encodeFunctionResult, getAddress, hexToBytes, keccak256, toFunctionSelector, type Hex } from "viem";
import { boardRegistryAbi } from "../../src/abi/boardRegistry.ts";
import { MemoryBlobBackend } from "../../src/blob.ts";
import { leftMs, type Deadline } from "../../src/chain/deadline.ts";
import { NotBroadcast } from "../../src/chain/evm.ts";
import { RefusedBeforeInclusion } from "../../src/chain/native.ts";
import type { BeforeBroadcast, CallOutcome, EvmSend, ReceiptFee, RelayChain, TxRequest, TxStatus, WindowRequest } from "../../src/chain/types.ts";
import {
  DEMO_CHALLENGE_LIMITS,
  DEMO_FREE_SEATS,
  DEMO_GUEST_CAP,
  DEMO_GUEST_TTL_SECONDS,
  DEMO_JOIN_LIMITS,
  GAS_CEILING,
  REGISTRY_ADDRESS,
  REGISTRY_CODE_KECCAK,
  REGISTRY_DEPLOY_BLOCK,
  RELAY_LIMITS,
  WINDOW,
  WINDOW_CLOSE_FEE_UQOR,
  WINDOW_OPEN_FEE_UQOR,
  type RelayAction,
} from "../../src/config.ts";
import { admittedKey, type DemoContext, type DemoLimits, type DemoSweepContext } from "../../src/demo.ts";
import type { BoardSnapshot, DemoChain, Grant, KeyStatus } from "../../src/demoBoard.ts";
import type { DocumentContext } from "../../src/docupload.ts";
import type { EnvelopeLogs } from "../../src/envelopeSweep.ts";
import type { RelayContext, RelayLimits } from "../../src/relay.ts";
import { LockBusy, MemoryStore, type LockOptions, type SharedStore } from "../../src/store.ts";
import { ledgerFor, nonceKey } from "../../src/window.ts";

// A made-up store credential: the handlers only pass it through, and no request leaves the model.
const FAKE_STORE_CREDENTIAL = "vercel_blob_rw_world_notarealsecret";

/** Thursday 19 Nov 2026, 10:00 UTC: far enough from midnight that a day jump is a command, not an accident. */
export const T0 = Date.parse("2026-11-19T10:00:00Z");
export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;
export const ORIGIN = "https://blobs.example";
export const DEMO_BOARD = 9n;
export const PUBLIC_BOARDS = [1n, 2n, 3n] as const;
export const RELAYER = { qor1: "qor13gmaduk6r79q0utnt3tgcfs3ypwe86tn8292fq", evm: "0x8A37d6f2DA1F8a07f1735c568C2611205d93e973" } as const;
/** Two IPv4 clients, one more, and two /64s of one IPv6 /48, so the /48 rule is reachable. */
export const CLIENT_IPS = ["203.0.113.1", "203.0.113.2", "198.51.100.7", "2001:db8:5:1::7", "2001:db8:5:2::7"] as const;
/** Boards 1 and 2 share a chair, so one chair's counters span two boards. */
export const PUBLIC_CHAIRS = [getAddress("0x64b85c422776d173a324fa72cc72f7fffdd42d82"), getAddress("0x624b5c35e3665eb9ade6d75bbbca1218a09e00d1")] as const;
export const ZERO: Hex = "0x0000000000000000000000000000000000000000";
const GWEI = 1_000_000_000n;
const BASE_FEE = 100n * GWEI;
const TIP = GWEI;
const BLOCK_MS = 1_400;
/** A few thousand blocks past the deploy block, so one log scan page covers the whole history. */
const H0 = REGISTRY_DEPLOY_BLOCK + 5_000n;
/** The relayer's account nonce when the world starts, adopted already: a relayer that has been running. */
const START_NONCE = 5n;
const SLOW_LAND_MS = 2_500;
const SIGNATURE_BYTES = 4_627;
/** Limits a run of sixty commands can reach, so the refusals at each one are exercised too. */
const TIGHT_RELAY_LIMITS: RelayLimits = { perIp: 8, perChair: 6, perBoard: 5, total: 12, rejected: 6, windowSeconds: 3600 };
const TIGHT_DEMO_LIMITS: DemoLimits = { join: { perIp: 3, windowSeconds: 3600, perDay: 6 }, challenge: { perIp: 5, total: 12, windowSeconds: 3600 }, leave: { perIp: 2, windowSeconds: 3600 } };
const GET_BOARD = toFunctionSelector("getBoard(uint256)");
const ACTION_OF: Readonly<Record<string, RelayAction | undefined>> = { addMember: "add", removeMember: "remove", rotateEpoch: "rotate", postDocument: "post", transferChair: "transfer", createBoard: "create" };
const CREATE_NONCES = toFunctionSelector("createNonces(address)");

/**
 * What the chain does with one EVM send the relayer hands it. land: in a block at once. slow: in a
 * block 2.5 s of world time later. pending: in the pool until a mine command. revert: in a block at
 * once, reverted. refuse: the node refuses it and it never exists. lostReply: the node takes it but
 * the answer is lost, so the send throws. noReceipt: in a block, but no receipt is ever reported.
 * lieReceipt: in a block, and the receipt reports more gas than the transaction allowed.
 */
export type TxFate = "land" | "slow" | "pending" | "revert" | "refuse" | "lostReply" | "noReceipt" | "lieReceipt";
/** What the chain does with one native window open or close: commit, or refuse before any block. */
export type NativeFate = "commit" | "refuse";
export type TxState = "pending" | "landed" | "reverted" | "unknown";

export interface ChainTx {
  hash: string;
  kind: "evm" | "native";
  nonce: bigint;
  state: TxState;
  what: "send" | "open" | "close" | "foreign";
  seq: number;
  command: string;
  at: number;
  /** The request that handed it over, and when that request began. */
  flow?: number;
  flowStartedAt: number;
  /** The length of the store's write log when it was handed over, to order it against counter windows. */
  logIndex: number;
  data?: Hex;
  gas?: bigint;
  maxFeePerGas?: bigint;
  receipt: "true" | "never" | "lie";
  landAt?: number;
  landedAt?: number;
  /** The real fee in uqor, once it is in a block. */
  fee: bigint;
  /**
   * The UTC days its worst case may be booked on, by the world clock: from the day its request began
   * to the day it was handed over. The code books on the request's own time, so one that straddles
   * midnight may land on either; any other day is wrong.
   */
  days: string[];
  /** The board nonce its signature is for, read from the signature itself; undefined for a window open or close. */
  signedNonce?: bigint;
  forceRevert: boolean;
  /** The command sequence number at which it became unknown or reverted. */
  deadSeq?: number;
  scope?: "public" | "demo";
  boardId?: bigint;
  action?: string;
  chair?: Hex;
  member?: Hex;
  cipherHash?: Hex;
  cipherSize?: bigint;
  /** For a public post: the UTC day of the relay request, the day its bytes are booked on. */
  requestDay?: string;
}

/** One document a board holds, in the order the registry recorded them. `bot` marks the demo bot's own packs. */
export interface DocumentModel {
  docRef: Hex;
  cipherHash: Hex;
  cipherSize: bigint;
  epoch: bigint;
  bot: boolean;
}

export interface BoardModel {
  id: bigint;
  chair: Hex;
  boardRef: Hex;
  epoch: bigint;
  nonce: bigint;
  members: Hex[];
  grants: Grant[];
  documents: DocumentModel[];
}

export interface ChainEvent {
  block: bigint;
  boardId: bigint;
  kind: "granted" | "posted";
  envelopeHash?: Hex;
  member?: Hex;
  cipherHash?: Hex;
  cipherSize?: bigint;
}

export type KemMode = { kind: "own" } | { kind: "none" } | { kind: "copy"; from: Hex } | { kind: "unreadable" } | { kind: "invalid" };

export interface SeatOnly {
  evm: Hex;
  seal: SealKeyPair;
}

/** Everyone the worlds share: real keys are slow to derive, so they are made once per test file. */
export interface Cast {
  chairPhrase: string;
  chair: Identity;
  seeded: readonly [Identity, Identity];
  guests: readonly Identity[];
  /** Members seated before the run began who hold signing keys of their own, so they can sign a leave. They are the first of the fillers. */
  early: readonly Identity[];
  fillers: readonly SeatOnly[];
  /** The demo board's seed envelope for each filler count, sealed once. */
  seedEnvelopes: Map<number, { boardRef: Hex; envelope: Uint8Array }>;
}

export async function makeCast(guestCount = 6, fillerCount = 36, earlyCount = 3): Promise<Cast> {
  const chairPhrase = generateMnemonic();
  const earlySeats = Math.min(earlyCount, fillerCount);
  const ids = await Promise.all(Array.from({ length: 3 + guestCount + earlySeats }, (_, i) => identityFromMnemonic(i === 0 ? chairPhrase : generateMnemonic())));
  const [chair, asha, ben, ...rest] = ids as [Identity, Identity, Identity, ...Identity[]];
  const guests = rest.slice(0, guestCount);
  const early = rest.slice(guestCount);
  const fillers = [
    ...early.map((e): SeatOnly => ({ evm: e.evm, seal: e.seal })),
    ...Array.from({ length: fillerCount - earlySeats }, (_, i) => ({ evm: toHex(Uint8Array.from({ length: 20 }, (_, j) => (j === 19 ? i + 1 : j === 0 ? 0x5e : 0xf0))), seal: generateSealKeys() })),
  ];
  return { chairPhrase, chair, seeded: [asha, ben], guests, early, fillers, seedEnvelopes: new Map() };
}

/** The pair qor_getKEMKey answers, in the frozen shape fetchKemKey builds. */
export const published = (address: Hex, key: Uint8Array): KemRecipient => Object.freeze({ address: toHex(hexToBytes(address)), kemPublicKey: key }) as KemRecipient;

/** The starting state a run draws: how full the demo board is, how tight the limits are, how much of today is spent already. */
export interface WorldInit {
  fillers: number;
  /** Minutes between the fillers' admission times, so some runs start with guests already past six hours. */
  fillerStepMinutes: number;
  tightLimits: boolean;
  /** The demo bot's relays per clock hour: the real 120, or a handful so demo_busy is reached. */
  demoRelaysPerHour: number;
  /** The share of each daily ledger already booked before the run starts. */
  preSpend: 0 | 0.5 | 0.97;
  /** Whether the demo board starts with a pack for its epoch, as the seed script leaves it, or with none, so the first pack is the bot's. */
  seedPack: boolean;
}

export interface StoreOp {
  op: "incr" | "setIfAbsent" | "cas" | "delete";
  key: string;
  amount?: number;
  at: number;
  /** The request that made it, so a refusal can be checked for what that request alone moved. */
  flow?: number;
  /** Whether the store changed: a write whose condition failed changed nothing. */
  wrote: boolean;
}

/** What the store needs from the world: a point where another request may run, time passing for a lock waiter, and who is asking. */
export interface StoreHooks {
  turn(label: string): Promise<void>;
  wait(ms: number): Promise<void>;
  flow(): number | undefined;
}

/** A lock waiter's pause between tries, in world time: the middle of the store's 50 to 200 ms. */
const LOCK_PAUSE_MS = 125;

/**
 * Which writes of one command land and then answer as a lost reply would: none, the ones named by
 * their ordinal in the command, every one, or each one with probability 0.3 from a seeded draw.
 */
export type LostMode = { kind: "none" } | { kind: "at"; ordinals: readonly number[] } | { kind: "every" } | { kind: "chance"; seed: number };

/** A small seeded generator (mulberry32), so a "chance" command replays the same writes. */
function seeded(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

/**
 * The real MemoryStore on the world's clock, with what a test needs: every write is logged with the
 * world time and the request that made it, every call is a point where an overlapping request may
 * run, locks wait on the world's clock, and the writes the command's LostMode picks (setIfAbsent,
 * compareAndSet, delete and increments alike) are applied twice and answered with the second reply,
 * which is what a client retry after a lost reply does. What a doubled increment added is kept per
 * key, so a counter can be compared with what the code meant to count.
 */
export class WorldStore implements SharedStore {
  readonly inner: MemoryStore;
  readonly log: StoreOp[] = [];
  /** When each counter's current window began: the world time, and the place in the write log, which orders events that share a millisecond. */
  readonly windowStart = new Map<string, { at: number; index: number }>();
  /** When each key written through here expires, in world time, as the store was told. */
  readonly expiry = new Map<string, number>();
  #lost: LostMode = { kind: "none" };
  #draw?: () => number;
  writes = 0;
  /** How many writes were applied twice in the whole run, by kind, and how many of them came after a command's fortieth write. */
  retried = 0;
  readonly retriedBy = { setIfAbsent: 0, cas: 0, delete: 0, incr: 0 };
  retriedLate = 0;
  /** What doubled increments added to each counter in its current window, beyond what the code asked for. */
  readonly extra = new Map<string, number>();
  /** Lock calls that found the lock held and waited, and locks taken while an earlier holder was still running because its lock had run out. */
  lockWaits = 0;
  lockTakeovers = 0;
  readonly #holding = new Map<string, number>();
  readonly #clock: () => number;
  readonly #hooks: StoreHooks;

  constructor(clock: () => number, hooks: StoreHooks) {
    this.#clock = clock;
    this.#hooks = hooks;
    this.inner = new MemoryStore({ now: clock });
  }

  #record(op: StoreOp["op"], key: string, wrote: boolean, amount?: number): void {
    this.log.push({ op, key, at: this.#clock(), flow: this.#hooks.flow(), wrote, ...(amount === undefined ? {} : { amount }) });
  }

  beginCommand(lost: LostMode): void {
    this.#lost = lost;
    this.#draw = lost.kind === "chance" ? seeded(lost.seed) : undefined;
    this.writes = 0;
  }

  /** Whether the write just counted lands and then answers as a lost reply would. */
  #doubles(op: keyof WorldStore["retriedBy"]): boolean {
    this.writes += 1;
    const lost = this.#lost;
    const yes = lost.kind === "every" || (lost.kind === "at" && lost.ordinals.includes(this.writes)) || (lost.kind === "chance" && (this.#draw?.() ?? 1) < 0.3);
    if (yes) {
      this.retried += 1;
      this.retriedBy[op] += 1;
      if (this.writes > 40) this.retriedLate += 1;
    }
    return yes;
  }

  async #twice<T>(op: "setIfAbsent" | "cas" | "delete", key: string, write: () => Promise<T>): Promise<T> {
    await this.#hooks.turn(`${op} ${key}`);
    if (this.#doubles(op)) {
      await write();
      // Another request may write between the first landing and the retry.
      await this.#hooks.turn(`retry ${op} ${key}`);
    }
    return write();
  }

  async incrWindow(key: string, windowSeconds: number, amount = 1): Promise<number> {
    await this.#hooks.turn(`incr ${key}`);
    const once = async (): Promise<number> => {
      const total = await this.inner.incrWindow(key, windowSeconds, amount);
      const at = this.#clock();
      if (total === amount) {
        this.windowStart.set(key, { at, index: this.log.length });
        this.expiry.set(key, at + windowSeconds * 1000);
        this.extra.delete(key);
      }
      this.#record("incr", key, true, amount);
      return total;
    };
    if (!this.#doubles("incr")) return once();
    await once();
    await this.#hooks.turn(`retry incr ${key}`);
    const total = await once();
    this.extra.set(key, (this.extra.get(key) ?? 0) + amount);
    return total;
  }

  /** What the counter at `key` holds without what doubled increments added: what the code meant it to hold. */
  async intended(key: string): Promise<bigint> {
    const raw = await this.inner.get(key);
    return raw === null ? 0n : BigInt(raw) - BigInt(this.extra.get(key) ?? 0);
  }

  setIfAbsent(key: string, value: string, ttlSeconds: number): Promise<boolean> {
    return this.#twice("setIfAbsent", key, async () => {
      const wrote = await this.inner.setIfAbsent(key, value, ttlSeconds);
      if (wrote) this.expiry.set(key, this.#clock() + ttlSeconds * 1000);
      this.#record("setIfAbsent", key, wrote);
      return wrote;
    });
  }

  async get(key: string): Promise<string | null> {
    await this.#hooks.turn(`get ${key}`);
    return this.inner.get(key);
  }

  compareAndSet(key: string, expected: string | null, next: string, ttlSeconds: number): Promise<boolean> {
    return this.#twice("cas", key, async () => {
      const wrote = await this.inner.compareAndSet(key, expected, next, ttlSeconds);
      if (wrote) this.expiry.set(key, this.#clock() + ttlSeconds * 1000);
      this.#record("cas", key, wrote);
      return wrote;
    });
  }

  delete(key: string): Promise<boolean> {
    return this.#twice("delete", key, async () => {
      const held = await this.inner.delete(key);
      this.expiry.delete(key);
      this.#record("delete", key, held);
      return held;
    });
  }

  /**
   * The SharedStore lock on the world's clock: a holder's lock runs out at its lifetime in world
   * time, and a waiter pauses LOCK_PAUSE_MS of world time between tries, so a lock can expire under
   * a running holder and another request can take it.
   */
  async withLock<T>(key: string, ttlSeconds: number, fn: () => Promise<T>, options?: LockOptions): Promise<T> {
    const lockKey = `lock:${key}`;
    const waitMs = options?.waitMs ?? 0;
    const token = randomUUID();
    const started = this.#clock();
    for (let tries = 0; ; tries++) {
      await this.#hooks.turn(`lock ${key}`);
      if (await this.inner.setIfAbsent(lockKey, token, ttlSeconds)) break;
      const waited = this.#clock() - started;
      if (waited >= waitMs) throw new LockBusy();
      if (tries === 0) this.lockWaits += 1;
      await this.#hooks.wait(Math.min(LOCK_PAUSE_MS, waitMs - waited));
    }
    const running = this.#holding.get(lockKey) ?? 0;
    if (running > 0) this.lockTakeovers += 1;
    this.#holding.set(lockKey, running + 1);
    try {
      return await fn();
    } finally {
      this.#holding.set(lockKey, (this.#holding.get(lockKey) ?? 1) - 1);
      await this.#hooks.turn(`release ${key}`);
      if ((await this.inner.get(lockKey)) === token) await this.inner.delete(lockKey);
    }
  }

  /** Milliseconds of life a key has left, as far as writes through here set it; undefined when unknown. */
  lifeLeft(key: string): number | undefined {
    const ends = this.expiry.get(key);
    return ends === undefined ? undefined : ends - this.#clock();
  }
}

/** A fake chair signature for a public board: the nonce it is signed at, whether it is genuine, and a salt that makes each action distinct. */
export function fakeSignature(nonce: bigint, valid: boolean, salt: number): Hex {
  const bytes = new Uint8Array(SIGNATURE_BYTES).fill(0xa7);
  new DataView(bytes.buffer).setBigUint64(0, nonce);
  bytes[8] = valid ? 1 : 0;
  new DataView(bytes.buffer).setUint32(9, salt);
  return bytesToHex(bytes);
}

function readFakeSignature(signature: Hex): { nonce: bigint; valid: boolean; salt: number } {
  const bytes = hexToBytes(signature);
  const view = new DataView(bytes.buffer, bytes.byteOffset);
  return { nonce: view.getBigUint64(0), valid: bytes[8] === 1, salt: view.getUint32(9) };
}

/** A public chair's relay body, as the app sends it: every integer a decimal string. */
export interface PublicBody {
  action: "rotate" | "post";
  boardId: string;
  params: Record<string, string>;
  deadline: string;
  signature: Hex;
}

/** A rotateEpoch on a public board, signed (or not, when `valid` is false) at `nonce`. The salt makes it a distinct action. */
export function rotateBody(world: World, boardId: bigint, nonce: bigint, salt: number, valid = true): PublicBody {
  const board = world.board(boardId);
  return {
    action: "rotate",
    boardId: boardId.toString(),
    params: { envelopeHash: keccak256(new TextEncoder().encode(`rotate ${salt}`)), envelopeSize: "1700", epochAfter: (board.epoch + 1n).toString() },
    deadline: (BigInt(Math.floor(world.now / 1000)) + 3_000n).toString(),
    signature: fakeSignature(nonce, valid, salt),
  };
}

/** A postDocument on a public board at `nonce`, for the document named `cipherHash`, stating `cipherSize`. */
export function postBody(world: World, boardId: bigint, nonce: bigint, salt: number, cipherHash: Hex, cipherSize: bigint): PublicBody {
  const board = world.board(boardId);
  return {
    action: "post",
    boardId: boardId.toString(),
    params: { docRef: keccak256(new TextEncoder().encode(`doc ${salt}`)), cipherHash, cipherSize: cipherSize.toString(), epoch: board.epoch.toString() },
    deadline: (BigInt(Math.floor(world.now / 1000)) + 3_000n).toString(),
    signature: fakeSignature(nonce, true, salt),
  };
}

/** A request from our own app, as the browser sends it. */
export function appRequest(path: string, body: unknown): Request {
  return new Request(`http://app.local${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-ava": "1", "sec-fetch-site": "same-origin" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

/** Revert data naming one of the registry's own errors, its arguments zeroed, as a node returns it. */
function revertWith(name: string): Hex | undefined {
  const entry = boardRegistryAbi.find((e) => e.type === "error" && e.name === name);
  if (entry === undefined || entry.type !== "error") return undefined;
  const args = entry.inputs.map((input) => {
    const type: string = input.type;
    return type === "address" ? ZERO : type === "bool" ? false : type === "bytes" ? "0x" : type.startsWith("bytes") ? `0x${"00".repeat(32)}` : 0n;
  });
  try {
    return encodeErrorResult({ abi: boardRegistryAbi, errorName: name, args } as never);
  } catch {
    return undefined;
  }
}

const utcDay = (ms: number): string => new Date(ms).toISOString().slice(0, 10);
const dayNoon = (day: string): number => Date.parse(`${day}T12:00:00Z`);
const lower = (address: string): string => address.toLowerCase();

/** One request in flight: a handler call, a pass, a sweep or a clock move, with its own identity while several overlap. */
export interface Flow {
  id: number;
  kind: string;
  guest?: string;
  startedAt: number;
  /** For a public relay: the UTC day it arrived, the day its post bytes are booked on. */
  requestDay?: string;
  /**
   * The UTC day of the last wall clock read this request made. The bot reads it once it holds the
   * lock for a post and books that post's bytes on its day.
   */
  wallDay?: string;
}

/** A turn count past which an overlap is taken to be stuck in a loop, so the run stops instead of hanging. */
const MAX_TURNS = 50_000;

/** The deterministic world one run drives: shared store, blob store, and a chain that can be slow, lossy and contradicted. */
export class World {
  readonly cast: Cast;
  readonly init: WorldInit;
  now = T0;
  mono = 0;
  readonly store: WorldStore;
  readonly blobs: MemoryBlobBackend;
  readonly boards = new Map<bigint, BoardModel>();
  readonly events: ChainEvent[] = [];
  readonly txs = new Map<string, ChainTx>();
  /** Our transactions waiting for a block, lowest nonce first. */
  readonly pool: ChainTx[] = [];
  confirmed = START_NONCE;
  win: { found: boolean; openedHeight: bigint; expiryHeight: bigint; maxTxs: bigint; maxValue: bigint; usedTxs: bigint; usedValue: bigint };
  readonly kem = new Map<string, KemMode>();
  /** Members whose KEM lookup fails for the current command only. */
  unreadable = new Set<string>();
  readonly background: (() => Promise<unknown>)[] = [];
  /** Every request so far, by command sequence number, with what it was and who it was for. */
  readonly ran: { seq: number; kind: string; guest?: string }[] = [];
  seq = 0;
  #kind = "setup";
  latency = 0;
  /** The request each async step belongs to, so overlapping requests keep their own identity. */
  readonly flows = new AsyncLocalStorage<Flow>();
  #flowIds = 0;
  /** Set while an overlap runs: every store call, chain call and wait is then a point where another request may run. */
  scheduler?: Scheduler;
  #turns = 0;
  #lastTurn?: number;
  /** How often an overlap switched from one request to another at a turn, across the run. */
  switches = 0;
  fates: TxFate[] = [];
  nativeFates: NativeFate[] = [];
  /** The command sequence at which the first foreign transaction used the relayer's nonce. */
  foreignSeq?: number;
  /** Our own sends and opens broadcast after a foreign transaction had already used the nonce. */
  readonly broadcastAfterForeign: ChainTx[] = [];
  /** Removals on the demo board, with the command and the request that relayed them. */
  readonly removals: { member: Hex; command: string; seq: number; flow?: number }[] = [];
  /** Sends handed over at a board nonce, or as a copy, while an earlier one there was still pending. */
  readonly doubleHanded: string[] = [];
  /** Removals that landed on a board of DEMO_GUEST_CAP minus DEMO_FREE_SEATS members or fewer, of a guest not due by the model. */
  readonly belowFloor: string[] = [];
  /** Removals that landed with the board at or under that floor, the case the floor check reads. */
  floorRemovals = 0;
  /** Demo packs handed to the node for an epoch that already had a pack, or that landed beside another of the bot's for one epoch. */
  readonly packTrouble: string[] = [];
  /** Whether an account's own seal keys opened an envelope a grant names, by account and envelope: what someone off the board would try. */
  readonly outsiderReads = new Map<string, boolean>();
  /** What each guest member made of each bot pack it was checked against, by pack, member and grants seen: whether it held the epoch's key, and what went wrong. */
  readonly packReads = new Map<string, { held: boolean; wrong?: string }>();
  /** When each member was admitted, by the world clock: the seed, or the start of the join whose add landed. */
  readonly admittedAt = new Map<string, number>();
  /** The last time each account's KEM record was anything but its own key, or its lookup failed. */
  readonly keyTrouble = new Map<string, number>();
  /** Documents the model uploaded: whether the bytes are the name's, their size, and when. */
  readonly docs = new Map<string, { honest: boolean; size: number; uploadedAt: number }>();
  /** Document tokens issued: who asked, on which day, the most bytes each lets in, the name it is for and when it ends. */
  readonly tokens: { clientIp: string; day: string; maxBytes: number; pathname: string; validUntil: number }[] = [];
  readonly #verified = new Map<string, boolean>();
  #natives = 0;
  #sends = 0;
  readonly relayChain: RelayChain;
  readonly demoChain: DemoChain;
  readonly logs: EnvelopeLogs;

  private constructor(cast: Cast, init: WorldInit) {
    this.cast = cast;
    this.init = init;
    this.store = new WorldStore(() => this.now, { turn: (label) => this.turn(label), wait: (ms) => this.sleep(ms), flow: () => this.flows.getStore()?.id });
    this.blobs = new MemoryBlobBackend(ORIGIN, { now: () => this.now });
    const opened = this.height() - 200n;
    this.win = { found: true, openedHeight: opened, expiryHeight: opened + BigInt(WINDOW.blocks), maxTxs: BigInt(WINDOW.maxTxs), maxValue: WINDOW.maxValue, usedTxs: 0n, usedValue: 0n };
    this.relayChain = this.#relayChain();
    this.demoChain = this.#demoChain();
    this.logs = this.#logs();
  }

  static async create(cast: Cast, init: WorldInit): Promise<World> {
    const world = new World(cast, init);
    await world.#seed();
    return world;
  }

  async #seed(): Promise<void> {
    const { cast, init } = this;
    const fillers = cast.fillers.slice(0, init.fillers);
    const members = [cast.chair, ...cast.seeded, ...fillers];
    let seed = cast.seedEnvelopes.get(init.fillers);
    if (seed === undefined) {
      const boardRef = bytesToHex(sha256(new TextEncoder().encode(`demo board ${init.fillers}`)));
      const envelope = sealEpochKey({ registry: REGISTRY_ADDRESS, boardRef, epoch: 3n, epochKey: newEpochKey(), recipients: members.map((m) => published(m.evm, m.seal.mlkemPublicKey)) });
      seed = { boardRef, envelope };
      cast.seedEnvelopes.set(init.fillers, seed);
    }
    const envelopeHash = bytesToHex(sha256(seed.envelope));
    const pathname = `envelope/${envelopeHash.slice(2)}`;
    await this.blobs.put(pathname, seed.envelope);
    this.blobs.uploadedAt.set(pathname, T0 - HOUR);
    this.boards.set(DEMO_BOARD, {
      id: DEMO_BOARD,
      chair: cast.chair.evm,
      boardRef: seed.boardRef,
      epoch: 3n,
      nonce: 11n,
      members: members.map((m) => m.evm),
      grants: [{ envelopeHash, envelopeSize: seed.envelope.length, mode: Mode.ROTATE, member: ZERO }],
      // The seed script's packs are not the bot's: no property reads their bytes.
      documents: init.seedPack ? [{ docRef: keccak256(new TextEncoder().encode("seed pack")), cipherHash: keccak256(new TextEncoder().encode("seed pack bytes")), cipherSize: 1_700n, epoch: 3n, bot: false }] : [],
    });
    this.events.push({ block: this.heightAt(T0 - HOUR), boardId: DEMO_BOARD, kind: "granted", envelopeHash, member: ZERO });
    for (const [i, id] of PUBLIC_BOARDS.entries()) {
      const chair = PUBLIC_CHAIRS[i === 2 ? 1 : 0];
      this.boards.set(id, { id, chair, boardRef: bytesToHex(sha256(new TextEncoder().encode(`public ${id}`))), epoch: 3n, nonce: 10n, members: [chair], grants: [], documents: [] });
    }
    for (const [i, f] of fillers.entries()) {
      const at = T0 - (i + 1) * init.fillerStepMinutes * 60_000;
      await this.store.inner.setIfAbsent(admittedKey(hexToBytes(f.evm)), String(at), 315_360_000);
      this.admittedAt.set(lower(f.evm), at);
    }
    await this.store.inner.setIfAbsent(nonceKey(RELAYER.evm), START_NONCE.toString(), 315_360_000);
    if (init.preSpend > 0) {
      const share = (ceiling: bigint) => BigInt(Math.floor(Number(ceiling) * init.preSpend));
      const chairs = share(ledgerFor("chairs", T0).ceiling);
      const demo = share(ledgerFor("demo", T0).ceiling);
      const chairA = share(ledgerFor("chair", T0, PUBLIC_CHAIRS[0]).ceiling);
      for (const [ledger, amount] of [
        [ledgerFor("total", T0), chairs + demo],
        [ledgerFor("chairs", T0), chairs],
        [ledgerFor("demo", T0), demo],
        [ledgerFor("chair", T0, PUBLIC_CHAIRS[0]), chairA < chairs ? chairA : chairs],
      ] as const) {
        if (amount > 0n) await this.store.inner.incrWindow(ledger.key, 2 * 86_400, Number(amount));
      }
    }
  }

  height(): bigint {
    return this.heightAt(this.now);
  }

  heightAt(ms: number): bigint {
    return H0 + BigInt(Math.floor((ms - T0) / BLOCK_MS));
  }

  blockTimeMs(block: bigint): number {
    return T0 + Number(block - H0) * BLOCK_MS;
  }

  /** Moves both clocks, and lets every transaction whose time has come reach its block. */
  advance(ms: number): void {
    if (ms <= 0) return;
    this.now += ms;
    this.mono += ms;
    this.drain();
  }

  clock = (): number => this.mono;
  /** The world time, noting its UTC day on the request that read it. */
  wallClock = (): number => {
    const flow = this.flows.getStore();
    if (flow !== undefined) flow.wallDay = utcDay(this.now);
    return this.now;
  };
  sleep = async (ms: number): Promise<void> => {
    await this.turn("sleep");
    this.advance(ms);
  };

  /** What kind of request the current step belongs to: its own flow's while requests overlap, else the command's. */
  get command(): string {
    return this.flows.getStore()?.kind ?? this.#kind;
  }

  flow(): Flow | undefined {
    return this.flows.getStore();
  }

  /** Runs `work` as one request with its own identity, recorded under the current command. */
  runFlow<T>(kind: string, guest: string | undefined, work: () => Promise<T>): Promise<T> {
    this.#flowIds += 1;
    const flow: Flow = { id: this.#flowIds, kind, guest, startedAt: this.now };
    this.ran.push({ seq: this.seq, kind, guest });
    return this.flows.run(flow, work);
  }

  /**
   * A point where another overlapping request may run: the scheduler decides which waiting step
   * goes next. Outside an overlap it does nothing, so a lone command runs as it always did.
   */
  async turn(label: string): Promise<void> {
    const s = this.scheduler;
    if (s === undefined) return;
    this.#turns += 1;
    if (this.#turns > MAX_TURNS) throw new Error(`An overlap took more than ${MAX_TURNS} turns, so some request is looping.`);
    const me = this.flows.getStore()?.id;
    await s.schedule(Promise.resolve(), `${me ?? "-"} ${label}`);
    if (this.#lastTurn !== undefined && me !== this.#lastTurn) this.switches += 1;
    this.#lastTurn = me;
  }

  /** One command starts: its name, its chain latency, the fates its sends meet, and which of its writes the store applies twice. */
  begin(kind: string, options: { latency?: number; fates?: readonly TxFate[]; nativeFates?: readonly NativeFate[]; lost?: LostMode; unreadable?: readonly Hex[] } = {}): void {
    this.seq += 1;
    this.#kind = kind;
    this.#turns = 0;
    this.#lastTurn = undefined;
    this.latency = options.latency ?? 0;
    this.fates = [...(options.fates ?? [])];
    this.nativeFates = [...(options.nativeFates ?? [])];
    this.unreadable = new Set((options.unreadable ?? []).map(lower));
    for (const id of this.unreadable) this.keyTrouble.set(id, this.now);
    this.store.beginCommand(options.lost ?? { kind: "none" });
  }

  end(): void {
    this.latency = 0;
    this.scheduler = undefined;
    this.unreadable = new Set();
    this.store.beginCommand({ kind: "none" });
  }

  async #lag(label: string): Promise<void> {
    await this.turn(label);
    if (this.latency > 0) this.advance(this.latency);
  }

  board(id: bigint): BoardModel {
    const board = this.boards.get(id);
    if (board === undefined) throw new Error(`The world has no board ${id}.`);
    return board;
  }

  isMember(boardId: bigint, account: string): boolean {
    return this.board(boardId).members.some((m) => lower(m) === lower(account));
  }

  status(hash: string): TxStatus {
    const tx = this.txs.get(hash);
    if (tx === undefined || tx.state === "unknown") return "unknown";
    return tx.state === "pending" ? "pending" : tx.state === "reverted" && tx.kind === "evm" ? "reverted" : "landed";
  }

  readWindow(): EvmWindow {
    const w = this.win;
    if (!w.found) {
      return { found: false, live: false, openedHeight: 0n, expiryHeight: 0n, maxTxs: 0n, usedTxs: 0n, maxValue: 0n, usedValue: 0n, remainingBlocks: 0n, remainingTxs: 0n, remainingValue: 0n, nativeOnly: false, allowedTargets: [] };
    }
    const h = this.height();
    const remainingBlocks = w.expiryHeight > h ? w.expiryHeight - h : 0n;
    return {
      found: true,
      live: remainingBlocks > 0n,
      openedHeight: w.openedHeight,
      expiryHeight: w.expiryHeight,
      maxTxs: w.maxTxs,
      usedTxs: w.usedTxs,
      maxValue: w.maxValue,
      usedValue: w.usedValue,
      remainingBlocks,
      remainingTxs: w.maxTxs - w.usedTxs,
      remainingValue: w.maxValue - w.usedValue,
      nativeOnly: false,
      allowedTargets: [REGISTRY_ADDRESS.toLowerCase()],
    };
  }

  /** The registry's answer to an action at this moment: what eth_call would say, and what landing it would do. */
  judge(data: Hex): { ok: true; apply: () => void } | { ok: false; error: string } {
    let decoded: { functionName: string; args: readonly unknown[] };
    try {
      decoded = decodeFunctionData({ abi: boardRegistryAbi, data }) as { functionName: string; args: readonly unknown[] };
    } catch {
      return { ok: false, error: "reverted" };
    }
    const args = decoded.args as readonly unknown[];
    const boardId = args[0] as bigint;
    const board = this.boards.get(boardId);
    if (board === undefined) return { ok: false, error: "UnknownBoard" };
    const deadline = args[args.length - 2] as bigint;
    const signature = args[args.length - 1] as Hex;
    if (deadline <= BigInt(Math.floor(this.now / 1000))) return { ok: false, error: "DeadlineExpired" };
    if (!this.#signedAt(board, decoded.functionName, args, signature, board.nonce)) return { ok: false, error: "BadSignature" };
    const grant = (envelopeHash: Hex, member: Hex): void => {
      this.events.push({ block: this.height(), boardId, kind: "granted", envelopeHash, member });
    };
    switch (decoded.functionName) {
      case "addMember": {
        const [, member, mode, envelopeHash, envelopeSize, epochAfter] = args as [bigint, Hex, number, Hex, number, bigint];
        if (this.isMember(boardId, member)) return { ok: false, error: "AlreadyMember" };
        if (epochAfter !== board.epoch + (mode === Mode.ROTATE ? 1n : 0n)) return { ok: false, error: "WrongEpoch" };
        return {
          ok: true,
          apply: () => {
            board.members.push(getAddress(member));
            board.nonce += 1n;
            board.grants.push({ envelopeHash, envelopeSize, mode, member: getAddress(member) });
            grant(envelopeHash, getAddress(member));
          },
        };
      }
      case "removeMember": {
        const [, member, envelopeHash, envelopeSize, epochAfter] = args as [bigint, Hex, Hex, number, bigint];
        if (!this.isMember(boardId, member)) return { ok: false, error: "NotMember" };
        if (lower(member) === lower(board.chair)) return { ok: false, error: "ChairCannotLeave" };
        if (epochAfter !== board.epoch + 1n) return { ok: false, error: "WrongEpoch" };
        return {
          ok: true,
          apply: () => {
            board.members = board.members.filter((m) => lower(m) !== lower(member));
            board.epoch = epochAfter;
            board.nonce += 1n;
            board.grants = [{ envelopeHash, envelopeSize, mode: Mode.ROTATE, member: ZERO }];
            grant(envelopeHash, ZERO);
          },
        };
      }
      case "rotateEpoch": {
        const [, envelopeHash, envelopeSize, epochAfter] = args as [bigint, Hex, number, bigint];
        if (epochAfter !== board.epoch + 1n) return { ok: false, error: "WrongEpoch" };
        return {
          ok: true,
          apply: () => {
            board.epoch = epochAfter;
            board.nonce += 1n;
            board.grants = [{ envelopeHash, envelopeSize, mode: Mode.ROTATE, member: ZERO }];
            grant(envelopeHash, ZERO);
          },
        };
      }
      case "postDocument": {
        const [, docRef, cipherHash, cipherSize, epoch] = args as [bigint, Hex, Hex, bigint, bigint];
        if (epoch !== board.epoch) return { ok: false, error: "WrongEpoch" };
        return {
          ok: true,
          apply: () => {
            const bot = boardId === DEMO_BOARD;
            if (bot && board.documents.some((d) => d.bot && d.epoch === epoch)) this.packTrouble.push(`a second pack of the bot's landed for epoch ${epoch} at command #${this.seq}`);
            board.nonce += 1n;
            board.documents.push({ docRef, cipherHash, cipherSize, epoch, bot });
            this.events.push({ block: this.height(), boardId, kind: "posted", cipherHash, cipherSize });
          },
        };
      }
      default:
        return { ok: false, error: "reverted" };
    }
  }

  /** Whether the action's signature is the chair's at `nonce`: a fake one on public boards, the bot's real ML-DSA one on the demo board. */
  #signedAt(board: BoardModel, functionName: string, args: readonly unknown[], signature: Hex, nonce: bigint): boolean {
    if (board.id !== DEMO_BOARD) {
      const fake = readFakeSignature(signature);
      return fake.valid && fake.nonce === nonce;
    }
    const cacheKey = `${keccak256(signature)}:${nonce}`;
    const known = this.#verified.get(cacheKey);
    if (known !== undefined) return known;
    let ok = false;
    try {
      const deadline = args[args.length - 2] as bigint;
      let paramsHash: Hex;
      let action: Action;
      if (functionName === "addMember") {
        const [, member, mode, envelopeHash, envelopeSize, epochAfter] = args as [bigint, Hex, Mode, Hex, number, bigint];
        paramsHash = paramsAdd({ member: getAddress(member), mode, envelopeHash, envelopeSize, epochAfter });
        action = Action.ADD;
      } else if (functionName === "removeMember") {
        const [, member, envelopeHash, envelopeSize, epochAfter] = args as [bigint, Hex, Hex, number, bigint];
        paramsHash = paramsRemove({ member: getAddress(member), envelopeHash, envelopeSize, epochAfter });
        action = Action.REMOVE;
      } else if (functionName === "postDocument") {
        const [, docRef, cipherHash, cipherSize, epoch] = args as [bigint, Hex, Hex, bigint, bigint];
        paramsHash = paramsPost({ docRef, cipherHash, cipherSize, epoch });
        action = Action.POST;
      } else {
        return false;
      }
      const message = actionMessage({ registry: REGISTRY_ADDRESS, action, boardId: board.id, paramsHash, nonce, deadline });
      ok = verifyAction(this.cast.chair.mldsa.publicKey, message, hexToBytes(signature));
    } catch {
      ok = false;
    }
    this.#verified.set(cacheKey, ok);
    return ok;
  }

  /** Lands every transaction at the head of the pool whose time has come, in nonce order. */
  drain(): void {
    for (;;) {
      const head = this.pool[0];
      if (head === undefined || head.landAt === undefined || head.landAt > this.now) return;
      this.#land(head, head.forceRevert);
    }
  }

  #land(tx: ChainTx, revert: boolean): void {
    const at = this.pool.indexOf(tx);
    if (at >= 0) this.pool.splice(at, 1);
    tx.landedAt = this.now;
    this.confirmed += 1n;
    const verdict = revert || tx.data === undefined ? undefined : this.judge(tx.data);
    if (verdict?.ok === true) {
      // A guest who signed its own leave goes whatever the board holds; the floor is the passes' rule.
      if (tx.boardId === DEMO_BOARD && tx.action === "remove" && tx.member !== undefined && tx.command !== "leave") this.#checkFloor(tx.member);
      verdict.apply();
      if (tx.boardId === DEMO_BOARD && tx.action === "add" && tx.member !== undefined) this.admittedAt.set(lower(tx.member), tx.flowStartedAt);
      tx.state = "landed";
    } else {
      tx.state = "reverted";
      tx.deadSeq = this.seq;
    }
    if (tx.gas !== undefined && tx.action !== undefined) {
      const used = (GAS_CEILING[tx.action as RelayAction] * 2n) / 3n;
      tx.fee = weiToUqorCeil(used * (BASE_FEE + TIP));
    }
  }

  /**
   * A removal about to land on a board already at the pass's floor must be of a guest due anyway, by
   * the model's own record: six hours since its admission, or a KEM record that went wrong since then.
   */
  #checkFloor(member: Hex): void {
    const board = this.board(DEMO_BOARD);
    const floor = DEMO_GUEST_CAP - DEMO_FREE_SEATS;
    if (board.members.length > floor) return;
    this.floorRemovals += 1;
    const id = lower(member);
    const since = this.admittedAt.get(id);
    const trouble = this.keyTrouble.get(id);
    const due = since === undefined || this.now - since >= DEMO_GUEST_TTL_SECONDS * 1000 || (trouble !== undefined && trouble >= since);
    if (!due) {
      this.belowFloor.push(`a removeMember of ${member} landed on a board of ${board.members.length} members, already at or under ${floor}, though it was admitted ${Math.round((this.now - (since ?? this.now)) / 60_000)} minutes ago with its own KEM key`);
    }
  }

  /** A pack is handed to the node only for an epoch with no document, and none of the bot's for it still pending. */
  #checkPackSend(board: BoardModel, epoch: bigint, record: ChainTx): void {
    const what = `${record.command} handed over a pack for epoch ${epoch} (command #${this.seq})`;
    const held = board.documents.find((d) => d.epoch === epoch);
    if (held !== undefined) this.packTrouble.push(`${what}, though that epoch already had ${held.bot ? "a pack of the bot's" : "the seed's pack"}`);
    const pending = [...this.txs.values()].find((t) => t.boardId === board.id && t.action === "post" && t.state === "pending" && t.data !== undefined && this.#postEpoch(t.data) === epoch);
    if (pending !== undefined) this.packTrouble.push(`${what} while ${pending.command}'s pack for it (command #${pending.seq}) was still pending`);
  }

  #postEpoch(data: Hex): bigint {
    return (decodeFunctionData({ abi: boardRegistryAbi, data }).args as readonly unknown[])[4] as bigint;
  }

  /** The QoreSeal keys of a member the cast knows: a guest or a filler. */
  sealOf(member: string): SealKeyPair | undefined {
    return [...this.cast.guests, ...this.cast.fillers].find((k) => lower(k.evm) === lower(member))?.seal;
  }

  /**
   * Whether an account's own seal keys open any envelope the demo board's current epoch grants: what
   * an account taken off the board would try with the keys it still holds. Each account and envelope
   * pair is tried once; an envelope the blob store no longer holds opens for nobody.
   */
  opensCurrentEpoch(member: Hex): boolean {
    const board = this.board(DEMO_BOARD);
    const seal = this.sealOf(member);
    if (seal === undefined) return false;
    for (const grant of board.grants) {
      const key = `${lower(member)}:${grant.envelopeHash}`;
      let opened = this.outsiderReads.get(key);
      if (opened === undefined) {
        const envelope = this.blobs.blobs.get(`envelope/${grant.envelopeHash.slice(2).toLowerCase()}`);
        if (envelope === undefined) continue;
        try {
          openEpochKey({ registry: REGISTRY_ADDRESS, boardRef: board.boardRef, epoch: board.epoch, envelope, expectedHash: grant.envelopeHash, expectedSize: grant.envelopeSize, sealKeys: seal });
          opened = true;
        } catch {
          opened = false;
        }
        this.outsiderReads.set(key, opened);
      }
      if (opened) return true;
    }
    return false;
  }

  /**
   * What a guest member makes of the bot's pack for the demo board's current epoch, opening it as a
   * member would: an envelope of the epoch's grants with its own seal keys, then the document the
   * post names, from the blob store. Undefined when it opens to `plain`, or when the member holds no
   * key for the epoch; otherwise what went wrong. Kept per pack, member and grant count, since the
   * pack's bytes never change and a member gains a grant only by joining.
   */
  async packRead(member: Hex, pack: DocumentModel, plain: Uint8Array): Promise<string | undefined> {
    const board = this.board(DEMO_BOARD);
    const key = `${pack.cipherHash}:${lower(member)}:${board.grants.length}`;
    const known = this.packReads.get(key);
    if (known !== undefined) return known.wrong;
    const seal = this.sealOf(member);
    let epochKey: Uint8Array | undefined;
    for (const grant of seal === undefined ? [] : board.grants) {
      const envelope = this.blobs.blobs.get(`envelope/${grant.envelopeHash.slice(2).toLowerCase()}`);
      if (envelope === undefined || seal === undefined) continue;
      try {
        epochKey = openEpochKey({ registry: REGISTRY_ADDRESS, boardRef: board.boardRef, epoch: board.epoch, envelope, expectedHash: grant.envelopeHash, expectedSize: grant.envelopeSize, sealKeys: seal });
        break;
      } catch {
        // Not sealed to this member; the next grant may be.
      }
    }
    let verdict: string | undefined;
    if (epochKey !== undefined) {
      const ciphertext = this.blobs.blobs.get(`document/${pack.cipherHash.slice(2).toLowerCase()}`);
      try {
        if (ciphertext === undefined) throw new Error("the blob store holds nothing under its name");
        const opened = await decryptDocument({ epochKey, registry: REGISTRY_ADDRESS, boardRef: board.boardRef, epoch: pack.epoch, docRef: pack.docRef, ciphertext, expectedHash: pack.cipherHash, expectedSize: pack.cipherSize });
        if (!Buffer.from(opened).equals(Buffer.from(plain))) verdict = `opens to ${opened.length} bytes that are not the pack text's ${plain.length}`;
      } catch (error) {
        verdict = `does not open: ${error instanceof Error ? error.message : String(error)}`;
      }
    }
    this.packReads.set(key, { held: epochKey !== undefined, ...(verdict === undefined ? {} : { wrong: verdict }) });
    return verdict;
  }

  /** Sets one account's KEM record, and remembers when it stopped being the account's own. */
  setKem(account: Hex, mode: KemMode): void {
    const id = lower(account);
    this.kem.set(id, mode);
    if (mode.kind !== "own") this.keyTrouble.set(id, this.now);
  }

  /** Drops the pool from the transaction at `from` on: none of them can land once a nonce below them is gone. */
  #drop(from: number): void {
    for (const tx of this.pool.splice(from)) {
      tx.state = "unknown";
      tx.deadSeq = this.seq;
    }
  }

  /** The chain mines, reverts or loses the oldest transaction waiting in the pool. */
  settleOldest(how: "mine" | "revert" | "lose"): void {
    const head = this.pool[0];
    if (head === undefined) return;
    if (how === "lose") this.#drop(0);
    else this.#land(head, how === "revert");
    this.drain();
  }

  /**
   * Someone else signs with the relayer's key at its next confirmed nonce, and it lands at once. Ours
   * waiting at that nonce, and every one after it, can then never land.
   */
  foreignTx(throughWindow: boolean): void {
    const nonce = this.confirmed;
    if (this.pool[0]?.nonce === nonce) this.#drop(0);
    const hash = bytesToHex(sha256(new TextEncoder().encode(`foreign ${this.seq} ${nonce}`)));
    this.txs.set(hash, {
      hash,
      kind: "evm",
      nonce,
      state: "landed",
      what: "foreign",
      seq: this.seq,
      command: this.command,
      at: this.now,
      flowStartedAt: this.now,
      logIndex: this.store.log.length,
      landedAt: this.now,
      receipt: "true",
      fee: 0n,
      days: [],
      forceRevert: false,
    });
    this.confirmed += 1n;
    this.foreignSeq ??= this.seq;
    const w = this.readWindow();
    if (throughWindow && w.live && w.remainingTxs > 0n) {
      this.win.usedTxs += 1n;
      this.win.usedValue += w.remainingValue < 1_000n ? w.remainingValue : 1_000n;
    }
  }

  /** The chair lands an action from its own account, outside the relay: what moves a board's nonce under a pending relay. */
  direct(data: Hex): boolean {
    const verdict = this.judge(data);
    if (verdict.ok) verdict.apply();
    return verdict.ok;
  }

  #pendingNonce(): bigint {
    return this.confirmed + BigInt(this.pool.length);
  }

  /** The UTC days from the current request's start to now, by the world clock. */
  #days(): string[] {
    const first = utcDay(this.flow()?.startedAt ?? this.now);
    const last = utcDay(this.now);
    return first === last ? [last] : [first, last];
  }

  /**
   * The board nonce the action is signed at: a public board's fake signature states it, and the
   * bot's real one is tried at the board's nonce and the few before it, since the bot signs at the
   * nonce it read.
   */
  #signedNonceOf(board: BoardModel, functionName: string, args: readonly unknown[]): bigint | undefined {
    const signature = args[args.length - 1] as Hex;
    if (board.id !== DEMO_BOARD) return readFakeSignature(signature).nonce;
    for (let back = 0n; back <= 4n && back <= board.nonce; back++) {
      if (this.#signedAt(board, functionName, args, signature, board.nonce - back)) return board.nonce - back;
    }
    return undefined;
  }

  #send = async (tx: EvmSend, _deadline: Deadline, beforeBroadcast?: BeforeBroadcast): Promise<Hex> => {
    await this.#lag("send");
    this.#sends += 1;
    const nonce = this.#pendingNonce();
    const hash = bytesToHex(sha256(new TextEncoder().encode(`send ${this.#sends} ${nonce} ${tx.data}`)));
    try {
      await beforeBroadcast?.({ kind: "evm", nonce, hash });
    } catch {
      throw new NotBroadcast("not recorded");
    }
    const fate = this.fates.shift() ?? "land";
    const { functionName, args } = decodeFunctionData({ abi: boardRegistryAbi, data: tx.data });
    const boardId = (args as readonly unknown[])[0] as bigint;
    const board = this.board(boardId);
    const action = ACTION_OF[functionName];
    const worst = evmWindowCost({ gas: tx.gas, maxFeePerGas: tx.maxFeePerGas });
    const scope = boardId === DEMO_BOARD ? "demo" : "public";
    const signedNonce = this.#signedNonceOf(board, functionName, args as readonly unknown[]);
    const record: ChainTx = {
      hash,
      kind: "evm",
      nonce,
      state: "pending",
      what: "send",
      seq: this.seq,
      command: this.command,
      at: this.now,
      flow: this.flow()?.id,
      flowStartedAt: this.flow()?.startedAt ?? this.now,
      logIndex: this.store.log.length,
      data: tx.data,
      gas: tx.gas,
      maxFeePerGas: tx.maxFeePerGas,
      receipt: fate === "noReceipt" ? "never" : fate === "lieReceipt" ? "lie" : "true",
      fee: 0n,
      days: this.#days(),
      signedNonce,
      forceRevert: fate === "revert",
      scope,
      boardId,
      action,
      chair: board.chair,
      requestDay: this.flow()?.requestDay ?? (scope === "demo" ? this.flow()?.wallDay : undefined),
    };
    if (functionName === "addMember" || functionName === "removeMember") record.member = getAddress((args as readonly unknown[])[1] as Hex);
    if (functionName === "postDocument") {
      record.cipherHash = (args as readonly unknown[])[2] as Hex;
      record.cipherSize = (args as readonly unknown[])[3] as bigint;
      if (boardId === DEMO_BOARD) this.#checkPackSend(board, (args as readonly unknown[])[4] as bigint, record);
    }
    const earlier = [...this.txs.values()].find((t) => t.what === "send" && t.boardId === boardId && signedNonce !== undefined && t.signedNonce === signedNonce && t.state === "pending");
    if (earlier !== undefined) {
      const how = earlier.data === tx.data ? "a copy of" : "a different action from";
      this.doubleHanded.push(`board ${boardId} nonce ${signedNonce}: ${record.command} handed over ${how} ${earlier.command}'s ${earlier.hash.slice(0, 12)} (command #${earlier.seq}) while that one was still pending`);
    }
    this.txs.set(hash, record);
    if (this.foreignSeq !== undefined) this.broadcastAfterForeign.push(record);
    if (functionName === "removeMember" && boardId === DEMO_BOARD && record.member !== undefined) this.removals.push({ member: record.member, command: this.command, seq: this.seq, flow: this.flow()?.id });
    const w = this.readWindow();
    if (fate === "refuse" || !w.live || w.remainingTxs <= 0n || w.remainingValue < worst) {
      record.state = "unknown";
      record.deadSeq = this.seq;
      throw new Error(`EVM transaction ${hash} was refused and is not on chain.`);
    }
    this.win.usedTxs += 1n;
    this.win.usedValue += worst;
    record.landAt = fate === "pending" ? undefined : fate === "slow" || fate === "lostReply" ? this.now + SLOW_LAND_MS : this.now;
    this.pool.push(record);
    this.drain();
    if (fate === "lostReply") throw new Error("The node's answer was lost.");
    return hash;
  };

  #native = async (what: "open" | "close", beforeBroadcast?: BeforeBroadcast, request?: WindowRequest): Promise<{ hash: string }> => {
    await this.#lag(what);
    this.#natives += 1;
    const nonce = this.#pendingNonce();
    const hash = bytesToHex(sha256(new TextEncoder().encode(`native ${this.#natives} ${nonce}`)))
      .slice(2)
      .toUpperCase();
    try {
      await beforeBroadcast?.({ kind: "native", nonce, hash });
    } catch {
      throw new NotBroadcast("not recorded");
    }
    const fate = this.nativeFates.shift() ?? "commit";
    const fee = what === "open" ? WINDOW_OPEN_FEE_UQOR : WINDOW_CLOSE_FEE_UQOR;
    const record: ChainTx = {
      hash,
      kind: "native",
      nonce,
      state: "pending",
      what,
      seq: this.seq,
      command: this.command,
      at: this.now,
      flow: this.flow()?.id,
      flowStartedAt: this.flow()?.startedAt ?? this.now,
      logIndex: this.store.log.length,
      receipt: "true",
      fee: 0n,
      days: this.#days(),
      forceRevert: false,
    };
    this.txs.set(hash, record);
    if (what === "open" && this.foreignSeq !== undefined) this.broadcastAfterForeign.push(record);
    if (fate === "refuse") {
      record.state = "unknown";
      record.deadSeq = this.seq;
      throw new RefusedBeforeInclusion(13, "sdk");
    }
    // A later sequence cannot commit ahead of an earlier one, so whatever of ours waits lands first.
    while (this.pool[0] !== undefined) this.#land(this.pool[0], this.pool[0].forceRevert);
    this.confirmed += 1n;
    record.state = "landed";
    record.landedAt = this.now;
    record.fee = fee;
    if (what === "open" && request !== undefined) {
      const h = this.height();
      this.win = { found: true, openedHeight: h, expiryHeight: h + BigInt(request.blocks), maxTxs: BigInt(request.maxTxs), maxValue: request.maxValue, usedTxs: 0n, usedValue: 0n };
    }
    if (what === "close") this.win = { ...this.win, found: false };
    return { hash };
  };

  #relayChain(): RelayChain {
    return {
      readWindow: async () => {
        await this.#lag("readWindow");
        return this.readWindow();
      },
      openWindow: (request, _deadline, beforeBroadcast) => this.#native("open", beforeBroadcast, request),
      closeWindow: (_deadline, beforeBroadcast) => this.#native("close", beforeBroadcast),
      call: async (req: TxRequest): Promise<CallOutcome> => {
        await this.#lag("call");
        if (req.data.startsWith(GET_BOARD)) {
          const board = this.boards.get(BigInt(`0x${req.data.slice(10)}`));
          if (board === undefined) return { ok: false, revertData: revertWith("UnknownBoard") };
          const result = { chair: board.chair, boardRef: board.boardRef, epoch: board.epoch, nonce: board.nonce, memberCount: board.members.length, documentCount: board.documents.length };
          return { ok: true, data: encodeFunctionResult({ abi: boardRegistryAbi, functionName: "getBoard", result }) };
        }
        if (req.data.startsWith(CREATE_NONCES)) return { ok: true, data: encodeFunctionResult({ abi: boardRegistryAbi, functionName: "createNonces", result: 0n }) };
        const verdict = this.judge(req.data);
        if (verdict.ok) return { ok: true, data: "0x" };
        return { ok: false, revertData: revertWith(verdict.error) };
      },
      estimateGas: async (req) => {
        await this.#lag("estimateGas");
        const { functionName } = decodeFunctionData({ abi: boardRegistryAbi, data: req.data });
        const action = ACTION_OF[functionName];
        if (action === undefined) throw new Error("No such registry action.");
        return (GAS_CEILING[action] * 2n) / 3n;
      },
      feeQuote: async () => {
        await this.#lag("feeQuote");
        return { baseFeePerGas: BASE_FEE, maxPriorityFeePerGas: TIP };
      },
      send: this.#send,
      nonce: async () => {
        await this.#lag("nonce");
        return this.#pendingNonce();
      },
      txStatus: async (_kind, hash) => {
        await this.#lag("txStatus");
        return this.status(hash);
      },
      registryCodeHash: async () => REGISTRY_CODE_KECCAK,
      receipt: async (hash: Hex, deadline: Deadline): Promise<ReceiptFee | undefined> => {
        const tx = this.txs.get(hash);
        if (tx === undefined) return undefined;
        await this.#waitFor(tx, leftMs(deadline));
        if (tx.state !== "landed" && tx.state !== "reverted") return undefined;
        if (tx.receipt === "never") return undefined;
        const used = ((tx.gas ?? 0n) * 2n) / 3n;
        if (tx.receipt === "lie") return { gasUsed: (tx.gas ?? 0n) + 1n, effectiveGasPrice: BASE_FEE + TIP };
        return { gasUsed: used, effectiveGasPrice: BASE_FEE + TIP };
      },
    };
  }

  /**
   * A receipt wait: the clock runs until the transaction lands, or for the whole wait when it will
   * not. While requests overlap it runs one block at a time, so the others move on during the wait.
   */
  async #waitFor(tx: ChainTx, waitMs: number): Promise<void> {
    await this.turn("receipt");
    if (tx.state !== "pending") return;
    const wait = Math.max(0, Math.floor(waitMs));
    if (this.scheduler === undefined) {
      if (tx.landAt !== undefined && tx.landAt - this.now <= wait) this.advance(Math.max(0, tx.landAt - this.now));
      else this.advance(wait);
      return;
    }
    const ends = this.now + wait;
    while (tx.state === "pending" && this.now < ends) {
      const next = tx.landAt !== undefined && tx.landAt > this.now ? Math.min(tx.landAt - this.now, BLOCK_MS) : BLOCK_MS;
      this.advance(Math.min(next, ends - this.now));
      if (tx.state === "pending" && this.now < ends) await this.turn("receipt wait");
    }
  }

  #demoChain(): DemoChain {
    const proven = (who: Identity): KeyStatus => ({ registered: true, algorithmId: 1, pubkey: who.mldsa.publicKey, possessionProven: true });
    const known = [this.cast.chair, ...this.cast.seeded, ...this.cast.guests, ...this.cast.early];
    return {
      board: async (boardId): Promise<BoardSnapshot> => {
        await this.#lag("board");
        const board = this.board(boardId);
        return {
          boardId,
          blockNumber: this.height(),
          blockTimestamp: BigInt(Math.floor(this.now / 1000)),
          chair: board.chair,
          boardRef: board.boardRef,
          epoch: board.epoch,
          nonce: board.nonce,
          members: [...board.members],
          grants: board.grants.map((g) => ({ ...g })),
          documentCount: board.documents.length,
          latestDocumentEpoch: board.documents.at(-1)?.epoch,
        };
      },
      keyStatus: async (account) => {
        await this.#lag("keyStatus");
        const who = known.find((k) => lower(k.evm) === lower(account));
        return who === undefined ? { registered: false, algorithmId: 0, pubkey: new Uint8Array(), possessionProven: false } : proven(who);
      },
      kemKey: async (account) => this.kemKey(account),
      receipt: async (hash, timeoutMs) => {
        const tx = this.txs.get(hash);
        if (tx === undefined) return undefined;
        await this.#waitFor(tx, timeoutMs);
        if (tx.receipt === "never") return undefined;
        return tx.state === "landed" ? "success" : tx.state === "reverted" ? "reverted" : undefined;
      },
      grantTimes: async (boardId, members) => {
        await this.#lag("grantTimes");
        const named = this.events.filter((e) => e.boardId === boardId && e.kind === "granted");
        const oldest = named.reduce((low, e) => (e.block < low ? e.block : low), this.height());
        return members.map((m) => {
          const latest = named.filter((e) => e.member !== undefined && lower(e.member) === lower(m)).reduce<bigint | undefined>((high, e) => (high === undefined || e.block > high ? e.block : high), undefined);
          return BigInt(Math.floor(this.blockTimeMs(latest ?? oldest) / 1000));
        });
      },
    };
  }

  /** qor_getKEMKey as the chain answers it now: a member's own key, none, a copy of another's, garbage, or a failed read. */
  async kemKey(account: Hex): Promise<KemRecipient> {
    await this.#lag("kemKey");
    const id = lower(account);
    if (this.unreadable.has(id)) throw new Error("The KEM lookup timed out.");
    const mode = this.kem.get(id) ?? { kind: "own" };
    const own = (address: string): Uint8Array | undefined =>
      [this.cast.chair, ...this.cast.seeded, ...this.cast.guests, ...this.cast.fillers].find((k) => lower(k.evm) === lower(address))?.seal.mlkemPublicKey;
    switch (mode.kind) {
      case "none":
        throw new KemKeyUnavailable("NOT_FOUND", "no key registered");
      case "unreadable":
        throw new Error("The KEM lookup failed.");
      case "invalid":
        throw new KemKeyUnavailable("INVALID_KEY", "not an ML-KEM key");
      case "copy": {
        const key = own(mode.from);
        if (key === undefined) throw new KemKeyUnavailable("NOT_FOUND", "no key registered");
        return published(account, key);
      }
      case "own": {
        const key = own(account);
        if (key === undefined) throw new KemKeyUnavailable("NOT_FOUND", "no key registered");
        return published(account, key);
      }
    }
  }

  relayLimits(): RelayLimits {
    return this.init.tightLimits ? TIGHT_RELAY_LIMITS : RELAY_LIMITS;
  }

  demoLimits(): DemoLimits {
    return this.init.tightLimits ? TIGHT_DEMO_LIMITS : { join: DEMO_JOIN_LIMITS, challenge: DEMO_CHALLENGE_LIMITS };
  }

  relayContext(clientIp: string): RelayContext {
    return { clientIp, now: this.now, store: this.store, relayer: RELAYER, chain: this.relayChain, limits: this.relayLimits(), sleep: this.sleep, clock: this.clock };
  }

  sweepContext(): DemoSweepContext {
    return {
      now: this.now,
      store: this.store,
      env: { DEMO_BOARD_ID: DEMO_BOARD, DEMO_SEEDED: this.cast.seeded.map((s) => s.evm), DEMO_CHAIR_MNEMONIC: this.cast.chairPhrase, BLOB_ORIGIN: ORIGIN },
      chain: this.demoChain,
      blobs: this.blobs,
      relayer: RELAYER,
      relayChain: this.relayChain,
      clock: this.clock,
      sleep: this.sleep,
      wallClock: this.wallClock,
    };
  }

  demoContext(clientIp: string): DemoContext {
    return { ...this.sweepContext(), clientIp, limits: this.demoLimits(), background: (work) => void this.background.push(work) };
  }

  documentContext(clientIp: string): DocumentContext {
    return {
      clientIp,
      now: this.now,
      store: this.store,
      blobs: this.blobs,
      env: { BLOB_ORIGIN: ORIGIN, BLOB_READ_WRITE_TOKEN: FAKE_STORE_CREDENTIAL },
      buildToken: async (options) => {
        this.tokens.push({
          clientIp,
          day: utcDay(this.now),
          maxBytes: options.maximumSizeInBytes ?? Number.POSITIVE_INFINITY,
          pathname: options.pathname,
          validUntil: options.validUntil ?? this.now,
        });
        return "vercel_blob_client_world_token";
      },
    };
  }

  #logs(): EnvelopeLogs {
    return {
      // The block now being built still takes events, so a scan only ever sees blocks that are done.
      latestBlock: async () => this.height() - 1n,
      envelopeHashes: async (fromBlock, toBlock) => this.events.filter((e) => e.kind === "granted" && e.block >= fromBlock && e.block <= toBlock).map((e) => e.envelopeHash as Hex),
      documentPosts: async (fromBlock, toBlock) =>
        this.events.filter((e) => e.kind === "posted" && e.block >= fromBlock && e.block <= toBlock).map((e) => ({ cipherHash: e.cipherHash as Hex, cipherSize: e.cipherSize as bigint })),
      blockTime: async (block) => this.blockTimeMs(block),
    };
  }
}

export { utcDay, dayNoon };
