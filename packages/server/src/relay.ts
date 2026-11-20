import { randomUUID } from "node:crypto";
import { evmWindowCost, weiToUqorCeil } from "@qorechain/evm";
import { accountBytes, toHex } from "@ava/core";
import { bytesToHex, decodeErrorResult, decodeFunctionResult, encodeFunctionData, keccak256, type Hex } from "viem";
import { z } from "zod";
import { boardRegistryAbi } from "./abi/boardRegistry.ts";
import type { RelayerAddress } from "./chain/account.ts";
import { OutOfTime, elapsedMs, narrowed, startDeadline, within, type Deadline } from "./chain/deadline.ts";
import { NotBroadcast } from "./chain/evm.ts";
import type { BeforeBroadcast, CallOutcome, FeeQuote, ReceiptFee, RelayChain, TxStatus } from "./chain/types.ts";
import {
  DEMO_RELAYS_PER_HOUR,
  GAS_CEILING,
  LOCK_TTL_SECONDS,
  MAX_FEE_PER_GAS,
  PER_CHAIR_DAILY_POST_BYTES,
  RECEIPT_WAIT_MS,
  REGISTRY_ADDRESS,
  REGISTRY_CODE_KECCAK,
  RELAY_BODY_CAP,
  RELAY_DEADLINE_MS,
  RELAY_LIMITS,
  SEND_CUTOFF_MS,
  SEND_LOCK_WAIT_MS,
  type RelayAction,
} from "./config.ts";
import { verifiedSize } from "./docupload.ts";
import { BodyTimeout, declaredLength, json, readBody as readBodyBytes, refuse, refuseCrossSite, TooLarge, type HandlerContext } from "./http.ts";
import { logEvent } from "./log.ts";
import { countClient } from "./ratelimit.ts";
import { accountBytesStrict } from "./requestAddress.ts";
import { LockBusy, claimOnce, type SharedStore } from "./store.ts";
import {
  DailyCeilingReached,
  RelayerHalted,
  WindowUnavailable,
  ensureWindow,
  guardSend,
  isHalted,
  ledgerFor,
  recordWindowSend,
  releaseSpend,
  reserveOn,
  settleSpend,
  type Ledger,
  type Reservation,
  type SendGuard,
  type WindowDeps,
  type WindowState,
} from "./window.ts";

export interface RelayLimits {
  /** Requests per IP; an IPv6 /48 shares 4 times this (countClient). */
  perIp: number;
  perChair: number;
  perBoard: number;
  /** Public actions whose pre-flight passed again under the send lock, across every chair and board. */
  total: number;
  /** Requests whose pre-flight failed, across every IP. */
  rejected: number;
  windowSeconds: number;
}

export type RelayContext = HandlerContext & {
  /** The relayer's public addresses. Its keys live only inside `chain`. */
  relayer: RelayerAddress;
  chain: RelayChain;
  /** Overrides RELAY_LIMITS. */
  limits?: RelayLimits;
  /** The pause after a window opens. Tests pass one that moves their clock instead of waiting. */
  sleep?: (ms: number) => Promise<void>;
  /** A monotonic clock in milliseconds for the time budget; the process's own by default. */
  clock?: () => number;
  /**
   * "demo" for the demo bot's own relays, set only by server code and never from a request field
   * (threat model C41): such a relay skips the per-IP, per-board, per-chair and valid-total
   * counters, because the bot reserves its hourly room before each relay with reserveDemoRelays; it
   * books on the demo bot's daily share instead of the chairs' share, and has no per-chair daily
   * cap. Absent for every public relay.
   */
  scope?: "demo";
  /**
   * Set only by server code for a relay it makes itself (the demo bot's addMember), never from a
   * request field. Runs once the relayer's transaction is signed, after this relay's own marks name
   * its hash and before the broadcast, so a record the caller keeps names the transaction before the
   * chain can see it (threat model C34). If it throws, nothing is broadcast and the relay answers 502
   * chain_unreachable.
   */
  onSigned?: (txHash: Hex) => Promise<void>;
};

export const SEND_LOCK = "relayer:send";
const REJECTED_KEY = "rate:relay:rejected";
const VALID_KEY = "rate:relay:valid";

const DECIMAL = /^(0|[1-9][0-9]{0,77})$/;
const MAX_UINT = { 8: 0xffn, 32: 0xffff_ffffn, 64: 0xffff_ffff_ffff_ffffn, 256: (1n << 256n) - 1n } as const;
const SIGNATURE_HEX = /^0x[0-9a-fA-F]{9254}$/;

/** An unsigned integer as a canonical decimal string (no sign, no leading zeros), within its Solidity type. */
const uint = (bits: keyof typeof MAX_UINT, min = 0n) =>
  z
    .string()
    .regex(DECIMAL)
    .transform((s) => BigInt(s))
    .refine((n) => n >= min && n <= MAX_UINT[bits]);

const bytes32 = z
  .string()
  .regex(/^0x[0-9a-fA-F]{64}$/)
  .transform((s) => s.toLowerCase() as Hex);

/** A 0x address in exact EIP-55 form, decoded to its 20 bytes by the strict shared codec (threat model C16). */
const address = z
  .string()
  .max(42)
  .transform((s, ctx) => {
    if (s.startsWith("0x")) {
      try {
        return toHex(accountBytesStrict(s));
      } catch {
        // Falls through to the issue below.
      }
    }
    ctx.addIssue({ code: "custom", message: "not a 0x address" });
    return z.NEVER;
  });

/** Exactly 4,627 bytes: one ML-DSA-87 signature. */
const signature = z
  .string()
  .regex(SIGNATURE_HEX)
  .transform((s) => s.toLowerCase() as Hex);

const common = { deadline: uint(64), signature };
const boardId = uint(256, 1n);

/**
 * The relay body. Unknown top-level fields, such as a target, a gas limit or a value, are dropped
 * and never read: the relayer builds the whole transaction itself. Inside `params` only the fields
 * of that action (docs/spec/actions.md) are accepted.
 */
const relayBody = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("create"),
    boardId: z.never().optional(),
    params: z.strictObject({ chair: address, boardRef: bytes32, envelopeHash: bytes32, envelopeSize: uint(32) }),
    ...common,
  }),
  z.object({
    action: z.literal("add"),
    boardId,
    params: z.strictObject({ member: address, mode: uint(8), envelopeHash: bytes32, envelopeSize: uint(32), epochAfter: uint(64) }),
    ...common,
  }),
  z.object({
    action: z.literal("remove"),
    boardId,
    params: z.strictObject({ member: address, envelopeHash: bytes32, envelopeSize: uint(32), epochAfter: uint(64) }),
    ...common,
  }),
  z.object({
    action: z.literal("rotate"),
    boardId,
    params: z.strictObject({ envelopeHash: bytes32, envelopeSize: uint(32), epochAfter: uint(64) }),
    ...common,
  }),
  z.object({
    action: z.literal("post"),
    boardId,
    params: z.strictObject({ docRef: bytes32, cipherHash: bytes32, cipherSize: uint(64), epoch: uint(64) }),
    ...common,
  }),
  z.object({
    action: z.literal("transfer"),
    boardId,
    params: z.strictObject({ newChair: address }),
    ...common,
  }),
]);

type RelayBody = z.infer<typeof relayBody>;

interface Built {
  action: RelayAction;
  data: Hex;
  /** The signed deadline in unix seconds: until then the registry may take these exact bytes. */
  deadline: bigint;
  /** Set for every action but create. */
  boardId?: bigint;
  /** Set for create only: the chair named in the signed parameters. */
  chair?: Hex;
  /** Set for post only: the size the chair signed for the document the post keeps for good. */
  cipherSize?: bigint;
  /** Set for post only: the SHA-256 the chair signed as the document's name. */
  cipherHash?: Hex;
  /**
   * Never set by buildCalldata. Set on a post only once the document's verified size has been found
   * equal to cipherSize (documentKept): the bytes the post bytes budget books.
   */
  keptBytes?: bigint;
}

/**
 * The calldata, built by the server from the typed fields and the generated ABI (threat model C24),
 * with what the relay checks before sending it: the board, the chair named by a create, and for a
 * post the signed cipherHash and cipherSize. keptBytes is never set here.
 */
export function buildCalldata(b: RelayBody): Built {
  const abi = boardRegistryAbi;
  switch (b.action) {
    case "create": {
      const p = b.params;
      const data = encodeFunctionData({ abi, functionName: "createBoard", args: [p.chair, p.boardRef, p.envelopeHash, Number(p.envelopeSize), b.deadline, b.signature] });
      return { deadline: b.deadline, action: "create", data, chair: p.chair };
    }
    case "add": {
      const p = b.params;
      const args = [b.boardId, p.member, Number(p.mode), p.envelopeHash, Number(p.envelopeSize), p.epochAfter, b.deadline, b.signature] as const;
      return { deadline: b.deadline, action: "add", data: encodeFunctionData({ abi, functionName: "addMember", args }), boardId: b.boardId };
    }
    case "remove": {
      const p = b.params;
      const args = [b.boardId, p.member, p.envelopeHash, Number(p.envelopeSize), p.epochAfter, b.deadline, b.signature] as const;
      return { deadline: b.deadline, action: "remove", data: encodeFunctionData({ abi, functionName: "removeMember", args }), boardId: b.boardId };
    }
    case "rotate": {
      const p = b.params;
      const args = [b.boardId, p.envelopeHash, Number(p.envelopeSize), p.epochAfter, b.deadline, b.signature] as const;
      return { deadline: b.deadline, action: "rotate", data: encodeFunctionData({ abi, functionName: "rotateEpoch", args }), boardId: b.boardId };
    }
    case "post": {
      const p = b.params;
      const args = [b.boardId, p.docRef, p.cipherHash, p.cipherSize, p.epoch, b.deadline, b.signature] as const;
      return { deadline: b.deadline, action: "post", data: encodeFunctionData({ abi, functionName: "postDocument", args }), boardId: b.boardId, cipherSize: p.cipherSize, cipherHash: p.cipherHash };
    }
    case "transfer": {
      const args = [b.boardId, b.params.newChair, b.deadline, b.signature] as const;
      return { deadline: b.deadline, action: "transfer", data: encodeFunctionData({ abi, functionName: "transferChair", args }), boardId: b.boardId };
    }
  }
}

const REGISTRY_ERRORS: ReadonlySet<string> = new Set(boardRegistryAbi.flatMap((entry) => (entry.type === "error" ? [entry.name] : [])));

/**
 * The registry's custom error name for a revert, or "reverted". Only names the registry's own ABI
 * declares can come out, so nothing the chain or a caller wrote is ever echoed.
 */
export function revertName(data: Hex | undefined): string {
  if (data === undefined || data === "0x") return "reverted";
  try {
    const { errorName } = decodeErrorResult({ abi: boardRegistryAbi, data });
    return REGISTRY_ERRORS.has(errorName) ? errorName : "reverted";
  } catch {
    return "reverted";
  }
}

/**
 * EIP-1559 fees for one send: a fee cap of twice the base fee plus the tip, held at MAX_FEE_PER_GAS,
 * or undefined when even the base fee plus the tip would not fit under that ceiling.
 */
export function feeCaps(quote: FeeQuote): { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } | undefined {
  const { baseFeePerGas, maxPriorityFeePerGas } = quote;
  if (baseFeePerGas <= 0n || maxPriorityFeePerGas < 0n) return undefined;
  const wanted = baseFeePerGas * 2n + maxPriorityFeePerGas;
  const maxFeePerGas = wanted < MAX_FEE_PER_GAS ? wanted : MAX_FEE_PER_GAS;
  if (baseFeePerGas + maxPriorityFeePerGas > maxFeePerGas) return undefined;
  return { maxFeePerGas, maxPriorityFeePerGas };
}

type Fields = Record<string, string | number | boolean>;

function refusal(status: number, reason: string, fields: Fields = {}, headers: Record<string, string> = {}): Response {
  logEvent("relay_refused", { reason, status, ...fields });
  return refuse(status, reason, headers);
}

/** Counts one request under `key` in shared state. Fails closed: a store error counts as over. */
async function under(ctx: RelayContext, key: string, max: number, windowSeconds: number): Promise<boolean> {
  try {
    return (await ctx.store.incrWindow(key, windowSeconds)) <= max;
  } catch {
    return false;
  }
}

/**
 * Whether the counter under `key` already holds `max`, read without counting, so a relay that
 * would be refused there is refused before it waits for the send lock. Fails closed: a store
 * error or a value that is not a count reads as full.
 */
async function atLimit(ctx: RelayContext, key: string, max: number): Promise<boolean> {
  try {
    const raw = await ctx.store.get(key);
    if (raw === null) return false;
    const count = Number(raw);
    return !Number.isSafeInteger(count) || count >= max;
  } catch {
    return true;
  }
}

/** The 20 bytes as lowercase hex, so one account always counts under one key whatever form named it. */
const accountKey = (account: string): string => bytesToHex(accountBytes(account));

interface HourlyCounter {
  key: string;
  max: number;
  limit: "per_board" | "per_chair" | "total";
}

/**
 * The hourly counters a public relay takes, most specific first, so a board or a chair at its own
 * limit is refused before everyone's valid total moves: the board's (every action but create),
 * the acting chair's, then the valid total.
 */
function hourlyCounters(built: Built, chair: Hex, limits: RelayLimits): HourlyCounter[] {
  return [
    ...(built.boardId === undefined ? [] : [{ key: `rate:relay:board:${built.boardId}`, max: limits.perBoard, limit: "per_board" } as const]),
    { key: `rate:relay:chair:${accountKey(chair)}`, max: limits.perChair, limit: "per_chair" },
    { key: VALID_KEY, max: limits.total, limit: "total" },
  ];
}

/** The mark that one action, named by its exact calldata, has taken the hourly counters (C40). */
const countedKey = (data: Hex): string => `relay:counted:${keccak256(data)}`;

/** A chain whose block clock runs behind ours may still take an action a little past its signed deadline. */
const COUNTED_GRACE_SECONDS = 600;
/** One counted mark per action, so a far signed deadline must not hold its key for longer than a day. */
const COUNTED_MAX_SECONDS = 86_400;

/**
 * How long an action's counted mark lives: while the registry may still take its bytes, until its
 * signed deadline and COUNTED_GRACE_SECONDS after, at most a day, and never less than the counting
 * window it guards, so a lost send repeated in the next window is not counted there again.
 */
function countedSeconds(deadline: bigint, now: number, windowSeconds: number): number {
  const left = deadline - BigInt(Math.floor(now / 1000)) + BigInt(COUNTED_GRACE_SECONDS);
  const lived = left > BigInt(COUNTED_MAX_SECONDS) ? BigInt(COUNTED_MAX_SECONDS) : left;
  return Math.max(windowSeconds, Number(lived));
}

/**
 * Moves the per-board, per-chair and valid-total counters for one action once (threat model C40):
 * a byte-identical relay of an action already counted, whose first send was lost and whose marks
 * then gave way, takes none of them again, while its ledgers and post bytes still book per send.
 * Runs under the send lock, so the mark's read and its write cannot race. The mark is written by
 * setIfAbsent for countedSeconds, only once every counter has passed, so an action a counter
 * refused is counted afresh when it comes back; a mark that cannot be read or written counts the
 * action again, the side that over-counts.
 *
 * @returns undefined once the action is counted, now or before; otherwise 429 rate_limited naming
 *   the counter that refused.
 */
async function countOnce(ctx: RelayContext, built: Built, chair: Hex, limits: RelayLimits, fields: Fields): Promise<Response | undefined> {
  const key = countedKey(built.data);
  if ((await ctx.store.get(key).catch(() => null)) !== null) return undefined;
  for (const counter of hourlyCounters(built, chair, limits)) {
    if (!(await under(ctx, counter.key, counter.max, limits.windowSeconds))) {
      return refusal(429, "rate_limited", { ...fields, limit: counter.limit }, { "retry-after": String(limits.windowSeconds) });
    }
  }
  await ctx.store.setIfAbsent(key, "1", countedSeconds(built.deadline, ctx.now, limits.windowSeconds)).catch(() => logEvent("relay_counted_mark_unset", fields));
  return undefined;
}

/** An hour's demo key outlives its hour, so a reservation near the hour's end never finds it gone. */
const DEMO_HOUR_KEY_SECONDS = 2 * 3600;
const DEMO_RESERVE_TRIES = 3;
/** The hour's count and the token of the write that set it: "<count>:<uuid>". */
const DEMO_TAKEN = /^(\d{1,4}):[0-9a-f-]{36}$/;
const demoHourKey = (now: number): string => `rate:relay:demo:${Math.floor(now / 3_600_000)}`;

/**
 * How many of the clock hour's DEMO_RELAYS_PER_HOUR demo relays are still free, read without taking
 * any (threat model C41), so a pressure pass stops before it looks anything up when there are none.
 * reserveDemoRelays still decides; this only saves work. 0 for a `now` it does not accept, a store
 * failure or a count it cannot read, so the reader does nothing.
 */
export async function demoRelaysLeft(store: SharedStore, now: number): Promise<number> {
  if (!Number.isSafeInteger(now) || now < 0) return 0;
  try {
    const held = await store.get(demoHourKey(now));
    const taken = held === null ? 0 : Number(DEMO_TAKEN.exec(held)?.[1] ?? Number.NaN);
    return Number.isSafeInteger(taken) ? Math.max(0, DEMO_RELAYS_PER_HOUR - taken) : 0;
  } catch {
    return 0;
  }
}

/**
 * Reserves one of the clock hour's DEMO_RELAYS_PER_HOUR demo relays (threat model C41). The demo bot
 * calls it before each relay it makes: before a join's addMember, and before each removeMember a
 * sweep or a pressure pass makes (the pass keeps DEMO_FREE_SEATS free). Relays in scope "demo" take
 * nothing more hourly, and no public relay can reach this room. The hour is the UTC clock hour of
 * `now`, so a burst at the end of one hour and the start of the next can reach twice the figure;
 * the bot's daily ledger and its daily join limit still bound the day.
 *
 * The count moves only by compare-and-set from the value read, and every write carries a fresh
 * token, so a request retried after a lost reply is told apart from another caller's equal count.
 *
 * @param now Milliseconds since the epoch.
 * @param count Always 1: every relay is reserved on its own, right before it is made.
 * @returns true when the relay was taken. false when the hour is full, `count` or `now` is not one
 *   this accepts, the store failed or held something unreadable, or other callers won the race
 *   three times; nothing was then taken.
 */
export async function reserveDemoRelays(store: SharedStore, now: number, count: 1): Promise<boolean> {
  if (count !== 1 || !Number.isSafeInteger(now) || now < 0) return false;
  const key = demoHourKey(now);
  try {
    for (let attempt = 0; attempt < DEMO_RESERVE_TRIES; attempt++) {
      const held = await store.get(key);
      const taken = held === null ? 0 : Number(DEMO_TAKEN.exec(held)?.[1] ?? Number.NaN);
      if (!Number.isSafeInteger(taken)) break;
      if (taken + count > DEMO_RELAYS_PER_HOUR) {
        logEvent("relay_refused", { reason: "demo_hour_full", scope: "demo", taken, asked: count });
        return false;
      }
      const next = `${taken + count}:${randomUUID()}`;
      if (await store.compareAndSet(key, held, next, DEMO_HOUR_KEY_SECONDS)) return true;
      if ((await store.get(key)) === next) return true;
    }
  } catch {
    // Refused below, like every other path that cannot prove the room was taken.
  }
  logEvent("relay_refused", { reason: "demo_reserve_failed", scope: "demo" });
  return false;
}

async function readBody(request: Request): Promise<{ body: RelayBody } | { response: Response }> {
  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") return { response: refusal(415, "json_only") };
  const stated = declaredLength(request);
  if (stated !== undefined && stated > RELAY_BODY_CAP) return { response: refusal(413, "body_too_large") };
  if (request.body === null) return { response: refusal(400, "bad_body") };
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBodyBytes(request.body, RELAY_BODY_CAP)));
  } catch (error) {
    if (error instanceof BodyTimeout) return { response: refusal(408, "body_timeout") };
    return { response: error instanceof TooLarge ? refusal(413, "body_too_large") : refusal(400, "bad_body") };
  }
  const checked = relayBody.safeParse(parsed);
  if (!checked.success) {
    // Paths name our own schema's fields, never a value or a key the caller chose.
    const field = (checked.error.issues[0]?.path ?? []).map(String).join(".").slice(0, 64);
    return { response: refusal(400, "bad_body", { field }) };
  }
  return { body: checked.data };
}

/**
 * Who acts and at which registry nonce, read at the latest block: for a board action the board's
 * current chair and nonce (getBoard), for createBoard the signed chair and its create nonce
 * (createNonces). The signature commits to that nonce, so an action that passed its pre-flight is
 * an action at it. A revert answers with the registry's error name; a read that fails is undefined.
 */
async function actingAt(ctx: RelayContext, built: Built, deadline: Deadline): Promise<{ chair: Hex; nonce: bigint } | { refused: string } | undefined> {
  const abi = boardRegistryAbi;
  const read = (data: Hex, what: string) => within(deadline, ctx.chain.call({ from: ctx.relayer.evm, to: REGISTRY_ADDRESS, data }), what);
  try {
    if (built.chair !== undefined) {
      const outcome = await read(encodeFunctionData({ abi, functionName: "createNonces", args: [built.chair] }), "reading the create nonce");
      if (!outcome.ok) return { refused: revertName(outcome.revertData) };
      return { chair: built.chair, nonce: decodeFunctionResult({ abi, functionName: "createNonces", data: outcome.data }) };
    }
    const outcome = await read(encodeFunctionData({ abi, functionName: "getBoard", args: [built.boardId ?? 0n] }), "reading the board");
    if (!outcome.ok) return { refused: revertName(outcome.revertData) };
    const board = decodeFunctionResult({ abi, functionName: "getBoard", data: outcome.data });
    return { chair: board.chair, nonce: board.nonce };
  } catch {
    return undefined;
  }
}

const lateRefusal = (fields: Fields): Response => refusal(503, "out_of_time", fields, { "retry-after": "30" });

/**
 * The exact transaction's eth_call, run before anything but the IP is counted (threat model C40).
 * The registry checks the chair's signature, so only an action that passes here may count against
 * a chair, a board or the total. A revert counts against the rejected total alone and answers 422
 * with the registry's error name, or 429 once that total is spent.
 *
 * @returns undefined when the call passed, otherwise the refusal to send.
 */
async function preflight(ctx: RelayContext, built: Built, limits: RelayLimits, fields: Fields, deadline: Deadline): Promise<Response | undefined> {
  let outcome: CallOutcome;
  try {
    outcome = await within(deadline, ctx.chain.call({ from: ctx.relayer.evm, to: REGISTRY_ADDRESS, data: built.data }), "the pre-flight call");
  } catch (error) {
    return error instanceof OutOfTime ? lateRefusal(fields) : refusal(502, "chain_unreachable", fields);
  }
  if (outcome.ok) return undefined;
  if (!(await under(ctx, REJECTED_KEY, limits.rejected, limits.windowSeconds))) {
    return refusal(429, "rate_limited", { ...fields, limit: "rejected" }, { "retry-after": String(limits.windowSeconds) });
  }
  return refusal(422, revertName(outcome.revertData), fields);
}

/** A send that reached the node, with what is needed to settle its booking once the receipt is in. */
interface Sent {
  hash: Hex;
  reservation: Reservation;
  gas: bigint;
  maxFeePerGas: bigint;
}

/** What one pass under the send lock did: the answer, whether a transaction was handed to the node, and the send to settle. */
interface Attempt {
  response: Response;
  /** True once a signed transaction was handed to the node, whatever came back: it may still land. */
  handedOver?: boolean;
  sent?: Sent;
  /** The in-flight mark this relay claimed, to clear on a receipt or when nothing was handed over. */
  inflight?: Mark;
}

const isDemo = (ctx: RelayContext): boolean => ctx.scope === "demo";

/**
 * The ledgers a send books on, most specific first, so one chair's cap refuses before the shared
 * shares are touched. The bot's relays and the chairs' relays never share a ledger but the total.
 */
function sendLedgers(ctx: RelayContext, chair: Hex): Ledger[] {
  if (isDemo(ctx)) return [ledgerFor("demo", ctx.now), ledgerFor("total", ctx.now)];
  return [ledgerFor("chair", ctx.now, chair), ledgerFor("chairs", ctx.now), ledgerFor("total", ctx.now)];
}

const secondsToUtcMidnight = (now: number): number => 86_400 - Math.floor((now % 86_400_000) / 1000);

function ledgerRefusal(now: number, error: unknown, fields: Fields): Response {
  if (!(error instanceof DailyCeilingReached)) return refusal(503, "ledger_unavailable", fields);
  // One chair's own day is spent: that is a limit on the caller, not on the service.
  if (error.ledger === "chair") return refusal(429, "rate_limited", { ...fields, limit: "chair_daily" }, { "retry-after": String(secondsToUtcMidnight(now)) });
  return refusal(503, "daily_ceiling", { ...fields, ledger: error.ledger });
}

/**
 * The bytes a post keeps for good, as this server last read and hashed them (threat model C44): the
 * size in the document's verified mark (verifiedSize), accepted only when it equals the signed
 * cipherSize, so the post bytes budget books what the store holds and never the chair's claim. It
 * reads the store alone and moves nothing, so it runs before every counter but the IP's.
 *
 * @returns undefined for every action but a post; the size for a post whose document is verified
 *   at exactly its cipherSize; otherwise the refusal: 422 document_unverified when the document has
 *   no verified mark, 422 size_mismatch when the mark states another size, 503 store_unavailable
 *   when the mark cannot be read.
 */
async function documentKept(ctx: RelayContext, built: Built, fields: Fields): Promise<bigint | Response | undefined> {
  if (built.action !== "post") return undefined;
  let size: bigint | undefined;
  try {
    size = await verifiedSize(ctx.store, (built.cipherHash ?? "").slice(2));
  } catch {
    return refusal(503, "store_unavailable", fields);
  }
  if (size === undefined) return refusal(422, "document_unverified", fields);
  if (size !== built.cipherSize) return refusal(422, "size_mismatch", fields);
  return size;
}

/**
 * Books a post's verified bytes on the chair's and the day's post ledgers, all or none, before the
 * broadcast (threat model C44): a posted document is kept for good, so it is budgeted by what it keeps.
 *
 * @returns undefined for every action but a post, the reservation to give back if nothing is
 *   broadcast, or the refusal: 422 document_unverified for a post whose size documentKept did not
 *   settle, 429 post_bytes (retry after UTC midnight) when either ledger would pass its ceiling,
 *   503 ledger_unavailable when they cannot be read.
 */
async function reservePostBytes(ctx: RelayContext, built: Built, chair: Hex, fields: Fields): Promise<Reservation | Response | undefined> {
  if (built.action !== "post") return undefined;
  const kept = built.keptBytes;
  if (kept === undefined || kept !== built.cipherSize) return refusal(422, "document_unverified", fields);
  const full = () => refusal(429, "post_bytes", fields, { "retry-after": String(secondsToUtcMidnight(ctx.now)) });
  if (kept > PER_CHAIR_DAILY_POST_BYTES) return full();
  try {
    return await reserveOn(ctx.store, [ledgerFor("chair_posts", ctx.now, chair), ledgerFor("posts", ctx.now)], kept, "post_bytes");
  } catch (error) {
    return error instanceof DailyCeilingReached ? full() : refusal(503, "ledger_unavailable", fields);
  }
}

/**
 * The last steps before a relay's broadcast, run inside beforeBroadcast once the transaction's record
 * under its nonce and both marks name it (threat model C24, C40): the per-board, per-chair and valid
 * counters (countOnce; the bot's own relays take none, C41), then the window's own record of our
 * sends, so a later read can tell our spending from anyone else's. A counter that refuses leaves no
 * window record.
 *
 * @returns undefined when the broadcast may go ahead; otherwise the refusal: 429 rate_limited from a
 *   counter, or 503 ledger_unavailable when the window record cannot be written.
 */
async function countAndRecord(ctx: RelayContext, built: Built, chair: Hex, limits: RelayLimits, fields: Fields, openedHeight: bigint, worst: bigint): Promise<Response | undefined> {
  if (!isDemo(ctx)) {
    const over = await countOnce(ctx, built, chair, limits, fields);
    if (over !== undefined) return over;
  }
  try {
    await recordWindowSend(ctx.store, openedHeight, worst);
  } catch {
    return refusal(503, "ledger_unavailable", fields);
  }
  return undefined;
}

/**
 * Everything after admission, while holding the send lock: one transaction at a time, so nonces
 * never collide. `marks` are this relay's copy and in-flight marks: any still held for another
 * relay's lost transaction is taken first, and each is given the transaction's hash before it is broadcast.
 */
async function relayOnce(ctx: RelayContext, built: Built, chair: Hex, limits: RelayLimits, fields: Fields, deadline: Deadline, marks: readonly Mark[]): Promise<Attempt> {
  if (elapsedMs(deadline) > SEND_CUTOFF_MS) return { response: lateRefusal(fields) };
  const taken = await takeDisplaced(ctx, marks, deadline, fields);
  if (taken !== undefined) return { response: taken };
  const windowDeps: WindowDeps = { store: ctx.store, now: ctx.now, relayer: ctx.relayer, chain: ctx.chain, sleep: ctx.sleep, deadline };
  let halted: boolean;
  try {
    halted = await isHalted(ctx.store, ctx.now);
  } catch {
    return { response: refusal(503, "ledger_unavailable", fields) };
  }
  if (halted) {
    // A halted relayer still closes a live window it finds, so a close that failed earlier is tried again.
    await ensureWindow(windowDeps).catch(() => undefined);
    return { response: refusal(503, "halted", fields) };
  }
  let state: WindowState;
  try {
    state = await ensureWindow(windowDeps);
  } catch (error) {
    if (error instanceof RelayerHalted) return { response: refusal(503, "halted", fields) };
    if (error instanceof DailyCeilingReached) return { response: refusal(503, "daily_ceiling", fields) };
    if (error instanceof OutOfTime) return { response: lateRefusal(fields) };
    if (error instanceof LockBusy) return { response: refusal(503, "busy", fields, { "retry-after": "30" }) };
    return { response: refusal(503, "window_unavailable", fields) };
  }

  // The contract is the check: the exact transaction must pass eth_call before anything is spent.
  const tx = { from: ctx.relayer.evm, to: REGISTRY_ADDRESS, data: built.data };
  try {
    const outcome = await within(deadline, ctx.chain.call(tx), "the pre-flight call");
    if (!outcome.ok) return { response: refusal(422, revertName(outcome.revertData), fields) };
  } catch (error) {
    return { response: error instanceof OutOfTime ? lateRefusal(fields) : refusal(502, "chain_unreachable", fields) };
  }
  let gas: bigint;
  let quote: FeeQuote;
  try {
    gas = await within(deadline, ctx.chain.estimateGas(tx), "the gas estimate");
    quote = await within(deadline, ctx.chain.feeQuote(), "the fee quote");
  } catch (error) {
    return { response: error instanceof OutOfTime ? lateRefusal(fields) : refusal(502, "chain_unreachable", fields) };
  }
  const ceiling = GAS_CEILING[built.action];
  if (gas > ceiling) return { response: refusal(422, "gas_above_ceiling", { ...fields, gas: gas.toString() }) };
  const fee = feeCaps(quote);
  if (fee === undefined) return { response: refusal(503, "fee_above_ceiling", fields) };

  // The worst case, gas limit times fee cap, is what the window charges and what the ledgers book.
  const worst = evmWindowCost({ gas: ceiling, maxFeePerGas: fee.maxFeePerGas });
  if (elapsedMs(deadline) > SEND_CUTOFF_MS) return { response: lateRefusal(fields) };
  const kept = await reservePostBytes(ctx, built, chair, fields);
  if (kept instanceof Response) return { response: kept };
  let reservation: Reservation;
  try {
    reservation = await reserveOn(ctx.store, sendLedgers(ctx, chair), worst, built.action);
  } catch (error) {
    if (kept !== undefined) await releaseSpend(ctx.store, kept);
    return { response: ledgerRefusal(ctx.now, error, fields) };
  }
  const unsent = async (response: Response): Promise<Attempt> => {
    await releaseSpend(ctx.store, reservation);
    if (kept !== undefined) await releaseSpend(ctx.store, kept);
    return { response };
  };
  let guard: SendGuard;
  try {
    guard = await guardSend(windowDeps, state.window);
  } catch (error) {
    if (error instanceof RelayerHalted) return unsent(refusal(503, "halted", fields));
    if (error instanceof OutOfTime) return unsent(lateRefusal(fields));
    return unsent(error instanceof WindowUnavailable ? refusal(503, "window_unavailable", fields) : refusal(502, "chain_unreachable", fields));
  }
  // A send started after the cutoff could outlive the function and the lock.
  if (elapsedMs(deadline) > SEND_CUTOFF_MS) return unsent(lateRefusal(fields));

  // From here the transaction may reach the chain, so its worst case stays booked unless a receipt
  // settles it, and its record stays for the next nonce check to find it in a block.
  // The marks carry the hash before the broadcast, so a later relay can ask the chain about it; a
  // mark that cannot take it stops the broadcast, and the record is undone below.
  let refused: Response | undefined;
  const beforeBroadcast: BeforeBroadcast = async (signedTx) => {
    await guard.beforeBroadcast(signedTx);
    await stampMarks(ctx, marks, signedTx.hash);
    // The hourly counters cannot be given back, so they move last (C40): after every refusal a
    // caller can cause, the nonce check's wait, the cutoff and the record's look-up of an earlier
    // send at this nonce included, and after the bookings that can be returned. A relay retried
    // after a 503 would otherwise take them again. The bot's relays take none (C41).
    refused = await countAndRecord(ctx, built, chair, limits, fields, state.window.openedHeight, worst);
    if (refused !== undefined) throw new Error("Refused before the broadcast.");
    // stampMarks has refused any hash that is not 0x and 64 lowercase hex digits.
    await ctx.onSigned?.(signedTx.hash as Hex);
  };
  let hash: Hex;
  try {
    hash = await ctx.chain.send({ to: REGISTRY_ADDRESS, data: built.data, gas: ceiling, ...fee }, deadline, beforeBroadcast);
  } catch (error) {
    if (!(error instanceof NotBroadcast)) return { response: refusal(502, "broadcast_failed", fields), handedOver: true };
    await guard.undo();
    return unsent(refused ?? refusal(502, "chain_unreachable", fields));
  }
  if (!/^0x[0-9a-f]{64}$/.test(hash)) return { response: refusal(502, "broadcast_failed", fields), handedOver: true };
  logEvent("relay_sent", { ...fields, txHash: hash, nonce: guard.nonce.toString(), gas: ceiling.toString(), maxFeePerGas: fee.maxFeePerGas.toString(), worstUqor: worst.toString() });
  return { response: json(202, { txHash: hash }), handedOver: true, sent: { hash, reservation, gas: ceiling, maxFeePerGas: fee.maxFeePerGas } };
}

/** Each chain object's verdict on the registry's code. Production builds one chain per process, so this is the process's check (C9). */
const registryVerdicts = new WeakMap<RelayChain, boolean>();

/**
 * Whether the code at REGISTRY_ADDRESS is the deployed registry's (threat model C9): an address with
 * no code answers every eth_call with success, so the pre-flight alone cannot tell. A match or a
 * mismatch is kept; a read that fails is not, so the next relay asks again.
 *
 * @returns The verdict, or undefined when the code could not be read.
 */
async function registryChecked(ctx: RelayContext, deadline: Deadline): Promise<boolean | undefined> {
  const known = registryVerdicts.get(ctx.chain);
  if (known !== undefined) return known;
  if (ctx.chain.registryCodeHash === undefined) return false;
  let found: unknown;
  try {
    found = await within(deadline, ctx.chain.registryCodeHash(), "reading the registry's code");
  } catch {
    return undefined;
  }
  const shown = typeof found === "string" && /^0x[0-9a-fA-F]{64}$/.test(found) ? found.toLowerCase() : undefined;
  const matches = shown === REGISTRY_CODE_KECCAK;
  registryVerdicts.set(ctx.chain, matches);
  if (!matches) logEvent("relay_registry_mismatch", { found: shown ?? "none" });
  return matches;
}

/** The mark that stops copies of one signed action, keyed on its exact calldata, signature included. */
const copyKey = (data: Hex): string => `relay:copy:${keccak256(data)}`;

/** A copy mark lives until the action's own signed deadline, at least 1 s and at most an hour. */
function copySeconds(deadline: bigint, now: number): number {
  const left = deadline - BigInt(Math.floor(now / 1000));
  return left < 1n ? 1 : left > 3600n ? 3600 : Number(left);
}

/**
 * The mark that keeps one action per registry nonce in flight (threat model C40): a board's nonce,
 * or for createBoard the chair's create nonce, so re-signed actions at one nonce cannot each take a
 * counter and then all but one revert.
 */
function inflightKey(built: Built, chair: Hex, nonce: bigint): string {
  return built.boardId === undefined ? `relay:inflight:${accountKey(chair)}:create:${nonce}` : `relay:inflight:${built.boardId}:${nonce}`;
}

/**
 * What a copy or in-flight mark holds: the token of the relay that set it, then either the moment
 * (ms since the epoch) that relay's time runs out, or the hash of the transaction it signed.
 */
const MARK_VALUE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):(?:until:([0-9]{1,16})|tx:(0x[0-9a-f]{64}))$/;

/** A mark read back as an input would be; anything this file does not write, an older form included, is undefined and so held. */
function readMark(raw: string): { until: number } | { tx: Hex } | undefined {
  const parts = MARK_VALUE.exec(raw);
  if (parts === null) return undefined;
  if (parts[3] !== undefined) return { tx: parts[3] as Hex };
  const until = Number(parts[2]);
  return Number.isSafeInteger(until) ? { until } : undefined;
}

/**
 * One once-only mark this relay claimed (threat model C40, C46): the copy mark on its calldata or
 * the in-flight mark on its registry nonce.
 */
interface Mark {
  readonly kind: "copy" | "inflight";
  readonly key: string;
  readonly ttlSeconds: number;
  readonly token: string;
  /** What the mark holds for this relay; undefined while it still waits to be taken under the send lock. */
  value?: string;
  /** Another relay's mark for a transaction the chain did not know, to take under the send lock if it still does not. */
  displaced?: { held: string; tx: Hex };
}

const busyAnswer = (mark: Pick<Mark, "kind">, fields: Fields): Response => refusal(409, mark.kind === "copy" ? "duplicate" : "nonce_in_flight", fields);

/** This relay's value for a mark with no transaction yet: held only until the relay's own deadline. */
const untilValue = (ctx: RelayContext, token: string): string => `${token}:until:${ctx.now + RELAY_DEADLINE_MS}`;

/** A compare-and-set that counts a retried write that did land, read back as `next`, as its own. */
async function swapped(store: SharedStore, key: string, expected: string | null, next: string, ttlSeconds: number): Promise<boolean> {
  return (await store.compareAndSet(key, expected, next, ttlSeconds)) || (await store.get(key)) === next;
}

/** Where the chain says a marked transaction stands, or undefined when it cannot be asked in time. */
async function markedStatus(ctx: RelayContext, tx: Hex, deadline: Deadline): Promise<TxStatus | undefined> {
  if (ctx.chain.txStatus === undefined) return undefined;
  try {
    return await within(deadline, ctx.chain.txStatus("evm", tx), "looking up a marked transaction");
  } catch {
    return undefined;
  }
}

/**
 * Claims the once-only mark `key` for this relay (threat model C26, C40, C46). A mark that is free,
 * or that another relay set with no transaction yet and whose deadline has passed, is taken at
 * once by compare-and-set. A mark naming a transaction that can no longer land (cannotLand: the
 * chain does not know it, the rule the send record uses, or holds it reverted, which leaves the
 * board's nonce unchanged) is only marked to be taken: takeDisplaced takes it under the send lock,
 * where no other relay is between signing and broadcasting, so the chain's answer then is final.
 *
 * @returns The mark, or the refusal: 409 duplicate (copy) or nonce_in_flight (in-flight) while
 *   the mark guards a relay still inside its deadline, a transaction the chain holds pending or
 *   landed, or a value it cannot read; 502 chain_unreachable when the chain cannot say, or has no lookup; 503
 *   store_unavailable when the store fails.
 */
async function claimMark(ctx: RelayContext, kind: Mark["kind"], key: string, ttlSeconds: number, deadline: Deadline, fields: Fields): Promise<Mark | Response> {
  const token = randomUUID();
  const mine = untilValue(ctx, token);
  const mark: Mark = { kind, key, ttlSeconds, token };
  let held: string | null;
  try {
    if (await claimOnce(ctx.store, key, mine, ttlSeconds)) return { ...mark, value: mine };
    held = await ctx.store.get(key);
    if (held === null) return (await swapped(ctx.store, key, null, mine, ttlSeconds)) ? { ...mark, value: mine } : busyAnswer(mark, fields);
  } catch {
    return refusal(503, "store_unavailable", fields);
  }
  const state = readMark(held);
  if (state === undefined) return busyAnswer(mark, fields);
  if ("until" in state) {
    if (ctx.now <= state.until) return busyAnswer(mark, fields);
    try {
      return (await swapped(ctx.store, key, held, mine, ttlSeconds)) ? { ...mark, value: mine } : busyAnswer(mark, fields);
    } catch {
      return refusal(503, "store_unavailable", fields);
    }
  }
  const status = await markedStatus(ctx, state.tx, deadline);
  if (status === undefined) return refusal(502, "chain_unreachable", fields);
  return cannotLand(status) ? { ...mark, displaced: { held, tx: state.tx } } : busyAnswer(mark, fields);
}

/**
 * Whether the transaction a mark names can no longer change the registry: the chain does not know
 * it, or holds it with a reverted receipt, which leaves the board's nonce where it was. A pending
 * transaction, or one that landed, still holds its mark.
 */
const cannotLand = (status: TxStatus): boolean => status === "unknown" || status === "reverted";

/**
 * Under the send lock, before anything else: takes each mark claimMark found held for a transaction
 * that could no longer land, once the chain still says so (unknown, or reverted), by compare-and-set
 * from the value then found. A transaction that turned up in the meantime, pending or landed, keeps its mark.
 *
 * @returns undefined once every mark is this relay's, otherwise the refusal claimMark would give.
 */
async function takeDisplaced(ctx: RelayContext, marks: readonly Mark[], deadline: Deadline, fields: Fields): Promise<Response | undefined> {
  for (const mark of marks) {
    if (mark.displaced === undefined) continue;
    const status = await markedStatus(ctx, mark.displaced.tx, deadline);
    if (status === undefined) return refusal(502, "chain_unreachable", fields);
    if (!cannotLand(status)) return busyAnswer(mark, fields);
    const mine = untilValue(ctx, mark.token);
    try {
      if (!(await swapped(ctx.store, mark.key, mark.displaced.held, mine, mark.ttlSeconds))) return busyAnswer(mark, fields);
    } catch {
      return refusal(503, "store_unavailable", fields);
    }
    logEvent("relay_mark_taken", { ...fields, mark: mark.kind, lostTx: mark.displaced.tx });
    mark.value = mine;
    mark.displaced = undefined;
  }
  return undefined;
}

/**
 * Writes the signed transaction's hash into each of this relay's marks, by compare-and-set from what
 * it held, inside beforeBroadcast. Throws, so nothing is broadcast, when a mark is no longer this
 * relay's or cannot be written: the mark must name the transaction before the chain can see it.
 */
async function stampMarks(ctx: RelayContext, marks: readonly Mark[], hash: string): Promise<void> {
  if (!/^0x[0-9a-f]{64}$/.test(hash)) throw new Error("The signed transaction's hash is not one a mark can hold.");
  for (const mark of marks) {
    if (mark.value === undefined) throw new Error("A mark is not this relay's.");
    const next = `${mark.token}:tx:${hash}`;
    if (mark.value === next) continue;
    if (!(await swapped(ctx.store, mark.key, mark.value, next, mark.ttlSeconds))) throw new Error("A mark moved before the broadcast.");
    mark.value = next;
  }
}

/**
 * The in-flight mark for the action's registry nonce, then a read of the hourly counters, so a
 * relay already over one is refused before it waits for the lock, then the send under the lock.
 * Every refusal here comes before any broadcast.
 */
async function admitAndSend(ctx: RelayContext, built: Built, limits: RelayLimits, fields: Fields, deadline: Deadline, signedDeadline: bigint, copy: Mark): Promise<Attempt> {
  const retry = { "retry-after": String(limits.windowSeconds) };
  const demo = isDemo(ctx);
  const acting = await actingAt(ctx, built, deadline);
  if (acting === undefined) return { response: refusal(502, "chain_unreachable", fields) };
  if ("refused" in acting) return { response: refusal(422, acting.refused, fields) };
  // The mark lives as long as the action can land: until its own signed deadline, at most an hour.
  const inflight = await claimMark(ctx, "inflight", inflightKey(built, acting.chair, acting.nonce), copySeconds(signedDeadline, ctx.now), deadline, fields);
  if (inflight instanceof Response) return { response: inflight };
  const marked = (attempt: Attempt): Attempt => ({ ...attempt, inflight });
  // Read only: the counters move under the send lock, last (relayOnce). The bot's relays have
  // their own room, reserved before a join (reserveDemoRelays), and take none of these. Nor does
  // a byte-identical retry of an action countOnce has counted, so it is not refused by a count it
  // already holds; a mark that cannot be read leaves the read in place, the side that refuses.
  if (!demo && (await ctx.store.get(countedKey(built.data)).catch(() => null)) === null) {
    for (const counter of hourlyCounters(built, acting.chair, limits)) {
      if (await atLimit(ctx, counter.key, counter.max)) return marked({ response: refusal(429, "rate_limited", { ...fields, limit: counter.limit }, retry) });
    }
  }

  const waitMs = Math.floor(Math.max(0, Math.min(SEND_LOCK_WAIT_MS, SEND_CUTOFF_MS - elapsedMs(deadline))));
  try {
    return marked(await ctx.store.withLock(SEND_LOCK, LOCK_TTL_SECONDS, () => relayOnce(ctx, built, acting.chair, limits, fields, deadline, [copy, inflight]), { waitMs }));
  } catch (error) {
    if (error instanceof LockBusy) return marked({ response: refusal(503, "busy", fields, { "retry-after": "30" }) });
    return marked({ response: refusal(503, "store_unavailable", fields) });
  }
}

/** Clears one of this relay's marks, only while it still holds this relay's value, so a mark another relay has since taken stays. */
async function clearMark(ctx: RelayContext, mark: Mark, fields: Fields): Promise<void> {
  if (mark.value === undefined) return;
  try {
    if ((await ctx.store.get(mark.key)) === mark.value) await ctx.store.delete(mark.key);
  } catch {
    logEvent(mark.kind === "copy" ? "relay_copy_mark_kept" : "relay_inflight_mark_kept", fields);
  }
}

/** A receipt can only be believed inside what the transaction allowed: its gas limit and its fee cap. */
const withinLimits = (fee: ReceiptFee, sent: Sent): boolean =>
  fee.gasUsed > 0n && fee.gasUsed <= sent.gas && fee.effectiveGasPrice > 0n && fee.effectiveGasPrice <= sent.maxFeePerGas;

/**
 * Waits, outside the send lock, for the send's receipt and settles its booking down to the real
 * fee, gas used times effective gas price rounded up to whole uqor. No receipt in time, or one
 * outside the transaction's own limits, keeps the worst case booked.
 *
 * @returns Whether a receipt was seen: the transaction is in a block and no longer in flight.
 */
async function settleFromReceipt(ctx: RelayContext, sent: Sent, deadline: Deadline): Promise<boolean> {
  const wait = narrowed(deadline, RECEIPT_WAIT_MS);
  let fee: ReceiptFee | undefined;
  try {
    fee = ctx.chain.receipt === undefined ? undefined : await within(wait, ctx.chain.receipt(sent.hash, wait), "the receipt");
  } catch {
    fee = undefined;
  }
  if (fee === undefined || !withinLimits(fee, sent)) {
    logEvent("relay_unsettled", { txHash: sent.hash, worstUqor: sent.reservation.amount.toString() });
    return fee !== undefined;
  }
  await settleSpend(ctx.store, sent.reservation, weiToUqorCeil(fee.gasUsed * fee.effectiveGasPrice));
  return true;
}

/**
 * Relays one chair-signed board action to the registry from the relayer's own account (threat model
 * C9, C23 to C26, C31, C32, C36, C40, C41, C44).
 *
 * Admission, in order: unless scope is "demo", a request another site's page could have sent (403
 * cross_site, refuseCrossSite), before anything is counted or read; POST only (405); the code at
 * REGISTRY_ADDRESS, read once per chain object and
 * compared with REGISTRY_CODE_KECCAK, before any counter (503 registry_mismatch, 502 when it cannot
 * be read); the per-IP limit, which every public request counts against, with every /64 of one
 * IPv6 /48 also sharing 4 times it (countClient, 429); `application/json`
 * (415); at most RELAY_BODY_CAP bytes, refused while reading (413), ending within 20 seconds (408
 * body_timeout); the body schema, so a malformed
 * address (anything but exact EIP-55), hash, integer or a signature of any other length is refused
 * (400) before any chain call; for a post, the document's verified size (verifiedSize, a store read
 * that moves nothing) must equal the signed cipherSize, else 422 document_unverified when it has no
 * verified mark or 422 size_mismatch when the mark states another size; the eth_call of the exact
 * transaction from the relayer, so the registry checks the signature before any other counter
 * moves (422 with the registry's error name, counted against the rejected total only, 429 once
 * that is spent); a once-only mark on the calldata's keccak256, living until the signed deadline
 * and at most an hour, so a copy of a pending action answers 409 duplicate and moves nothing; the
 * chair and the registry nonce the action is signed at (the create parameter and createNonces, or
 * getBoard, at the latest block; a revert answers 422 with the registry's error name); a mark on
 * that board nonce, or that chair's create nonce, living like the copy mark, so a second, different
 * action at a nonce with one in flight answers 409 nonce_in_flight and moves nothing; then a read,
 * without counting, of the per-board, per-chair and valid-total counters, so a relay already over
 * one answers 429 before it waits for the lock (skipped for a byte-identical retry of an action
 * countOnce already counted, which takes none of them again). A relay with scope "demo" skips the per-IP,
 * per-board and per-chair limits and the valid total: the bot reserves its hourly room before each
 * relay (reserveDemoRelays).
 *
 * Both marks give way (C26, C40): one that holds no transaction yet stops other relays only while
 * the relay that set it is inside RELAY_DEADLINE_MS of its arrival; one that names the relayer
 * transaction it guards (written into it by compare-and-set before the broadcast, or nothing is
 * broadcast) stops them while the chain holds that transaction pending or landed, or cannot say,
 * and is taken under the send lock once the chain answers "unknown" or "reverted" there as well. So
 * after a send the node refused, or one that reverted at the board's unchanged nonce, the chair may
 * send the same bytes again, or cancel by landing a different action at that nonce.
 *
 * Then, under the shared lock "relayer:send" (waiting up to 20 s, else 503): any mark to take
 * from a lost transaction (409 if it turned up meanwhile); the halt flag (after a
 * suspected key leak ensureWindow still runs, to close a live window or retry a failed close, and
 * the answer is 503 halted until an operator clears it); ensureWindow (503 at the daily ceiling or
 * without a usable window); eth_call of the exact transaction again, because another action may
 * have moved the board's nonce while this one waited (422 on a revert, and nothing is sent);
 * estimateGas (422 above the action's gas ceiling); the fee cap (503 above MAX_FEE_PER_GAS); for a
 * post, its verified size booked on the chair's and the day's post bytes (429 post_bytes past
 * PER_CHAIR_DAILY_POST_BYTES or TOTAL_DAILY_POST_BYTES); the worst case booked on the chair's own
 * day (429 at PER_CHAIR_DAILY_UQOR), the chairs' or the demo bot's share and the total (503
 * daily_ceiling), all or none; the nonce check (guardSend: a nonce the chain used since the stored
 * one that is not a recorded transaction of ours in a block answers 503 halted, with the window
 * closed; one of ours still waiting for a block answers 503 window_unavailable); SEND_CUTOFF_MS
 * again, since that check may wait (503 out_of_time); then, once the transaction is signed and
 * before its broadcast, the signed transaction recorded under its nonce (where an earlier
 * transaction of ours holds that nonce, a look-up of it that the chain answers pending or landed,
 * or that runs out of time, sends nothing: 502 chain_unreachable) and its hash written into both
 * marks; only then, last of all because they cannot be given back, the per-board, per-chair and
 * valid-action counters (429, the bookings, the record and the marks given back), so a relay refused
 * anywhere earlier, and retried, takes none of them, and taken once per action (countOnce:
 * byte-identical calldata already counted takes none again); the same worst case recorded against
 * the window it goes through; then `ctx.onSigned` when server code set it (a throw there sends
 * nothing), then one broadcast with the action's ceiling as gas limit.
 *
 * After the lock is released the relay waits up to RECEIPT_WAIT_MS for the receipt, settles the
 * booking down to the real fee and clears the nonce mark; without a receipt the worst case stays
 * booked and the mark keeps the hash. Any refusal before the broadcast gives the booking and the
 * post bytes back and removes the copy and nonce marks, so the same bytes, or another action at
 * that nonce, may be sent again.
 *
 * The whole path runs on one clock started when the request arrives: no send starts after
 * SEND_CUTOFF_MS (45 s), no window opens after OPEN_CUTOFF_MS (20 s), and every read ends by
 * RELAY_DEADLINE_MS (55 s), each answered 503 out_of_time, so the path ends inside the function's
 * and the 60 s lock's lifetime.
 *
 * @returns 202 with `{ txHash }` only. A hash is a claim that the transaction was handed to the
 *   node, never that it succeeded: the caller confirms the receipt and the registry event (C26).
 */
export async function handleRelay(request: Request, ctx: RelayContext): Promise<Response> {
  // The demo bot builds its own request when it sets scope "demo", so there is no browser to check.
  const crossSite = isDemo(ctx) ? undefined : refuseCrossSite(request);
  if (crossSite !== undefined) return crossSite;
  const deadline = startDeadline(RELAY_DEADLINE_MS, ctx.clock);
  if (request.method !== "POST") return refusal(405, "method_not_allowed", {}, { allow: "POST" });
  const registry = await registryChecked(ctx, deadline);
  if (registry === undefined) return refusal(502, "chain_unreachable");
  if (!registry) return refusal(503, "registry_mismatch");
  const limits = ctx.limits ?? RELAY_LIMITS;
  const retry = { "retry-after": String(limits.windowSeconds) };
  const demo = isDemo(ctx);
  if (!demo) {
    // Per IP, and per IPv6 /48 at 4 times that, with the one rule every endpoint uses (C23).
    const client = await countClient(ctx.store, { scope: "relay", clientIp: ctx.clientIp, perIp: limits.perIp, windowSeconds: limits.windowSeconds });
    if (!client.ok) return refusal(429, "rate_limited", { limit: client.refusedBy ?? "per_ip" }, retry);
  }

  const read = await readBody(request);
  if ("response" in read) return read.response;
  const signed = buildCalldata(read.body);
  const fields: Fields = {
    action: signed.action,
    ...(signed.boardId === undefined ? {} : { boardId: signed.boardId.toString() }),
    ...(demo ? { scope: "demo" } : {}),
  };
  const kept = await documentKept(ctx, signed, fields);
  if (kept instanceof Response) return kept;
  const built: Built = kept === undefined ? signed : { ...signed, keptBytes: kept };

  const refused = await preflight(ctx, built, limits, fields, deadline);
  if (refused !== undefined) return refused;

  // Copies of a pending action pass the pre-flight too; only the first may move the counters below (C40, C46).
  const copy = await claimMark(ctx, "copy", copyKey(built.data), copySeconds(read.body.deadline, ctx.now), deadline, fields);
  if (copy instanceof Response) return copy;
  const attempt = await admitAndSend(ctx, built, limits, fields, deadline, read.body.deadline, copy);
  // Nothing reached the node, so the chair may send these same bytes, or another action at this nonce, again.
  if (attempt.handedOver !== true) {
    await clearMark(ctx, copy, fields);
    if (attempt.inflight !== undefined) await clearMark(ctx, attempt.inflight, fields);
  }
  if (attempt.sent !== undefined && (await settleFromReceipt(ctx, attempt.sent, deadline)) && attempt.inflight !== undefined) {
    await clearMark(ctx, attempt.inflight, fields);
  }
  return attempt.response;
}
