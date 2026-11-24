import { randomUUID } from "node:crypto";
import {
  KemKeyUnavailable,
  Mode,
  accountBytes,
  challengeMessage,
  encryptDocument,
  identityFromMnemonic,
  leaveMessage,
  newDocRef,
  newEpochKey,
  sameAccount,
  sameHash,
  sealEpochKey,
  sha256,
  toHex,
  type Identity,
  type KemRecipient,
} from "@ava/core";
import { mldsa87 } from "@qorechain/pqc";
import { validateMlkemPublicKey } from "@qorechain/qoreseal";
import { bytesToHex, hexToBytes, type Hex } from "viem";
import { z } from "zod";
import { sameUrl, type BlobBackend } from "./blob.ts";
import type { RelayerAddress } from "./chain/account.ts";
import { OutOfTime, elapsedMs, leftMs, startDeadline, within, type Deadline } from "./chain/deadline.ts";
import type { RelayChain } from "./chain/types.ts";
import {
  DEMO_CHALLENGE_LIMITS,
  DEMO_CHALLENGE_SECONDS,
  DEMO_DEADLINE_MS,
  DEMO_FREE_SEATS,
  DEMO_GUEST_CAP,
  DEMO_GUEST_TTL_SECONDS,
  DEMO_JOIN_LIMITS,
  DEMO_LEAVE_LIMITS,
  DEMO_LOCK_TTL_SECONDS,
  DEMO_LOCK_WAIT_MS,
  DEMO_RECEIPT_WAIT_MS,
  DEMO_RELAY_CUTOFF_MS,
  REGISTRY_ADDRESS,
} from "./config.ts";
import {
  DemoStop,
  openCurrentEpochKey,
  provenMldsaKey,
  relayAction,
  sealedTo,
  signedAction,
  uploadEnvelope,
  type BoardSnapshot,
  type DemoChain,
} from "./demoBoard.ts";
import { DEMO_PACK_TEXT } from "./demoPack.ts";
import { writeVerifiedMark } from "./docupload.ts";
import { isHttpsOrigin, requireDemoChairMnemonic, type ServerEnv } from "./env.ts";
import { BodyTimeout, declaredLength, json, readBody, refuse, refuseCrossSite, TooLarge, type HandlerContext } from "./http.ts";
import { logEvent } from "./log.ts";
import { countClient } from "./ratelimit.ts";
import { demoRelaysLeft, reserveDemoRelays, type RelayContext } from "./relay.ts";
import { accountBytesStrict } from "./requestAddress.ts";
import { LockBusy, claimOnce, type SharedStore } from "./store.ts";

export interface DemoLimits {
  /** Join requests per IP per window, and joins whose addMember is relayed per UTC day. */
  join: { perIp: number; windowSeconds: number; perDay: number };
  challenge: { perIp: number; total: number; windowSeconds: number };
  /** Leave requests per IP per window; DEMO_LEAVE_LIMITS when absent. Leave challenges use `challenge`. */
  leave?: { perIp: number; windowSeconds: number };
}

export type DemoContext = HandlerContext & {
  env: Pick<ServerEnv, "DEMO_BOARD_ID" | "DEMO_SEEDED" | "DEMO_CHAIR_MNEMONIC" | "BLOB_ORIGIN">;
  chain: DemoChain;
  blobs: BlobBackend;
  /** The relayer's public addresses and its chain access, for the one relay pipeline. */
  relayer: RelayerAddress;
  relayChain: RelayChain;
  /** Overrides DEMO_JOIN_LIMITS and DEMO_CHALLENGE_LIMITS. */
  limits?: DemoLimits;
  /** A monotonic clock in milliseconds for the time budget; the process's own by default. */
  clock?: () => number;
  /**
   * Milliseconds since the epoch, read afresh for each removal the sweep or a pressure pass makes
   * (threat model C41), because `now` is when the request arrived and a pass outlives it: each
   * removal books its demo relay on the clock hour, and its ledger on the UTC day, in which it runs.
   * Date.now when absent.
   */
  wallClock?: () => number;
  /** Passed to the relay for the pause after a window opens. */
  sleep?: (ms: number) => Promise<void>;
  /**
   * Runs work after the join has answered, such as Next.js `after` (threat model C41). A join hands
   * it one pressure pass when the board needs seats freed. Absent, nothing is scheduled and the
   * scheduled sweep does the work.
   */
  background?: (work: () => Promise<unknown>) => void;
};

/** What the scheduled sweep and the pressure pass need: no caller, so no client IP. */
export type DemoSweepContext = Omit<DemoContext, "clientIp" | "limits" | "background">;

/**
 * Why the bot removes a guest: its six hours are up, its ML-KEM key is unusable or is another
 * member's, its key lookup has come back unreadable on three sweeps in a row, or a pressure pass is
 * freeing seats ahead of the next judges.
 */
export type RemovalReason = "expired" | "key_missing" | "key_invalid" | "key_changed" | "key_shared" | "key_unreadable" | "pressure" | "left";

type Removed = { done: "removed"; member: Hex; reason: RemovalReason; txHash: Hex; epochAfter: string; landed: boolean };

export type SweepOutcome = { done: "not_ready" } | { done: "nothing_due"; guests: number; unknown: number } | Removed | { done: "refused"; reason: string };

/** What one ensureCurrentPack call did: posted the pack for `epoch`, found that epoch's pack in place, or refused and changed nothing. */
export type PackOutcome = { done: "posted"; txHash: Hex; epoch: bigint } | { done: "current" } | { done: "refused"; reason: string };

/** What one pressure pass did (threat model C41): every removal it made, in order, and why it stopped. */
export interface PressureOutcome {
  removed: Extract<SweepOutcome, { done: "removed" }>[];
  /**
   * room: the board holds DEMO_GUEST_CAP minus DEMO_FREE_SEATS members or fewer. limit:
   * DEMO_FREE_SEATS removals were made. unlanded: the last removal's receipt was not seen, so the
   * next could not be signed on the board's next nonce. Otherwise the step that stopped it: not_ready,
   * nothing_due (no guest left to remove) or refused, with nothing done in that step.
   */
  stopped: { done: "room" } | { done: "limit" } | { done: "unlanded" } | Exclude<SweepOutcome, { done: "removed" }>;
}

/** How a removal is chosen: "expiry" by the scheduled sweep, "pressure" by a pass freeing seats. */
type SweepMode = "expiry" | "pressure";

export const DEMO_LOCK = "demo:join";
/** The hour's challenge total for every caller, under the key `limit` kept it in, so its count carries over. */
const CHALLENGE_TOTAL_KEY = "rate:demo-challenge:all";
const LEAVE_CHALLENGE_TOTAL_KEY = "rate:demo-leave-challenge:all";
/**
 * A consumed challenge is left as a tombstone naming the join that consumed it, for a minute: longer
 * than the store client's retries of that write (three tries of at most 3 s), so the join's read-back
 * still finds it. A new challenge for the guest replaces it at once.
 */
const CONSUMED_SECONDS = 60;
const CONSUMED = /^consumed:[0-9a-f-]{36}$/;
/** An admission is recorded for ten years: "ever admitted" outlives the demo. */
const ADMITTED_SECONDS = 315_360_000;
/**
 * An admission mark: the time in milliseconds the join took it, then ":joining" while that join is
 * under way and, once its addMember is signed, that transaction's hash instead, so a mark whose
 * addMember never landed can be told apart and given up. The time alone marks a guest a board read
 * showed a member.
 */
const ADMISSION_MARK = /^(\d{1,16})(?::(0x[0-9a-f]{64}|joining))?$/;
/**
 * The mark a join holds while it is under way, before keepAdmission names its addMember: the time it
 * took it, then ":joining", so another join of the guest meanwhile is told to come back (C34).
 */
const joiningMark = (at: number): string => `${at}:joining`;
const DAY_KEY_SECONDS = 2 * 86_400;
/** Guests whose addMember was sent with no receipt seen, as a JSON array of lowercase 0x addresses, for the sweep to settle. */
const UNSETTLED_KEY = "demo:unsettled";
/**
 * A join answered without a receipt is rare, so twenty covers a stalled hour. A guest that drops off
 * a full list still has its mark settled by its own next join.
 */
const UNSETTLED_MAX = 20;
const UNSETTLED_ENTRY = /^0x[0-9a-f]{40}$/;
/**
 * How long a join's read of the board's size is kept for the next joins: five seconds. A board_full
 * answer counts nothing against anyone, so this, and one read at a time, is what keeps a flood of
 * them at a full board from becoming a flood of chain reads.
 */
const BOARD_SIZE_SECONDS = 5;
const boardSizeKey = (boardId: bigint): string => `demo:board-size:${boardId}`;
/**
 * Refusals one guest address may collect in a UTC day once it has proven its key. Every such try
 * costs the bot chain reads, so an identity that will never be admitted stops after five.
 */
const FAILED_JOINS_PER_DAY = 5;
/** The board read that settles a failed join's mark gets its own budget, inside the lock's 30 s margin. */
const MARK_READ_MS = 10_000;
const CHALLENGE_BODY_CAP = 256;
/** A join body is about 9.5 KB: the 4,627-byte signature as hex plus four short fields. */
const JOIN_BODY_CAP = 16_384;
/** The sweep has no caller. Its uploads are internal and its relays scoped "demo", so no IP is counted; this only fills the field. */
const SWEEP_CLIENT_IP = "127.0.0.1";
/** KEM lookups run a few at a time, so a sweep of 39 recipients neither crawls nor floods the RPC. */
const KEM_PARALLEL = 4;
/**
 * Sweeps in a row a member's ML-KEM lookup must come back unreadable before that member stops
 * blocking every removal and becomes one itself (threat model C42). One bad answer is the network;
 * three in a row, minutes apart, is the member's own record.
 */
const UNREADABLE_RUNS_TO_REMOVE = 3;
/** A run of unreadable lookups is forgotten a day after it started. */
const UNREADABLE_RUN_SECONDS = 86_400;
/** A block timestamp at or past this (the year 2255) is not one the chain could have written. */
const MAX_UNIX_SECONDS = 9_000_000_000n;
const DEFAULT_LIMITS: DemoLimits = { join: DEMO_JOIN_LIMITS, challenge: DEMO_CHALLENGE_LIMITS };
/** The exact bytes ensureCurrentPack encrypts. Undefined for an empty pack text, so every post is refused and nothing else changes. */
const DEMO_PACK: Uint8Array | undefined = DEMO_PACK_TEXT.length > 0 ? new TextEncoder().encode(DEMO_PACK_TEXT) : undefined;

export const challengeKey = (guest: Uint8Array): string => `demo:challenge:${bytesToHex(guest)}`;
/** A guest's live leave request, kept apart from its join challenge so neither can stand in for the other (threat model C47). */
export const leaveKey = (guest: Uint8Array): string => `demo:leave:${bytesToHex(guest)}`;
export const admittedKey = (guest: Uint8Array): string => `demo:admitted:${bytesToHex(guest)}`;
const utcDay = (now: number): string => new Date(now).toISOString().slice(0, 10);
const joinDayKey = (now: number): string => `demo:join:count:${utcDay(now)}`;
const failedJoinsKey = (guest: Uint8Array, now: number): string => `demo:failed:${bytesToHex(guest)}:${utcDay(now)}`;
const unreadableKey = (member: Hex): string => `demo:kem-unreadable:${bytesToHex(accountBytes(member))}`;

const bytes32 = z
  .string()
  .regex(/^0x[0-9a-fA-F]{64}$/)
  .transform((s) => s.toLowerCase() as Hex);
const uint64 = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/)
  .transform((s) => BigInt(s))
  .refine((n) => n <= 0xffff_ffff_ffff_ffffn);
const address = z.string().max(64);

const ChallengeBody = z.strictObject({ guest: address });
/**
 * The join body. Any other field (a mode, an epoch, an envelope, a board id) is dropped and never
 * read: the bot builds everything it signs from its own reads (threat model C33).
 */
const JoinBody = z.object({
  guest: address,
  botNonce: bytes32,
  expiry: uint64,
  signature: z
    .string()
    .regex(/^0x[0-9a-fA-F]{9254}$/)
    .transform((s) => hexToBytes(s as Hex)),
});
/** A stored challenge, checked as an input when it is read back. */
const StoredChallenge = z.strictObject({ botNonce: bytes32, expiry: uint64 });

type Fields = Record<string, string | number | boolean>;

/** A step that cannot go on, as the bot reports it: its own stop, running out of time, or anything else. */
function asStop(error: unknown, fallback: string): DemoStop {
  if (error instanceof DemoStop) return error;
  if (error instanceof OutOfTime) return new DemoStop(503, "out_of_time");
  return new DemoStop(502, fallback);
}

function refusal(status: number, reason: string, fields: Fields = {}, headers: Record<string, string> = {}): Response {
  logEvent("demo_refused", { reason, status, ...fields });
  return refuse(status, reason, headers);
}

function untilTomorrow(now: number): string {
  const next = new Date(now);
  next.setUTCHours(24, 0, 0, 0);
  return String(Math.max(1, Math.ceil((next.getTime() - now) / 1000)));
}

/** Seconds until the next UTC clock hour, when reserveDemoRelays counts afresh. */
function untilNextHour(now: number): string {
  return String(Math.max(1, Math.ceil((3_600_000 - (now % 3_600_000)) / 1000)));
}

const nowSeconds = (now: number): bigint => BigInt(Math.floor(now / 1000));

async function readCount(store: SharedStore, key: string): Promise<number> {
  const raw = await store.get(key);
  if (raw === null) return 0;
  if (!/^\d{1,15}$/.test(raw)) throw new Error("A demo counter holds an unexpected value.");
  return Number(raw);
}

/** Read under the lock before the hour's relay is reserved, so a join the day cannot take reserves nothing (C33). */
async function requireDayLeft(ctx: DemoContext, perDay: number): Promise<void> {
  let joins: number;
  try {
    joins = await readCount(ctx.store, joinDayKey(ctx.now));
  } catch {
    throw new DemoStop(503, "store_unavailable");
  }
  if (joins >= perDay) throw new DemoStop(503, "daily_limit");
}

/**
 * Takes the join from the day right before its addMember is relayed, and never earlier, so a join
 * refused at any check before this takes nothing. Only the "demo:join" lock holder writes here.
 */
async function countJoin(ctx: DemoContext, perDay: number): Promise<void> {
  let joins: number;
  try {
    joins = await ctx.store.incrWindow(joinDayKey(ctx.now), DAY_KEY_SECONDS);
  } catch {
    throw new DemoStop(503, "store_unavailable");
  }
  if (joins > perDay) throw new DemoStop(503, "daily_limit");
}

/**
 * A refusal the guest caused: a 4xx other than 429, such as no_kem_key, bad_kem_key, already_member
 * or already_admitted. A 5xx or a 429 is the service's own state (the lock, the day, the store, the
 * chain, the relay) and never counts, so a judge is not locked out for the service's trouble.
 */
const guestCaused = (status: number): boolean => status >= 400 && status < 500 && status !== 429;

async function countFailure(store: SharedStore, guest: Uint8Array, now: number, fields: Fields): Promise<void> {
  await store.incrWindow(failedJoinsKey(guest, now), DAY_KEY_SECONDS).catch(() => logEvent("demo_failure_uncounted", fields));
}

async function readJson(request: Request, cap: number): Promise<{ value: unknown } | { response: Response }> {
  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") return { response: refusal(415, "json_only") };
  const stated = declaredLength(request);
  if (stated !== undefined && stated > cap) return { response: refusal(413, "body_too_large") };
  if (request.body === null) return { response: refusal(400, "bad_body") };
  try {
    return { value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBody(request.body, cap))) };
  } catch (error) {
    if (error instanceof BodyTimeout) return { response: refusal(408, "body_timeout") };
    return { response: error instanceof TooLarge ? refusal(413, "body_too_large") : refusal(400, "bad_body") };
  }
}

/** The guest's 20 bytes by the strict shared codec (C16), or undefined for anything else, the zero account included. */
function guestBytes(input: string): Uint8Array | undefined {
  try {
    const bytes = accountBytesStrict(input);
    return bytes.every((b) => b === 0) ? undefined : bytes;
  } catch {
    return undefined;
  }
}

function freshNonce(): Hex {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
  if (bytes.every((b) => b === 0)) throw new Error("The random source returned only zero bytes. Refusing to use it.");
  return bytesToHex(bytes);
}

/** What a signed request is for. Each purpose has its own message, its own record and its own counters. */
interface Purpose {
  scope: string;
  totalKey: string;
  key: (guest: Uint8Array) => string;
  message: typeof challengeMessage;
}
const JOIN: Purpose = { scope: "demo-challenge", totalKey: CHALLENGE_TOTAL_KEY, key: challengeKey, message: challengeMessage };
const LEAVE: Purpose = { scope: "demo-leave-challenge", totalKey: LEAVE_CHALLENGE_TOTAL_KEY, key: leaveKey, message: leaveMessage };

function challengeAnswer(purpose: Purpose, boardId: bigint, guest: Uint8Array, record: { botNonce: Hex; expiry: bigint }): Response {
  const message = purpose.message({ registry: REGISTRY_ADDRESS, boardId, guest: toHex(guest), botNonce: record.botNonce, expiry: record.expiry });
  return json(200, { registry: REGISTRY_ADDRESS, boardId: boardId.toString(), botNonce: record.botNonce, expiry: record.expiry.toString(), message: bytesToHex(message) });
}

/**
 * Issues the guest challenge the demo bot will check before it admits anyone (threat model C33).
 *
 * POST `{ guest }` as JSON, any address form the shared codec accepts. Answers 200 `{ registry,
 * boardId, botNonce, expiry, message }`: a fresh 32-byte botNonce, an expiry DEMO_CHALLENGE_SECONDS
 * (300 s) ahead in unix seconds, and `message`, the exact 224 bytes from challengeMessage the guest
 * signs with its registered ML-DSA-87 key, so the browser signs what the bot will check. The record
 * lives under "demo:challenge:<guest>" for 300 s; one live challenge per guest, so a second request
 * while it lives gets the same challenge back. One a join has consumed (its tombstone) is replaced
 * by a fresh one at once.
 *
 * First of all, a request another site's page could have sent is refused with 403 cross_site
 * (refuseCrossSite), before anything is counted or read. Then refuses with 405 for another method,
 * 503 not_ready before the board is seeded, 429 over this IP's hourly limit (every /64 of one IPv6
 * /48 also sharing 4 times it, countClient), 415, 413 and 400 for a body that is not exactly
 * `{ guest }` with a valid non-zero address, 408 body_timeout for a body that has not ended after 20
 * seconds, 429 over the hourly total for every caller, counted only once the body has passed, so
 * junk never uses up anyone else's room, and 503 when the shared store fails.
 */
export function handleDemoChallenge(request: Request, ctx: DemoContext): Promise<Response> {
  return issue(request, ctx, JOIN);
}

/**
 * Issues the request a guest signs to leave the demo board (threat model C47). The same checks,
 * limits and answers as handleDemoChallenge, under its own counters, with `message` the 224 bytes
 * of leaveMessage and the record under "demo:leave:<guest>". A join challenge and a leave request
 * for one guest are separate records with separate nonces, and their bytes carry different tags.
 */
export function handleDemoLeaveChallenge(request: Request, ctx: DemoContext): Promise<Response> {
  return issue(request, ctx, LEAVE);
}

/** Issues one signed-request record for a purpose: a join challenge or a leave request. The checks are the same; the bytes, the record and the counters are the purpose's own. */
async function issue(request: Request, ctx: DemoContext, purpose: Purpose): Promise<Response> {
  const crossSite = refuseCrossSite(request);
  if (crossSite !== undefined) return crossSite;
  if (request.method !== "POST") return refusal(405, "method_not_allowed", {}, { allow: "POST" });
  const boardId = ctx.env.DEMO_BOARD_ID;
  if (boardId === undefined) return refusal(503, "not_ready");
  const rules = (ctx.limits ?? DEFAULT_LIMITS).challenge;
  const retry = { "retry-after": String(rules.windowSeconds) };
  // Junk counts against its own IP (and /48), and against everyone's total only once its body is valid.
  const client = await countClient(ctx.store, { scope: purpose.scope, clientIp: ctx.clientIp, perIp: rules.perIp, windowSeconds: rules.windowSeconds });
  if (!client.ok) return refusal(429, "rate_limited", { limit: client.refusedBy ?? "per_ip" }, retry);

  const read = await readJson(request, CHALLENGE_BODY_CAP);
  if ("response" in read) return read.response;
  const checked = ChallengeBody.safeParse(read.value);
  const guest = checked.success ? guestBytes(checked.data.guest) : undefined;
  if (guest === undefined) return refusal(400, "bad_guest");
  let total: number;
  try {
    total = await ctx.store.incrWindow(purpose.totalKey, rules.windowSeconds);
  } catch {
    return refusal(503, "store_unavailable");
  }
  if (total > rules.total) return refusal(429, "rate_limited", { limit: "total" }, retry);

  const record = { botNonce: freshNonce(), expiry: nowSeconds(ctx.now) + BigInt(DEMO_CHALLENGE_SECONDS) };
  const fresh = JSON.stringify({ botNonce: record.botNonce, expiry: record.expiry.toString() });
  const key = purpose.key(guest);
  try {
    if (await ctx.store.setIfAbsent(key, fresh, DEMO_CHALLENGE_SECONDS)) return challengeAnswer(purpose, boardId, guest, record);
    // A write that landed but lost its reply reads back as this fresh challenge, which is live.
    const held = await ctx.store.get(key);
    const live = parseChallenge(held);
    if (live !== undefined && live.expiry > nowSeconds(ctx.now)) return challengeAnswer(purpose, boardId, guest, live);
    if (held !== null && CONSUMED.test(held)) {
      if ((await ctx.store.compareAndSet(key, held, fresh, DEMO_CHALLENGE_SECONDS)) || (await ctx.store.get(key)) === fresh) return challengeAnswer(purpose, boardId, guest, record);
    }
  } catch {
    return refusal(503, "store_unavailable");
  }
  return refusal(503, "busy", {}, { "retry-after": "1" });
}

function parseChallenge(raw: string | null): { botNonce: Hex; expiry: bigint } | undefined {
  if (raw === null) return undefined;
  try {
    const parsed = StoredChallenge.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

/** The demo chair's keys, loaded here and only by the bot's own functions (threat model C37). */
async function demoChair(env: DemoContext["env"]): Promise<Identity> {
  return identityFromMnemonic(requireDemoChairMnemonic(env));
}

/** The board at the latest block, with the bot's own key checked to be its chair. */
async function readOwnBoard(ctx: DemoSweepContext, boardId: bigint, chair: Identity, deadline: Deadline): Promise<BoardSnapshot> {
  let snapshot: BoardSnapshot;
  try {
    snapshot = await within(deadline, ctx.chain.board(boardId), "reading the demo board");
  } catch {
    throw new DemoStop(502, "chain_unreachable");
  }
  if (!sameAccount(snapshot.chair, chair.evm)) throw new DemoStop(503, "not_chair");
  return snapshot;
}

/**
 * Every relay the bot makes runs in scope "demo" (threat model C41): it books on the bot's own daily
 * share and is never counted against the IP that asked for the join, so a guest's own junk traffic
 * cannot make the bot's own addMember or removeMember fail. `onSigned` goes to the relay as is.
 */
function relayContext(ctx: DemoSweepContext, clientIp: string, onSigned?: RelayContext["onSigned"]): RelayContext {
  return { clientIp, now: ctx.now, store: ctx.store, relayer: ctx.relayer, chain: ctx.relayChain, clock: ctx.clock, sleep: ctx.sleep, scope: "demo", ...(onSigned === undefined ? {} : { onSigned }) };
}

/**
 * Relays one signed action and waits, within the deadline, for it to land, so the next queued
 * action reads the moved board nonce. `onSigned` runs inside the relay once the transaction is
 * signed, before its broadcast; if it throws, nothing is sent.
 *
 * @returns The hash and whether its receipt was seen. `sent` is true from the moment the relay may
 *   have broadcast it and stays true through a revert, because a copy of the same signed action
 *   may have landed first (threat model C34): only a board read can say what happened.
 */
async function relayAndWait(
  ctx: DemoSweepContext,
  clientIp: string,
  body: Parameters<typeof relayAction>[0],
  deadline: Deadline,
  sent: { value: boolean },
  onSigned?: RelayContext["onSigned"],
): Promise<{ txHash: Hex; landed: boolean }> {
  if (elapsedMs(deadline) > DEMO_RELAY_CUTOFF_MS) throw new DemoStop(503, "out_of_time");
  const outcome = await relayAction(body, relayContext(ctx, clientIp, onSigned));
  if (outcome.txHash === undefined) {
    // Only a lost broadcast can have reached the chain; every other relay refusal sent nothing.
    sent.value = outcome.error === "broadcast_failed";
    if (sent.value) await forgetBoardSize(ctx);
    throw new DemoStop(outcome.status === 429 || outcome.status === 503 ? outcome.status : 502, `relay_${outcome.error ?? "unknown"}`);
  }
  sent.value = true;
  const status = await ctx.chain.receipt(outcome.txHash, Math.floor(Math.min(DEMO_RECEIPT_WAIT_MS, leftMs(deadline)))).catch(() => undefined);
  await forgetBoardSize(ctx);
  if (status === "reverted") throw new DemoStop(502, "reverted");
  return { txHash: outcome.txHash, landed: status === "success" };
}

/** Set by the one join that reads the board to store its size, for as long as a stored size lives. */
const readingKey = (boardId: bigint): string => `${boardSizeKey(boardId)}:reading`;

/**
 * Whether the demo board holds DEMO_GUEST_CAP members or more, by a read of the board at most
 * BOARD_SIZE_SECONDS old (threat model C41), for the check a join makes before anything else. Only
 * a full size is stored and believed: a size under the cap goes stale as soon as an add lands, and
 * one whose broadcast reply was lost can land seconds after the join that sent it has answered, so a
 * join that met a full board would be counted on it. A join that finds no full size stored reads
 * the board itself; the one that holds the reading flag also stores what it read when it is full,
 * so joins answered board_full cost one board read every few seconds, plus one for each join that
 * arrives while that read is under way. No join skips the check. A store or chain failure answers
 * undefined: the join goes on, counted, to the check under the lock, which stays the one that decides.
 *
 * @returns The answer, and whether this call read the chain for it.
 */
async function boardFull(ctx: DemoContext, boardId: bigint, deadline: Deadline): Promise<{ full: boolean | undefined; read: boolean }> {
  const key = boardSizeKey(boardId);
  try {
    const stored = await ctx.store.get(key);
    if (stored !== null && /^\d{1,4}$/.test(stored) && Number(stored) >= DEMO_GUEST_CAP) return { full: true, read: false };
    const storing = await ctx.store.setIfAbsent(readingKey(boardId), "1", BOARD_SIZE_SECONDS);
    const size = (await within(deadline, ctx.chain.board(boardId), "reading the demo board")).members.length;
    if (storing && size >= DEMO_GUEST_CAP) await ctx.store.setIfAbsent(key, String(size), BOARD_SIZE_SECONDS);
    return { full: size >= DEMO_GUEST_CAP, read: true };
  } catch {
    return { full: undefined, read: false };
  }
}

/**
 * Forgets the stored board size and the reading flag after a relay that may change the members, so
 * the next join reads the board afresh and stores what it read.
 */
async function forgetBoardSize(ctx: DemoSweepContext): Promise<void> {
  const boardId = ctx.env.DEMO_BOARD_ID;
  if (boardId === undefined) return;
  try {
    await ctx.store.delete(boardSizeKey(boardId));
    await ctx.store.delete(readingKey(boardId));
  } catch {
    logEvent("demo_board_size_kept", {});
  }
}

/**
 * The guest's recipient pair, looked up and checked before anything is counted or locked for the
 * join (threat model C15, C33, C41), so a guest the bot could never seal to costs nothing. A pair
 * naming another account is the lookup's fault, not the guest's.
 */
async function kemKeyFor(ctx: DemoSweepContext, account: Hex, deadline: Deadline): Promise<KemRecipient> {
  let recipient: KemRecipient;
  try {
    recipient = await within(deadline, ctx.chain.kemKey(account), "the KEM lookup");
  } catch (error) {
    if (error instanceof KemKeyUnavailable && error.reason === "NOT_FOUND") throw new DemoStop(403, "no_kem_key");
    if (error instanceof KemKeyUnavailable && (error.reason === "INVALID_KEY" || error.reason === "WRONG_ALGORITHM")) throw new DemoStop(403, "bad_kem_key");
    throw asStop(error, "kem_unavailable");
  }
  if (!pairFor(recipient, account)) throw new DemoStop(502, "kem_unavailable");
  try {
    validateMlkemPublicKey(recipient.kemPublicKey);
  } catch {
    throw new DemoStop(403, "bad_kem_key");
  }
  return recipient;
}

/** Whether the lookup's answer is a pair for exactly the account asked about, checked like an input before it reaches a seal. */
function pairFor(recipient: KemRecipient, account: Hex): boolean {
  try {
    return typeof recipient.address === "string" && recipient.kemPublicKey instanceof Uint8Array && sameAccount(recipient.address, account);
  } catch {
    return false;
  }
}

/**
 * Refuses a guest whose ML-KEM key is byte-equal to one a current member has published (threat
 * model C15, C42), before the day, the lock or any removal: a seal takes each key once, so such a
 * guest could only be removed again, after taking a seat from someone. Only members whose lookup
 * succeeded are compared. A member whose lookup is unreadable is skipped and the join goes on,
 * because one member's record must not stop every join, and the sweep is the backstop: a copier
 * that slips in is marked key_shared by memberKeys at the next sweep or pressure pass, removed first
 * and left out of the reseal, so the board is never frozen.
 *
 * @throws DemoStop 403 key_shared, 502 chain_unreachable when the board cannot be read.
 */
async function refuseSharedKey(ctx: DemoContext, boardId: bigint, guest: Uint8Array, key: Uint8Array, deadline: Deadline): Promise<void> {
  let members: readonly Hex[];
  try {
    members = (await within(deadline, ctx.chain.board(boardId), "reading the demo board")).members;
  } catch {
    throw new DemoStop(502, "chain_unreachable");
  }
  // The guest's own seat, if it has one, is for admit to refuse as already_member.
  const looked = await lookUpKeys(ctx, members.filter((m) => !sameAccount(m, guest)), deadline);
  const mine = bytesToHex(key);
  if (looked.some((k) => "recipient" in k && bytesToHex(k.recipient.kemPublicKey) === mine)) throw new DemoStop(403, "key_shared");
}

/** One join once the guest has passed every check it can fail: what the admission under the lock works from. */
interface Join {
  boardId: bigint;
  guest: Uint8Array;
  recipient: KemRecipient;
  perDay: number;
}

/**
 * Takes one of this clock hour's demo relays for the join's addMember, before anything is opened,
 * sealed or uploaded for it (threat model C41). Nothing is given back if a later step stops the join.
 *
 * @throws DemoStop 503 demo_busy when the hour has none left.
 */
async function reserveRelay(ctx: DemoSweepContext): Promise<void> {
  if (!(await reserveDemoRelays(ctx.store, ctx.now, 1))) throw new DemoStop(503, "demo_busy");
}

/** Set under the lock when the board needs a pressure pass, which the join schedules once the lock is released. */
type PressureDue = { value: boolean };

/** The admission itself, under the "demo:join" lock. One relay, and it never removes anyone (C41). */
async function admit(ctx: DemoContext, join: Join, deadline: Deadline, sent: { value: boolean }, pressure: PressureDue): Promise<Response> {
  const guestHex = toHex(join.guest);
  const chair = await demoChair(ctx.env);
  const snapshot = await readOwnBoard(ctx, join.boardId, chair, deadline);
  if (snapshot.members.some((m) => sameAccount(m, join.guest))) throw new DemoStop(409, "already_member");
  await requireDayLeft(ctx, join.perDay);
  // A judge at a full board is told to come back in seconds, never seated by evicting someone: a
  // two-step join could stop between its removal and its addition and cost a guest its seat for nothing.
  if (snapshot.members.length >= DEMO_GUEST_CAP) {
    pressure.value = true;
    throw new DemoStop(503, "board_full");
  }
  await reserveRelay(ctx);

  const epochKey = await openCurrentEpochKey({
    snapshot,
    sealKeys: chair.seal,
    blobs: ctx.blobs,
    blobOrigin: ctx.env.BLOB_ORIGIN,
    signal: AbortSignal.timeout(Math.max(1, Math.floor(leftMs(deadline)))),
  });
  let envelope: Uint8Array;
  try {
    envelope = sealEpochKey({ registry: REGISTRY_ADDRESS, boardRef: snapshot.boardRef, epoch: snapshot.epoch, epochKey, recipients: [join.recipient] });
  } finally {
    epochKey.fill(0);
  }
  const uploaded = await within(deadline, uploadEnvelope(envelope, { clientIp: ctx.clientIp, now: ctx.now, store: ctx.store, blobs: ctx.blobs, blobOrigin: ctx.env.BLOB_ORIGIN, internal: "demo-bot" }), "the envelope upload");
  const body = signedAction(chair, snapshot, {
    kind: "add",
    member: guestHex,
    mode: Mode.SEAL_CURRENT,
    envelopeHash: uploaded.hash,
    envelopeSize: uploaded.size,
    epochAfter: snapshot.epoch,
  });
  await countJoin(ctx, join.perDay);
  const { txHash, landed } = await relayAndWait(ctx, ctx.clientIp, body, deadline, sent, (signed) => keepAdmission(ctx.store, join.guest, ctx.now, signed));
  if (!landed) await noteUnsettled(ctx.store, join.guest);
  pressure.value = snapshot.members.length + 1 > DEMO_GUEST_CAP - DEMO_FREE_SEATS;
  logEvent("demo_admitted", { boardId: join.boardId.toString(), guest: guestHex, epoch: snapshot.epoch.toString(), txHash });
  return json(202, { txHash });
}

/**
 * Makes the guest's admission mark permanent and names the addMember's transaction in it, in one
 * compare-and-set from this join's own value, inside the relay once the transaction is signed and
 * before its broadcast (threat model C34). Until then the mark lives only as long as the lock, so a
 * join that stops with nothing sent and then fails to take its mark back locks the guest out for
 * 150 s at most, never for good; and a permanent mark always names the one addMember that can
 * seat its guest, so it can be given up once that transaction can no longer land.
 *
 * @throws When the mark is no longer this join's or cannot be written, so nothing is broadcast.
 */
async function keepAdmission(store: SharedStore, guest: Uint8Array, at: number, txHash: Hex): Promise<void> {
  const key = admittedKey(guest);
  const next = `${at}:${txHash}`;
  if (await store.compareAndSet(key, joiningMark(at), next, ADMITTED_SECONDS)) return;
  // A retried write that had already landed reads back as this one.
  if ((await store.get(key)) === next) return;
  throw new Error("The admission mark is no longer this join's.");
}

/**
 * The time a stored admission mark holds, and the addMember it names or whether a join holding it is
 * still under way, read as an input; undefined for a value in no form this file writes.
 */
function readAdmission(raw: string): { at: number; txHash?: Hex; joining?: true } | undefined {
  const parts = ADMISSION_MARK.exec(raw);
  const at = Number(parts?.[1]);
  if (parts === null || !Number.isSafeInteger(at)) return undefined;
  if (parts[2] === undefined) return { at };
  return parts[2] === "joining" ? { at, joining: true } : { at, txHash: parts[2] as Hex };
}

/** Whether a read of the board at the latest block shows the guest a member. Throws when the read fails. */
async function isMember(ctx: DemoSweepContext, boardId: bigint, guest: Uint8Array, deadline: Deadline): Promise<boolean> {
  return (await within(deadline, ctx.chain.board(boardId), "reading the demo board")).members.some((m) => sameAccount(m, guest));
}

/**
 * What an admission mark means for its guest (threat model C34): "held" while it keeps the guest
 * out, "stale" once the addMember it names can no longer seat the guest, "unsure" while that
 * cannot be told yet. A mark a join still under way holds (joiningMark) is unsure: that join may yet
 * seat the guest, or stop and take it back. A mark that names no transaction is held: a guest a
 * board read showed a member. One that names the guest's addMember is stale only when the guest
 * is not a member and the relayer's txStatus says that transaction does not exist or reverted, or
 * says it landed and its receipt says it reverted. A member, a receipt of success, or a value in no
 * form this file writes, is held; a pending transaction, a landed one whose receipt is not seen,
 * or a read that fails or cannot say, is unsure.
 *
 * @param member Whether the guest sits on the board; it may throw, which reads as unsure.
 */
async function admissionStanding(ctx: DemoSweepContext, raw: string, member: () => Promise<boolean>, deadline: Deadline): Promise<"held" | "stale" | "unsure"> {
  const mark = readAdmission(raw);
  if (mark?.joining === true) return "unsure";
  const txHash = mark?.txHash;
  if (txHash === undefined) return "held";
  try {
    if (await member()) return "held";
    if (ctx.relayChain.txStatus === undefined) return "unsure";
    const status = await within(deadline, ctx.relayChain.txStatus("evm", txHash), "looking up an admission's addMember");
    if (status === "unknown" || status === "reverted") return "stale";
    if (status !== "landed") return "unsure";
    // "landed" also covers a block whose receipt was not there to read, so the receipt decides.
    const receipt = await ctx.chain.receipt(txHash, Math.floor(Math.min(MARK_READ_MS, leftMs(deadline))));
    return receipt === "reverted" ? "stale" : receipt === "success" ? "held" : "unsure";
  } catch {
    return "unsure";
  }
}

/** The guests UNSETTLED_KEY lists, read as an input: anything but an array of at most UNSETTLED_MAX lowercase 0x addresses reads as none. */
function parseUnsettled(raw: string | null): Hex[] {
  if (raw === null) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length <= UNSETTLED_MAX && parsed.every((entry) => typeof entry === "string" && UNSETTLED_ENTRY.test(entry))) return parsed as Hex[];
  } catch {
    // Read as none below; the next write replaces it.
  }
  return [];
}

/**
 * Lists the guest for the scheduled sweep to settle (settleAdmissions), after its addMember was
 * sent with no receipt seen, by compare-and-set under the "demo:join" lock. Past UNSETTLED_MAX the
 * oldest entry drops off, and that guest's own next join still settles its mark. A store failure
 * is logged and leaves the same to the guest's next join.
 */
async function noteUnsettled(store: SharedStore, guest: Uint8Array): Promise<void> {
  const id = bytesToHex(guest);
  try {
    const held = await store.get(UNSETTLED_KEY);
    const listed = parseUnsettled(held);
    if (listed.includes(id)) return;
    const next = JSON.stringify([...listed, id].slice(-UNSETTLED_MAX));
    if ((await store.compareAndSet(UNSETTLED_KEY, held, next, ADMITTED_SECONDS)) || (await store.get(UNSETTLED_KEY)) === next) return;
  } catch {
    // Logged below.
  }
  logEvent("demo_unsettled_unlisted", { guest: toHex(guest) });
}

/**
 * Settles each admission noteUnsettled listed, under the "demo:join" lock (threat model C34): a
 * guest whose mark admissionStanding finds stale loses it, so a judge whose addMember never landed
 * is free to join again; a guest whose mark is held or gone leaves the list; an unsure one stays
 * for the next sweep. Never throws: a store failure leaves the list for the next sweep.
 */
async function settleAdmissions(ctx: DemoSweepContext, snapshot: BoardSnapshot, deadline: Deadline): Promise<void> {
  try {
    const held = await ctx.store.get(UNSETTLED_KEY);
    const listed = parseUnsettled(held);
    if (listed.length === 0) return;
    const left: Hex[] = [];
    for (const id of listed) {
      const guest = hexToBytes(id);
      const key = admittedKey(guest);
      const mark = await ctx.store.get(key);
      if (mark === null) continue;
      const seated = snapshot.members.some((m) => sameAccount(m, guest));
      const standing = await admissionStanding(ctx, mark, async () => seated, deadline);
      if (standing === "unsure") left.push(id);
      if (standing === "stale" && (await ctx.store.get(key)) === mark) {
        await ctx.store.delete(key);
        logEvent("demo_mark_released", { guest: toHex(guest), reason: "addmember_lost" });
      }
    }
    await ctx.store.compareAndSet(UNSETTLED_KEY, held, JSON.stringify(left), ADMITTED_SECONDS);
  } catch {
    logEvent("demo_unsettled_unchecked", {});
  }
}

/**
 * Writes the guest's admission record as `at`, over whatever it holds, so an admitted guest always
 * has the time its six hours run from.
 */
async function recordAdmission(store: SharedStore, guest: Uint8Array, at: number): Promise<void> {
  const key = admittedKey(guest);
  const held = await store.get(key);
  if (held === String(at)) return;
  const wrote = held === null ? await store.setIfAbsent(key, String(at), ADMITTED_SECONDS) : await store.compareAndSet(key, held, String(at), ADMITTED_SECONDS);
  if (!wrote) throw new Error("The admission record changed while it was written.");
}

/**
 * After a join failed: with nothing sent the mark is taken back. After a send (a revert or a lost
 * broadcast included) the board is read again, and the mark goes only when that read shows the
 * guest is not a member (threat model C34). A guest who is a member keeps it, dated now. A read
 * that fails keeps it as it is, because a guest who may hold a seat must not be admitted twice.
 */
async function settleMark(ctx: DemoContext, join: Join, sent: boolean, fields: Fields): Promise<void> {
  const key = admittedKey(join.guest);
  if (!sent) {
    await ctx.store.delete(key).catch(() => logEvent("demo_mark_release_failed", fields));
    return;
  }
  let member: boolean;
  try {
    // The join's own deadline may be spent by now; the lock outlives it by 30 s, room for this read.
    const snapshot = await within(startDeadline(MARK_READ_MS, ctx.clock), ctx.chain.board(join.boardId), "reading the demo board");
    member = snapshot.members.some((m) => sameAccount(m, join.guest));
  } catch {
    logEvent("demo_mark_kept", { ...fields, reason: "board_unreadable" });
    await noteUnsettled(ctx.store, join.guest);
    return;
  }
  try {
    if (member) await recordAdmission(ctx.store, join.guest, ctx.now);
    else await ctx.store.delete(key);
    logEvent(member ? "demo_mark_kept" : "demo_mark_released", { ...fields, reason: "board_read" });
  } catch {
    logEvent("demo_mark_unsettled", { ...fields, member });
  }
}

/**
 * A mark whose addMember cannot yet be told landed or dead (admissionStanding "unsure"): the guest
 * is asked to come back in seconds, and the answer is a 503, so nothing counts against it (C34).
 */
const admissionUnsettled = (fields: Fields): Response => refusal(503, "admission_unsettled", fields, { "retry-after": "30" });

/**
 * Takes the once-per-guest mark for this join, for the lock's lifetime (threat model C34). A mark
 * already there gives way only when admissionStanding finds it stale, and only here, under the
 * "demo:join" lock, so no earlier join of this guest is still between its broadcast and its receipt.
 *
 * @returns true once the mark is this join's; false while the guest's mark holds; "unsure" while
 *   the addMember the mark names cannot be told landed or dead, and the mark is kept.
 * @throws When the store fails.
 */
async function takeAdmission(ctx: DemoContext, join: Join, deadline: Deadline, fields: Fields): Promise<boolean | "unsure"> {
  const key = admittedKey(join.guest);
  // Two joins of one guest can both get here, the second on a challenge issued once the first was
  // consumed, but the lock serialises them and their marks hold different arrival times, so a value
  // read back equal to this one is this join's own write.
  const mine = joiningMark(ctx.now);
  if (await claimOnce(ctx.store, key, mine, DEMO_LOCK_TTL_SECONDS)) return true;
  const held = await ctx.store.get(key);
  if (held !== null) {
    const standing = await admissionStanding(ctx, held, () => isMember(ctx, join.boardId, join.guest, deadline), deadline);
    if (standing === "unsure") return "unsure";
    if (standing === "held") return false;
    if ((await ctx.store.get(key)) !== held) return false;
    await ctx.store.delete(key);
    logEvent("demo_mark_released", { ...fields, reason: "addmember_lost" });
  }
  return claimOnce(ctx.store, key, mine, DEMO_LOCK_TTL_SECONDS);
}

/**
 * The once-per-guest mark, held for the lock's lifetime until keepAdmission makes it permanent just
 * before the broadcast, then the admission; after a failure, settleMark decides whether the mark stays.
 */
async function joinOnce(ctx: DemoContext, join: Join, deadline: Deadline, pressure: PressureDue): Promise<Response> {
  const fields: Fields = { guest: toHex(join.guest) };
  let taken: boolean | "unsure";
  try {
    taken = await takeAdmission(ctx, join, deadline, fields);
  } catch {
    return refusal(503, "store_unavailable", fields);
  }
  if (taken === "unsure") return admissionUnsettled(fields);
  if (!taken) return refusal(409, "already_admitted", fields);
  const sent = { value: false };
  try {
    return await admit(ctx, join, deadline, sent, pressure);
  } catch (error) {
    await settleMark(ctx, join, sent.value, fields);
    const stop = asStop(error, "join_failed");
    const retry: Record<string, string> =
      stop.reason === "daily_limit"
        ? { "retry-after": untilTomorrow(ctx.now) }
        : stop.reason === "demo_busy"
          ? { "retry-after": untilNextHour(ctx.now) }
          : stop.status === 503 || stop.status === 429
            ? { "retry-after": "30" }
            : {};
    return refusal(stop.status, stop.reason, fields, retry);
  }
}

/**
 * Everything after the guest's signature passed. From here the address is proven to be the
 * guest's own, so the caller counts each refusal the guest caused against it.
 */
async function joinProven(ctx: DemoContext, proven: { boardId: bigint; guest: Uint8Array; challenge: string; perDay: number }, deadline: Deadline, fields: Fields): Promise<Response> {
  const { boardId, guest, perDay } = proven;
  // Only a join that proves the challenge consumes it (threat model C43), so a stranger naming this
  // guest cannot cancel it. It moves the exact value it checked to a tombstone with its own token,
  // so of two racing joins exactly one lands, and a retried write that landed reads back as its own.
  const key = challengeKey(guest);
  const consumed = `consumed:${randomUUID()}`;
  try {
    if (!(await ctx.store.compareAndSet(key, proven.challenge, consumed, CONSUMED_SECONDS)) && (await ctx.store.get(key)) !== consumed) {
      return refusal(409, "no_challenge", fields);
    }
  } catch {
    return refusal(503, "store_unavailable", fields);
  }

  let mark: string | null;
  try {
    mark = await ctx.store.get(admittedKey(guest));
  } catch {
    return refusal(503, "store_unavailable", fields);
  }
  // A mark whose addMember can no longer land goes on to the lock, where takeAdmission gives it up.
  if (mark !== null) {
    const standing = await admissionStanding(ctx, mark, () => isMember(ctx, boardId, guest, deadline), deadline);
    if (standing === "held") return refusal(409, "already_admitted", fields);
    if (standing === "unsure") return admissionUnsettled(fields);
  }

  let recipient: KemRecipient;
  try {
    recipient = await kemKeyFor(ctx, toHex(guest), deadline);
    await refuseSharedKey(ctx, boardId, guest, recipient.kemPublicKey, deadline);
  } catch (error) {
    const stop = asStop(error, "kem_unavailable");
    return refusal(stop.status, stop.reason, fields, stop.status === 503 ? { "retry-after": "30" } : {});
  }

  try {
    if ((await readCount(ctx.store, joinDayKey(ctx.now))) >= perDay) {
      return refusal(503, "daily_limit", { ...fields, limit: "per_day" }, { "retry-after": untilTomorrow(ctx.now) });
    }
  } catch {
    return refusal(503, "store_unavailable", fields);
  }

  const join: Join = { boardId, guest, recipient, perDay };
  const pressure: PressureDue = { value: false };
  const waitMs = Math.floor(Math.max(0, Math.min(DEMO_LOCK_WAIT_MS, DEMO_RELAY_CUTOFF_MS - elapsedMs(deadline))));
  let response: Response;
  try {
    response = await ctx.store.withLock(DEMO_LOCK, DEMO_LOCK_TTL_SECONDS, () => joinOnce(ctx, join, deadline, pressure), { waitMs });
  } catch (error) {
    response = error instanceof LockBusy ? refusal(503, "busy", fields, { "retry-after": "30" }) : refusal(503, "store_unavailable", fields);
  }
  // Only once the lock is released, so the background work never waits on the join that asked for it.
  const passed = pressure.value && (await schedulePressure(ctx));
  if (response.status === 202 && !passed) schedulePack(ctx);
  return response;
}

/**
 * The mark that a pressure pass is scheduled or running, holding that pass's own token (threat
 * model C41). Passes never pile up behind a full board: each makes some 40 KEM lookups and as many
 * store writes before its first removal can be refused.
 */
export const PASS_KEY = "demo:pass";
/**
 * How long the pass mark holds unless renewed: the longest one removal can take (the lock wait and
 * the lock's whole life) and ten seconds for the store calls around it. A pass renews it before each
 * removal, so one that died lets the next start within this.
 */
const PASS_STEP_SECONDS = Math.ceil(DEMO_LOCK_WAIT_MS / 1000) + DEMO_LOCK_TTL_SECONDS + 10;

/**
 * Claims the pass mark for a new pass with a fresh token, read back on a no (claimOnce).
 * @returns The token, or undefined while another pass holds the mark. @throws When the store fails.
 */
async function claimPass(store: SharedStore): Promise<string | undefined> {
  const token = randomUUID();
  return (await claimOnce(store, PASS_KEY, token, PASS_STEP_SECONDS)) ? token : undefined;
}

/** Releases the pass mark if it is still this pass's. A failure is logged; the mark then ends within PASS_STEP_SECONDS. */
async function releasePass(store: SharedStore, token: string): Promise<void> {
  try {
    if ((await store.get(PASS_KEY)) === token) await store.delete(PASS_KEY);
  } catch {
    logEvent("demo_pass_kept", {});
  }
}

/**
 * Hands one pressure pass, then one ensureCurrentPack, to the caller's background runner (threat
 * model C41), unless a pass is already scheduled or running: it claims the pass mark first, and the
 * pass releases it when done. Both run on the join's wall clock, or Date.now, so each removal and
 * the post run on the time they run at and not on the join's arrival. The work answers the pass's
 * PressureOutcome, with `pack` added whenever ensureCurrentPack did more than find the current
 * epoch's pack in place. Without a runner nothing is scheduled and the scheduled sweep does the
 * work. A store failure or a runner that throws is logged, and the join's own answer stands.
 *
 * @returns Whether the work was handed to the runner.
 */
async function schedulePressure(ctx: DemoContext): Promise<boolean> {
  const boardId = ctx.env.DEMO_BOARD_ID;
  if (ctx.background === undefined || boardId === undefined || ctx.env.DEMO_CHAIR_MNEMONIC === undefined) return false;
  let token: string | undefined;
  try {
    token = await claimPass(ctx.store);
  } catch {
    logEvent("demo_pressure_unscheduled", { reason: "store_unavailable" });
    return false;
  }
  if (token === undefined) return false;
  const wallClock = ctx.wallClock ?? Date.now;
  const pass = token;
  try {
    ctx.background(async () => {
      const sweep = { ...ctx, wallClock };
      const outcome = await pressurePass(sweep, boardId, pass);
      // After the pass, so a pass that moved the epoch several times leads to one post, for the last.
      const pack = await ensureCurrentPack(sweep);
      return pack.done === "current" ? outcome : { ...outcome, pack };
    });
    return true;
  } catch {
    await releasePass(ctx.store, pass);
    logEvent("demo_pressure_unscheduled", {});
    return false;
  }
}

/**
 * Hands one ensureCurrentPack to the caller's background runner after an admitted join that
 * scheduled no pressure pass (threat model C41), so a guest seated on a quiet board whose current
 * epoch has no pack gets one without waiting for the scheduled sweep. It runs on the join's wall
 * clock, or Date.now, read once it holds the lock, and answers its PackOutcome. Runs of it and of a
 * pass meet under the "demo:join" lock, so a second one finds the first one's pack. Without a
 * runner nothing is scheduled. A runner that throws is logged, and the join's own answer stands.
 */
function schedulePack(ctx: DemoContext): void {
  if (ctx.background === undefined) return;
  const sweep = { ...ctx, wallClock: ctx.wallClock ?? Date.now };
  try {
    ctx.background(() => ensureCurrentPack(sweep));
  } catch {
    logEvent("demo_pack_unscheduled", {});
  }
}

/** The removal a proven leave request asks for, under the "demo:join" lock. */
async function leaveOnce(ctx: DemoContext, boardId: bigint, guest: Uint8Array, deadline: Deadline): Promise<Response> {
  // The request may have waited on the lock, so the hour and the day are read when the removal runs.
  const run: DemoSweepContext = { ...ctx, now: (ctx.wallClock ?? Date.now)() };
  const chair = await demoChair(run.env);
  const snapshot = await readOwnBoard(run, boardId, chair, deadline);
  const seeded = run.env.DEMO_SEEDED ?? [];
  const address = toHex(guest);
  if (sameAccount(address, snapshot.chair) || seeded.some((s) => sameAccount(s, address))) throw new DemoStop(403, "protected_member");
  const seat = snapshot.members.find((m) => sameAccount(m, address));
  if (seat === undefined) throw new DemoStop(409, "not_a_member");
  const plan = await planRemoval(run, snapshot, "pressure", deadline, seat);
  if ("done" in plan) throw new DemoStop(503, plan.done === "refused" ? plan.reason : "leave_failed");
  if (!(await reserveDemoRelays(run.store, run.now, 1))) throw new DemoStop(503, "demo_busy");
  // One admission per address, ever (C34): a member the bot holds no record of gets its mark
  // before it goes, so leaving is never a way back in.
  try {
    await run.store.setIfAbsent(admittedKey(guest), String(run.now), ADMITTED_SECONDS);
  } catch {
    throw new DemoStop(503, "store_unavailable");
  }
  const removed = await removeGuest(run, chair, snapshot, plan, SWEEP_CLIENT_IP, deadline);
  return json(202, { txHash: removed.txHash, epochAfter: removed.epochAfter });
}

/**
 * Removes a guest from the demo board at its own signed request (threat model C47).
 *
 * POST `{ guest, botNonce, expiry, signature }` as JSON, `signature` the guest's ML-DSA-87
 * signature over the leave request handleDemoLeaveChallenge issued. Every other field is dropped:
 * the bot builds what it signs from its own reads.
 *
 * In order, each refusal leaving every member and every counter but this IP's as it was: a request
 * another site's page could have sent (403 cross_site, refuseCrossSite); 405; 503 not_ready before
 * the board is seeded; this IP's hourly leaves, every /64 of one IPv6 /48 sharing 4 times it (429,
 * countClient); the body (415, 413, 408 after 20 seconds, 400, 400 bad_guest); the guest's stored
 * leave request (409 no_challenge), its botNonce and expiry (403 challenge_mismatch) and the expiry
 * not passed (403 challenge_expired); the guest's key from pqcKeyStatus, registered and possession
 * proven (403 no_proven_key); a pure ML-DSA-87 signature over the leave bytes the bot rebuilds from
 * its own record (403 bad_signature). Only the guest's own key can pass, and a join signature
 * cannot: its bytes carry the other tag. Then the request is used up by compare-and-set to a
 * tombstone with this call's own token, read back on a no, so one request removes at most once and
 * a lost reply never refuses a valid one (409 no_challenge).
 *
 * Then, under the "demo:join" lock (503 busy after 20 s) and one 120 s deadline, on the wall clock
 * read once the lock is held: the board read at one block, its chair checked to be the bot; the
 * chair and the seeded directors refused (403 protected_member); an account with no seat refused
 * (409 not_a_member); every other member's ML-KEM key looked up as a sweep does, a protected
 * member's unusable key or another member's unreadable one refusing the leave because the next
 * epoch could not be sealed to it (503 protected_key_unusable, 503 kem_unavailable; the leaver's
 * own key is not needed); one of the hour's demo relays reserved (503 demo_busy, retry after the
 * hour); the admission mark written if the bot held none, so an address is admitted once, ever;
 * then the sweep's own removal: a fresh epoch key sealed to every other usable member, uploaded as
 * the bot's own, removeMember signed with signBoardAction and relayed in scope "demo".
 *
 * After a 202 the demo chair's next pack is scheduled (ensureCurrentPack through `ctx.background`),
 * sealed under the new epoch, for which the guest who left holds no key.
 *
 * @returns 202 `{ txHash, epochAfter }`: a claim the removeMember was sent, which the browser
 *   confirms on chain (C26). A request refused after it was used up needs a fresh one.
 */
export async function handleDemoLeave(request: Request, ctx: DemoContext): Promise<Response> {
  const crossSite = refuseCrossSite(request);
  if (crossSite !== undefined) return crossSite;
  const deadline = startDeadline(DEMO_DEADLINE_MS, ctx.clock);
  if (request.method !== "POST") return refusal(405, "method_not_allowed", {}, { allow: "POST" });
  const boardId = ctx.env.DEMO_BOARD_ID;
  if (boardId === undefined || ctx.env.DEMO_CHAIR_MNEMONIC === undefined) return refusal(503, "not_ready");
  const rules = ctx.limits?.leave ?? DEMO_LEAVE_LIMITS;
  const client = await countClient(ctx.store, { scope: "demo-leave", clientIp: ctx.clientIp, perIp: rules.perIp, windowSeconds: rules.windowSeconds });
  if (!client.ok) return refusal(429, "rate_limited", { limit: client.refusedBy ?? "per_ip" }, { "retry-after": String(rules.windowSeconds) });

  const read = await readJson(request, JOIN_BODY_CAP);
  if ("response" in read) return read.response;
  const checked = JoinBody.safeParse(read.value);
  if (!checked.success) return refusal(400, "bad_body");
  const guest = guestBytes(checked.data.guest);
  if (guest === undefined) return refusal(400, "bad_guest");
  const fields: Fields = { guest: toHex(guest), leave: true };

  const key = leaveKey(guest);
  let raw: string | null;
  try {
    raw = await ctx.store.get(key);
  } catch {
    return refusal(503, "store_unavailable", fields);
  }
  const stored = parseChallenge(raw);
  if (raw === null || stored === undefined) return refusal(409, "no_challenge", fields);
  if (!sameHash(stored.botNonce, checked.data.botNonce) || stored.expiry !== checked.data.expiry) return refusal(403, "challenge_mismatch", fields);
  if (stored.expiry <= nowSeconds(ctx.now)) return refusal(403, "challenge_expired", fields);

  // The bytes checked are rebuilt from the bot's own record, never taken from the request.
  const message = leaveMessage({ registry: REGISTRY_ADDRESS, boardId, guest: toHex(guest), botNonce: stored.botNonce, expiry: stored.expiry });
  let publicKey: Uint8Array | undefined;
  try {
    publicKey = provenMldsaKey(await within(deadline, ctx.chain.keyStatus(toHex(guest)), "the key status read"));
  } catch {
    return refusal(502, "chain_unreachable", fields);
  }
  if (publicKey === undefined) return refusal(403, "no_proven_key", fields);
  let valid = false;
  try {
    valid = mldsa87.verify(publicKey, message, checked.data.signature);
  } catch {
    valid = false;
  }
  if (!valid) return refusal(403, "bad_signature", fields);

  const consumed = `consumed:${randomUUID()}`;
  try {
    if (!(await ctx.store.compareAndSet(key, raw, consumed, CONSUMED_SECONDS)) && (await ctx.store.get(key)) !== consumed) {
      return refusal(409, "no_challenge", fields);
    }
  } catch {
    return refusal(503, "store_unavailable", fields);
  }

  const waitMs = Math.floor(Math.max(0, Math.min(DEMO_LOCK_WAIT_MS, DEMO_RELAY_CUTOFF_MS - elapsedMs(deadline))));
  let response: Response;
  try {
    response = await ctx.store.withLock(DEMO_LOCK, DEMO_LOCK_TTL_SECONDS, () => leaveOnce(ctx, boardId, guest, deadline), { waitMs });
  } catch (error) {
    if (error instanceof LockBusy) return refusal(503, "busy", fields, { "retry-after": "30" });
    const stop = asStop(error, "leave_failed");
    const wait = stop.reason === "demo_busy" ? untilNextHour((ctx.wallClock ?? Date.now)()) : "30";
    return refusal(stop.status, stop.reason, fields, stop.status === 503 ? { "retry-after": wait } : {});
  }
  // The new epoch gets its pack once the lock is free; the guest who left holds no key for it.
  if (response.status === 202) schedulePack(ctx);
  return response;
}

/**
 * Admits one guest to the demo board (threat model C12, C15, C16, C33, C34, C35, C37, C41, C43).
 * The bot does nothing for the guest and counts nothing against the day until every check the guest
 * can fail has passed, and a join never removes anyone: it is one addMember or nothing.
 *
 * POST `{ guest, botNonce, expiry, signature }` as JSON; any other field is dropped unread. In order,
 * with nothing opened or signed until all of them pass: a request another site's page could have
 * sent (403 cross_site), before anything is counted or read; POST only (405); the board seeded and
 * the demo chair's phrase set (503 not_ready); a board holding DEMO_GUEST_CAP members or more, by a
 * read at most 5 s old (boardFull), answered 503 board_full with retry-after 30 before the body is
 * read and with nothing counted, consumed or removed, so the judge's retry of the same join reuses
 * its challenge and its hourly joins, and the join that read the board schedules a pressure pass;
 * this IP's hourly join limit, with every /64 of one
 * IPv6 /48 also sharing 4 times it (countClient, 429); the body (415,
 * 413, 408 body_timeout after 20 seconds, 400, and 400 bad_guest for anything but qor1 or exact
 * EIP-55); the guest's stored challenge (409 no_challenge); botNonce and expiry equal to the stored
 * ones (403 challenge_mismatch) and the expiry not passed (403 challenge_expired); the guest's key
 * from pqcKeyStatus, all four values: registered, algorithm 1, possession proven, 2,592 bytes (403
 * no_proven_key); a pure ML-DSA-87 signature, empty context, over the challenge bytes the bot
 * rebuilds from its own record (403 bad_signature). Every refusal so far leaves the challenge in
 * place and counts against nothing but the IP.
 *
 * From here the address is proven to be the guest's, and every refusal the guest caused (a 4xx
 * other than 429; never a 5xx or a 429) counts against it under "demo:failed:<address>:<UTC day>":
 * a guest with five already today is refused 429 too_many_failures. Then the challenge is consumed:
 * the exact value checked is moved by compare-and-set to a tombstone carrying this join's own token,
 * and on a no the key is read back, so a retried write that landed still counts as this join's and
 * one challenge serves one join at most (409 no_challenge); never admitted before (409
 * already_admitted), where a mark naming an addMember that can no longer land does not count: the
 * guest is not a member and the chain does not know that transaction or holds it reverted
 * (admissionStanding), and a mark whose addMember is still pending, or whose standing cannot be read
 * in time, answers 503 admission_unsettled with retry-after 30, keeps the mark and counts nothing
 * against the guest; the guest's ML-KEM key from fetchKemKey, checked with validateMlkemPublicKey
 * (403 no_kem_key, 403 bad_kem_key, 502 kem_unavailable); that key byte-equal to none a current
 * member has published, members whose lookup is unreadable skipped (403 key_shared);
 * the day's joins below its limit (503 daily_limit), read only.
 *
 * Then, under the lock "demo:join" (150 s, waiting at most 20 s, else 503 busy), all inside one
 * 120 s deadline: the once-per-guest mark, held only for the lock's 150 s, taking the place of a
 * mark whose addMember can no longer land (checked again here, so no earlier join of this guest is
 * between its broadcast and its receipt; unsure here too answers 503 admission_unsettled); the board read at one
 * block, its chair checked to be the bot; the guest not a member (409); the day's limit read again
 * (503 daily_limit); a board that filled since the first check answered 503 board_full with
 * retry-after 30, nothing reserved, taken from the day or removed, the mark taken back and a
 * pressure pass scheduled (this join's IP count and challenge, taken while the board had room,
 * stay taken); one of this clock hour's demo relays reserved with reserveDemoRelays (503 demo_busy,
 * retry after the hour); the current epoch's envelope downloaded by its on-chain hash and opened
 * only once its size and SHA-256 match the record (502 envelope_mismatch otherwise); the epoch key
 * sealed to the guest alone; the envelope uploaded through handleUpload as the bot's own
 * ("demo-bot", never counted against the guest's IP); addMember (SEAL_CURRENT, epochAfter = the
 * epoch read) built and signed by the bot with signBoardAction; only now the join taken from the
 * day; handleRelay in scope "demo", started no later than 65 s in (503 out_of_time), which makes the
 * mark permanent and names the addMember's hash in it once the transaction is signed and before its
 * broadcast (keepAdmission; nothing is broadcast if it cannot, 502 relay_chain_unreachable); then
 * the receipt, waited for up to 30 s. A 202 whose receipt was not seen lists the guest for the
 * scheduled sweep (noteUnsettled), which gives up the mark once its addMember can no longer land.
 *
 * If the join fails with nothing sent, the mark is taken back so the guest can try again; if that
 * fails too, it still ends with the lock. After a
 * send, a revert included, the board is read again: a guest who is a member keeps the mark, dated
 * now; the mark goes only when that read shows the guest is not a member, and a read that fails
 * lists the guest for the sweep.
 *
 * Seats are freed only in the background (C41): after a board_full answer, and after an admitted
 * join whose board now holds more than DEMO_GUEST_CAP minus DEMO_FREE_SEATS members, one pass of
 * freeDemoSeats, followed by one ensureCurrentPack, is handed to `ctx.background` once the lock is
 * released, unless a pass is already scheduled or running (the "demo:pass" mark), so passes never
 * pile up. Every other admitted join hands it ensureCurrentPack alone (schedulePack), so the epoch
 * the guest was sealed into gets its pack. Without it nothing is scheduled, and sweepDemoGuests,
 * which runs the same pass after its own step and ends with ensureCurrentPack, is the only remover.
 *
 * @returns 202 `{ txHash }`: a claim that the addMember was sent, which the browser confirms on chain (C26).
 */
export async function handleDemoJoin(request: Request, ctx: DemoContext): Promise<Response> {
  const crossSite = refuseCrossSite(request);
  if (crossSite !== undefined) return crossSite;
  const deadline = startDeadline(DEMO_DEADLINE_MS, ctx.clock);
  if (request.method !== "POST") return refusal(405, "method_not_allowed", {}, { allow: "POST" });
  const boardId = ctx.env.DEMO_BOARD_ID;
  if (boardId === undefined || ctx.env.DEMO_CHAIR_MNEMONIC === undefined) return refusal(503, "not_ready");
  // A full board is answered before the body is read or anything is counted or consumed, so a
  // judge told to come back retries the very same join, challenge and hourly joins intact (C41).
  const fullness = await boardFull(ctx, boardId, deadline);
  if (fullness.full === true) {
    if (fullness.read) await schedulePressure(ctx);
    return refusal(503, "board_full", {}, { "retry-after": "30" });
  }
  const rules = (ctx.limits ?? DEFAULT_LIMITS).join;
  const retry = { "retry-after": String(rules.windowSeconds) };
  // Per IP, and per IPv6 /48 at 4 times that, with the one rule every endpoint uses (C23).
  const client = await countClient(ctx.store, { scope: "demo-join", clientIp: ctx.clientIp, perIp: rules.perIp, windowSeconds: rules.windowSeconds });
  if (!client.ok) return refusal(429, "rate_limited", { limit: client.refusedBy ?? "per_ip" }, retry);

  const read = await readJson(request, JOIN_BODY_CAP);
  if ("response" in read) return read.response;
  const checked = JoinBody.safeParse(read.value);
  if (!checked.success) return refusal(400, "bad_body");
  const guest = guestBytes(checked.data.guest);
  if (guest === undefined) return refusal(400, "bad_guest");
  const fields: Fields = { guest: toHex(guest) };

  let raw: string | null;
  try {
    raw = await ctx.store.get(challengeKey(guest));
  } catch {
    return refusal(503, "store_unavailable", fields);
  }
  const stored = parseChallenge(raw);
  if (raw === null || stored === undefined) return refusal(409, "no_challenge", fields);
  if (!sameHash(stored.botNonce, checked.data.botNonce) || stored.expiry !== checked.data.expiry) return refusal(403, "challenge_mismatch", fields);
  if (stored.expiry <= nowSeconds(ctx.now)) return refusal(403, "challenge_expired", fields);

  // The bytes checked are rebuilt from the bot's own record, never taken from the request.
  const message = challengeMessage({ registry: REGISTRY_ADDRESS, boardId, guest: toHex(guest), botNonce: stored.botNonce, expiry: stored.expiry });
  let publicKey: Uint8Array | undefined;
  try {
    publicKey = provenMldsaKey(await within(deadline, ctx.chain.keyStatus(toHex(guest)), "the key status read"));
  } catch {
    return refusal(502, "chain_unreachable", fields);
  }
  if (publicKey === undefined) return refusal(403, "no_proven_key", fields);
  let valid = false;
  try {
    valid = mldsa87.verify(publicKey, message, checked.data.signature);
  } catch {
    valid = false;
  }
  if (!valid) return refusal(403, "bad_signature", fields);

  let failures: number;
  try {
    failures = await readCount(ctx.store, failedJoinsKey(guest, ctx.now));
  } catch {
    return refusal(503, "store_unavailable", fields);
  }
  if (failures >= FAILED_JOINS_PER_DAY) return refusal(429, "too_many_failures", fields, { "retry-after": untilTomorrow(ctx.now) });

  const response = await joinProven(ctx, { boardId, guest, challenge: raw, perDay: rules.perDay }, deadline, fields);
  if (guestCaused(response.status)) await countFailure(ctx.store, guest, ctx.now, fields);
  return response;
}

async function admittedAt(store: SharedStore, member: Hex): Promise<number | undefined> {
  const raw = await store.get(admittedKey(accountBytes(member)));
  return raw === null ? undefined : readAdmission(raw)?.at;
}

/**
 * Every guest's admission time in milliseconds, in the guests' order (threat model C34). A guest
 * member with no record, because its mark was lost or never written, is dated from the block
 * timestamp of its latest EnvelopeGranted, and that time is stored, so its six hours run like
 * anyone's. A time after `now` is taken as `now`. A failed log read leaves those guests undated
 * for this pass only.
 */
async function admissionTimes(ctx: DemoSweepContext, boardId: bigint, guests: readonly Hex[], deadline: Deadline): Promise<(number | undefined)[]> {
  const times = await Promise.all(guests.map((m) => admittedAt(ctx.store, m)));
  const undated = guests.filter((_, i) => times[i] === undefined);
  if (undated.length === 0) return times;
  let granted: bigint[];
  try {
    granted = await within(deadline, ctx.chain.grantTimes(boardId, undated), "the grant log read");
    if (granted.length !== undated.length || !granted.every((t) => typeof t === "bigint" && t > 0n && t < MAX_UNIX_SECONDS)) {
      throw new Error("The grant times are not one sane time per member.");
    }
  } catch {
    logEvent("demo_sweep_undated", { guests: undated.length });
    return times;
  }
  const dated = new Map(undated.map((m, i) => [m, Math.min(Number(granted[i]) * 1000, ctx.now)]));
  return Promise.all(
    guests.map(async (m, i) => {
      const known = times[i];
      if (known !== undefined) return known;
      const at = dated.get(m) as number;
      await ctx.store.setIfAbsent(admittedKey(accountBytes(m)), String(at), ADMITTED_SECONDS).catch(() => logEvent("demo_guest_date_unstored", { member: m }));
      logEvent("demo_guest_dated", { member: m, admittedAt: at });
      return at;
    }),
  );
}

type KeyProblem = "key_missing" | "key_invalid" | "key_changed" | "key_shared";

/**
 * One member's published ML-KEM key, as the recipient pair fetchKemKey builds, before it is compared
 * with anything. `unreadable` says nothing about the member by itself: the lookup failed (a timeout,
 * the network, a malformed answer, a pair for another account). Only a run of them does.
 */
type Lookup = { member: Hex; recipient: KemRecipient } | { member: Hex; problem: "key_missing" | "key_invalid" } | { member: Hex; unreadable: true };

/** One member's ML-KEM key as a removal sees it. */
type MemberKey = Lookup | { member: Hex; problem: KeyProblem };

interface RemovalPlan {
  member: Hex;
  reason: RemovalReason;
  /** Every member the next epoch is sealed to: all whose key is usable, the one removed excepted. */
  recipients: KemRecipient[];
}

async function lookUpKey(ctx: DemoSweepContext, member: Hex, deadline: Deadline): Promise<Lookup> {
  let recipient: KemRecipient;
  try {
    recipient = await within(deadline, ctx.chain.kemKey(member), "the KEM lookup");
  } catch (error) {
    if (error instanceof KemKeyUnavailable && error.reason === "NOT_FOUND") return { member, problem: "key_missing" };
    if (error instanceof KemKeyUnavailable && (error.reason === "INVALID_KEY" || error.reason === "WRONG_ALGORITHM")) return { member, problem: "key_invalid" };
    return { member, unreadable: true };
  }
  if (!pairFor(recipient, member)) return { member, unreadable: true };
  try {
    validateMlkemPublicKey(recipient.kemPublicKey);
  } catch {
    return { member, problem: "key_invalid" };
  }
  return { member, recipient };
}

/** The published keys of `members`, a few lookups at a time, in their order. */
async function lookUpKeys(ctx: DemoSweepContext, members: readonly Hex[], deadline: Deadline): Promise<Lookup[]> {
  const out: Lookup[] = [];
  for (let start = 0; start < members.length; start += KEM_PARALLEL) {
    out.push(...(await Promise.all(members.slice(start, start + KEM_PARALLEL).map((member) => lookUpKey(ctx, member, deadline)))));
  }
  return out;
}

/**
 * Every member's key, in the members' order, each checked against the current epoch's envelopes and
 * against every other member's (threat model C15, C42). A key the epoch was not sealed to is
 * key_changed. A seal takes each key once, so a key byte-equal to another member's is key_shared:
 * always for a guest, and for a protected member only when another protected member holds it too,
 * because a guest can copy a director's public key but a director cannot be removed for it.
 */
async function memberKeys(ctx: DemoSweepContext, snapshot: BoardSnapshot, isProtected: (m: Hex) => boolean, deadline: Deadline): Promise<MemberKey[]> {
  const signal = AbortSignal.timeout(Math.max(1, Math.floor(leftMs(deadline))));
  const sealed = await sealedTo({ snapshot, blobs: ctx.blobs, blobOrigin: ctx.env.BLOB_ORIGIN, signal });
  const looked = await lookUpKeys(ctx, snapshot.members, deadline);
  const holders = new Map<string, number[]>();
  looked.forEach((k, i) => {
    if (!("recipient" in k)) return;
    const id = bytesToHex(k.recipient.kemPublicKey);
    holders.set(id, [...(holders.get(id) ?? []), i]);
  });
  return looked.map((k, i): MemberKey => {
    if (!("recipient" in k)) return k;
    if (!sealed(k.recipient.kemPublicKey)) return { member: k.member, problem: "key_changed" };
    const others = (holders.get(bytesToHex(k.recipient.kemPublicKey)) ?? []).filter((j) => j !== i).map((j) => (looked[j] as Lookup).member);
    const shared = isProtected(k.member) ? others.some(isProtected) : others.length > 0;
    return shared ? { member: k.member, problem: "key_shared" } : k;
  });
}

/** A stored run: its count, then the time in milliseconds of its first unreadable sweep. */
const UNREADABLE_RUN = /^([1-9][0-9]{0,5}):([0-9]{1,16})$/;

/** The run `raw` holds, or undefined for none: nothing stored, a value of another shape, or a run that started a day ago or more. */
function parseRun(raw: string | null, now: number): { count: number; startedAt: number } | undefined {
  const match = raw === null ? null : UNREADABLE_RUN.exec(raw);
  if (match === null) return undefined;
  const startedAt = Number(match[2]);
  return now - startedAt < UNREADABLE_RUN_SECONDS * 1000 ? { count: Number(match[1]), startedAt } : undefined;
}

/**
 * Adds this sweep to the member's run by compare-and-set from the value read (threat model C31),
 * never by an increment: a request the store applied twice must not count two sweeps, because the
 * count decides a removal. The run keeps the time it started, so it is still forgotten a day after.
 *
 * @throws Error when another writer changed the run in between, so nothing is counted.
 */
async function addUnreadableRun(store: SharedStore, member: Hex, now: number): Promise<number> {
  const key = unreadableKey(member);
  const held = await store.get(key);
  const run = parseRun(held, now);
  const count = (run?.count ?? 0) + 1;
  const startedAt = run?.startedAt ?? now;
  const next = `${count}:${startedAt}`;
  const ttl = Math.min(UNREADABLE_RUN_SECONDS, Math.max(1, Math.ceil((startedAt + UNREADABLE_RUN_SECONDS * 1000 - now) / 1000)));
  if (await store.compareAndSet(key, held, next, ttl)) return count;
  // A write that landed but whose reply was lost reads back as ours.
  if ((await store.get(key)) === next) return count;
  throw new Error("The unreadable run changed while it was counted.");
}

/**
 * How many sweeps in a row each member's ML-KEM lookup has come back unreadable, this one included
 * when `counting` (threat model C42). A readable answer, usable or not, starts the count again. A
 * store failure counts nothing, so the member blocks removals as an unreadable lookup always did.
 */
async function unreadableRuns(store: SharedStore, keys: readonly MemberKey[], counting: boolean, now: number): Promise<Map<Hex, number>> {
  const runs = new Map<Hex, number>();
  for (let start = 0; start < keys.length; start += KEM_PARALLEL) {
    await Promise.all(
      keys.slice(start, start + KEM_PARALLEL).map(async (k) => {
        const key = unreadableKey(k.member);
        try {
          if (!("unreadable" in k)) await store.delete(key);
          else runs.set(k.member, counting ? await addUnreadableRun(store, k.member, now) : (parseRun(await store.get(key), now)?.count ?? 0));
        } catch {
          if ("unreadable" in k) runs.set(k.member, 0);
        }
      }),
    );
  }
  return runs;
}

/**
 * Picks the one guest to remove and the members the next epoch is sealed to (threat model C34,
 * C41, C42). Every guest has an admission time first (admissionTimes), then every member's ML-KEM
 * key is looked up. A guest whose key is missing, invalid, not the one the current epoch was
 * sealed to, or byte-equal to another member's, or whose lookup has been unreadable on
 * UNREADABLE_RUNS_TO_REMOVE sweeps in a row, is the target whatever its age, the oldest admitted
 * first, and every such guest is left out of the next epoch, so the reseal holds each key once. A
 * problem with the chair's or a seeded director's key, two of them sharing one included, logs
 * demo_sweep_alert on every pass and removes no one. A member whose lookup is unreadable, on fewer sweeps in a row than
 * that, also removes no one, because the next epoch could not be sealed to it. Otherwise the
 * target is the guest admitted longest ago: in "expiry" mode once its admission is older than
 * DEMO_GUEST_TTL_SECONDS, and in "pressure" mode at once, with the reason "pressure". A guest still
 * undated, after a failed log read, goes only when a pressure pass finds no dated guest.
 *
 * @param mode "expiry" for the scheduled sweep, the only caller that adds to an unreadable run,
 *   because its passes are minutes apart; "pressure" for freeDemoSeats, whose passes can follow
 *   each other within seconds and so only read the runs.
 */
async function planRemoval(ctx: DemoSweepContext, snapshot: BoardSnapshot, mode: SweepMode, deadline: Deadline, leaver?: Hex): Promise<RemovalPlan | SweepOutcome> {
  const seeded = ctx.env.DEMO_SEEDED ?? [];
  const isProtected = (m: Hex): boolean => sameAccount(m, snapshot.chair) || seeded.some((s) => sameAccount(s, m));
  const guests = snapshot.members.filter((m) => !isProtected(m));
  if (guests.length === 0) return { done: "nothing_due", guests: 0, unknown: 0 };
  // A leaver goes whatever its age, so the grant logs that date undated guests are not read for it.
  const times = leaver === undefined ? await admissionTimes(ctx, snapshot.boardId, guests, deadline) : [];
  const keys = await memberKeys(ctx, snapshot, isProtected, deadline);
  const runs = await unreadableRuns(ctx.store, keys, mode === "expiry", ctx.now);
  for (const k of keys) {
    if (isProtected(k.member) && !("recipient" in k)) {
      logEvent("demo_sweep_alert", { member: k.member, problem: "problem" in k ? k.problem : "kem_unavailable", unreadableRun: runs.get(k.member) ?? 0 });
      return { done: "refused", reason: "protected_key_unusable" };
    }
  }
  const named = (k: MemberKey): boolean => "unreadable" in k && (runs.get(k.member) ?? 0) >= UNREADABLE_RUNS_TO_REMOVE;
  // The leaver's own key is not needed to seal the epoch it will not be in.
  const leaving = (m: Hex): boolean => leaver !== undefined && sameAccount(m, leaver);
  if (keys.some((k) => "unreadable" in k && !named(k) && !leaving(k.member))) return { done: "refused", reason: "kem_unavailable" };
  if (leaver !== undefined) {
    return { member: leaver, reason: "left", recipients: keys.flatMap((k) => ("recipient" in k && !leaving(k.member) ? [k.recipient] : [])) };
  }

  const ageOf = new Map(guests.map((m, i) => [m, times[i]]));
  // No admission time sorts last, so a guest of unknown age is never taken before a dated one.
  const rank = (m: Hex): number => ageOf.get(m) ?? Number.MAX_SAFE_INTEGER;
  const oldestFirst = (a: Hex, b: Hex): number => rank(a) - rank(b);
  const bad = keys
    .flatMap((k): { member: Hex; reason: RemovalReason }[] => ("problem" in k ? [{ member: k.member, reason: k.problem }] : named(k) ? [{ member: k.member, reason: "key_unreadable" }] : []))
    .sort((a, b) => oldestFirst(a.member, b.member));
  let pick = bad[0];
  if (pick === undefined) {
    const oldest = [...guests].sort(oldestFirst)[0];
    const at = oldest === undefined ? undefined : ageOf.get(oldest);
    if (oldest !== undefined && mode === "pressure") pick = { member: oldest, reason: "pressure" };
    else if (oldest !== undefined && at !== undefined && ctx.now - at >= DEMO_GUEST_TTL_SECONDS * 1000) pick = { member: oldest, reason: "expired" };
  }
  if (pick === undefined) return { done: "nothing_due", guests: guests.length, unknown: times.filter((t) => t === undefined).length };
  const target = pick.member;
  const recipients = keys.flatMap((k) => ("recipient" in k && !sameAccount(k.member, target) ? [k.recipient] : []));
  return { member: target, reason: pick.reason, recipients };
}

/**
 * Removes the planned guest: a fresh epoch key sealed to the plan's recipients, the envelope
 * uploaded through handleUpload, removeMember signed by the demo chair and relayed through
 * handleRelay, then its receipt waited for. Once the receipt is seen, the member's unreadable run,
 * if it had one, is forgotten.
 */
async function removeGuest(ctx: DemoSweepContext, chair: Identity, snapshot: BoardSnapshot, plan: RemovalPlan, clientIp: string, deadline: Deadline): Promise<Removed> {
  const epochAfter = snapshot.epoch + 1n;
  const epochKey = newEpochKey();
  let envelope: Uint8Array;
  try {
    envelope = sealEpochKey({ registry: REGISTRY_ADDRESS, boardRef: snapshot.boardRef, epoch: epochAfter, epochKey, recipients: plan.recipients });
  } finally {
    epochKey.fill(0);
  }
  const uploaded = await within(deadline, uploadEnvelope(envelope, { clientIp, now: ctx.now, store: ctx.store, blobs: ctx.blobs, blobOrigin: ctx.env.BLOB_ORIGIN, internal: "sweep" }), "the envelope upload");
  // A chain read may give lowercase hex; the relay takes an address only in its EIP-55 form.
  const member = toHex(accountBytes(plan.member));
  const body = signedAction(chair, snapshot, { kind: "remove", member, envelopeHash: uploaded.hash, envelopeSize: uploaded.size, epochAfter });
  const { txHash, landed } = await relayAndWait(ctx, clientIp, body, deadline, { value: false });
  // A run counts sweeps of a sitting member only; one who has left must not carry it back in.
  if (landed) await ctx.store.delete(unreadableKey(plan.member)).catch(() => logEvent("demo_run_unforgotten", { member }));
  logEvent("demo_guest_removed", { boardId: snapshot.boardId.toString(), member, reason: plan.reason, epochAfter: epochAfter.toString(), txHash, landed });
  return { done: "removed", member, reason: plan.reason, txHash, epochAfter: epochAfter.toString(), landed };
}

/**
 * At most one removal, under the "demo:join" lock and its own 120 s deadline, so the lock never
 * outlives the one removal it guards. A pass takes the lock again at once for each of its up to
 * DEMO_FREE_SEATS removals, while a waiting join tries every 50 to 200 ms, so a join can wait behind
 * several removals; it waits at most DEMO_LOCK_WAIT_MS (20 s) and then answers 503 busy. In "pressure"
 * mode a board already at DEMO_GUEST_CAP minus DEMO_FREE_SEATS members or fewer answers room right
 * after the board read, before any key is looked up. One demo relay is reserved only once there is
 * a target. The removal runs on the wall clock read once the lock is held, never on `ctx.now`.
 */
function removeOneLocked(ctx: DemoSweepContext, boardId: bigint, mode: "expiry"): Promise<SweepOutcome>;
function removeOneLocked(ctx: DemoSweepContext, boardId: bigint, mode: "pressure"): Promise<SweepOutcome | { done: "room" }>;
async function removeOneLocked(sweep: DemoSweepContext, boardId: bigint, mode: SweepMode): Promise<SweepOutcome | { done: "room" }> {
  const deadline = startDeadline(DEMO_DEADLINE_MS, sweep.clock);
  const removeOne = async (): Promise<SweepOutcome | { done: "room" }> => {
    // A pass can start minutes after the join that asked for it, and each removal waits on the lock.
    const ctx: DemoSweepContext = { ...sweep, now: (sweep.wallClock ?? Date.now)() };
    const chair = await demoChair(ctx.env);
    const snapshot = await readOwnBoard(ctx, boardId, chair, deadline);
    if (mode === "expiry") await settleAdmissions(ctx, snapshot, deadline);
    if (mode === "pressure" && snapshot.members.length <= DEMO_GUEST_CAP - DEMO_FREE_SEATS) return { done: "room" };
    const plan = await planRemoval(ctx, snapshot, mode, deadline);
    if ("done" in plan) return plan;
    if (!(await reserveDemoRelays(ctx.store, ctx.now, 1))) return { done: "refused", reason: "demo_busy" };
    return removeGuest(ctx, chair, snapshot, plan, SWEEP_CLIENT_IP, deadline);
  };
  try {
    return await sweep.store.withLock(DEMO_LOCK, DEMO_LOCK_TTL_SECONDS, removeOne, { waitMs: DEMO_LOCK_WAIT_MS });
  } catch (error) {
    return { done: "refused", reason: error instanceof LockBusy ? "busy" : asStop(error, "sweep_failed").reason };
  }
}

/**
 * Removes at most one demo guest per call (threat model C34, C42). Under the lock, right after the
 * board read, it first settles every admission a join left unsettled (settleAdmissions): the mark of
 * a guest whose addMember can no longer land is given up, so that guest may join again. A guest
 * member with no admission
 * record is first dated from the block timestamp of its latest EnvelopeGranted, and that time is
 * stored, so every guest member expires. Every remaining member's ML-KEM key is then looked up and
 * checked against the current epoch's envelopes and against every other member's. A guest whose key
 * is missing, invalid, changed since the board was sealed to it, or byte-equal to another member's
 * (key_shared, left out of the next epoch) is removed first, whatever its age, and so is one whose lookup
 * has come back unreadable on three sweeps in a row (counted per member in the store, started
 * again by any readable answer, forgotten once that member's removal lands; a pressure pass only
 * reads it); otherwise the guest admitted longest ago, once its admission is
 * older than DEMO_GUEST_TTL_SECONDS (six hours). A lookup unreadable on fewer sweeps than that
 * removes no one, because the next epoch could not be sealed to that member. The chair and every
 * DEMO_SEEDED director are never candidates: a problem with one of their keys, two of them on one
 * key, or a lookup that fails, logs demo_sweep_alert on every sweep and removes no one. The new epoch key is fresh and
 * sealed to every remaining member whose key is usable, with the recipient pair fetchKemKey returns
 * for each (C15). One of this clock hour's demo relays is reserved first (reserveDemoRelays); with none left
 * the sweep answers refused demo_busy and removes no one. The envelope goes through handleUpload as an internal "sweep" upload, the removeMember is
 * signed by the demo chair with signBoardAction and relayed through handleRelay in scope "demo",
 * under the same "demo:join" lock and 120 s deadline as a join. The removal reads `ctx.wallClock`
 * (Date.now when absent) once it holds the lock and runs on that time, not on `ctx.now`: its age
 * checks, its demo relay's clock hour and its ledger's UTC day.
 *
 * Then, after nothing_due or a removal whose receipt was seen, it runs one pressure pass
 * (freeDemoSeats) while the board holds more than DEMO_GUEST_CAP minus DEMO_FREE_SEATS members
 * (threat model C41), so seats are freed on schedule even when no join had a background runner to
 * hand a pass to, or a pass was cut off. A refused step, or a removal whose receipt was not seen,
 * runs no pass: it would meet the same refusal, or the board's nonce that has not moved.
 *
 * Every sweep that gets past not_ready ends with ensureCurrentPack, so an epoch its own step or its
 * pass moved to, or one a post earlier missed, gets its pack from the sweep that follows.
 *
 * @returns What its own step did: not_ready, nothing_due (with the number of guests and of guests
 *   still undated because the grant log read failed), removed (with why, the transaction and
 *   whether its receipt was seen), or refused with a short reason; `pressure`, what the pass did,
 *   whenever the pass did more than find room at once; and `pack`, what ensureCurrentPack did,
 *   whenever it did more than find the current epoch's pack in place. Never throws for a failed step.
 */
export async function sweepDemoGuests(ctx: DemoSweepContext): Promise<SweepOutcome & { pressure?: PressureOutcome; pack?: PackOutcome }> {
  const boardId = ctx.env.DEMO_BOARD_ID;
  if (boardId === undefined || ctx.env.DEMO_CHAIR_MNEMONIC === undefined) return { done: "not_ready" };
  const outcome = await removeOneLocked(ctx, boardId, "expiry");
  if (outcome.done === "refused") logEvent("demo_sweep_refused", { reason: outcome.reason });
  let swept: SweepOutcome & { pressure?: PressureOutcome } = outcome;
  if (outcome.done === "nothing_due" || (outcome.done === "removed" && outcome.landed)) {
    const pressure = await freeDemoSeats(ctx);
    if (pressure.removed.length > 0 || pressure.stopped.done !== "room") swept = { ...outcome, pressure };
  }
  const pack = await ensureCurrentPack(ctx);
  return pack.done === "current" ? swept : { ...swept, pack };
}

/**
 * The pressure pass: frees seats on the demo board ahead of the next judges (threat model C34, C41,
 * C42), and the only remover besides sweepDemoGuests, which runs it too after its own step. It is
 * handed to a join's background runner and run by every scheduled sweep. No join ever removes anyone.
 * It never posts: the caller that ran it follows it with ensureCurrentPack.
 *
 * While the board holds more than DEMO_GUEST_CAP minus DEMO_FREE_SEATS members (34), it removes the
 * guest planRemoval picks in "pressure" mode: a guest with a key problem first, as the sweep would,
 * otherwise the guest admitted longest ago, with the reason "pressure". Each removal is the sweep's
 * own (a fresh epoch key sealed to every other usable member, removeMember signed by the demo chair
 * and relayed in scope "demo"), takes the "demo:join" lock for itself alone with its own 120 s
 * deadline, and reserves one of the clock hour's demo relays first. Each removal reads
 * `ctx.wallClock` (Date.now when absent) once it holds the lock and runs on that time, never on
 * `ctx.now`, which for a pass a join scheduled is the join's arrival. The chair and every
 * DEMO_SEEDED director are never candidates, and the pass never adds to a member's unreadable run.
 *
 * One pass runs at a time, a scheduled one included: a pass claims the "demo:pass" mark first and
 * answers refused pass_running while another holds it, renews the mark before each removal (refused
 * pass_lost if it is no longer this pass's) and releases it when done. Before each removal it reads
 * the clock hour's demo room (demoRelaysLeft), so with none left it answers refused demo_busy
 * before any board read or key lookup.
 *
 * It stops at the first step that does not remove someone (room, a refusal, the lock busy, no
 * guest), at a removal whose receipt was not seen, or after DEMO_FREE_SEATS removals. A refused or
 * failed step changes nothing for any guest.
 *
 * @returns Every removal made, in order, and why it stopped. Never throws for a failed step.
 */
export async function freeDemoSeats(ctx: DemoSweepContext): Promise<PressureOutcome> {
  const boardId = ctx.env.DEMO_BOARD_ID;
  if (boardId === undefined || ctx.env.DEMO_CHAIR_MNEMONIC === undefined) return { removed: [], stopped: { done: "not_ready" } };
  let token: string | undefined;
  try {
    token = await claimPass(ctx.store);
  } catch {
    return { removed: [], stopped: { done: "refused", reason: "store_unavailable" } };
  }
  if (token === undefined) {
    logEvent("demo_pressure_pass", { removed: 0, stopped: "pass_running" });
    return { removed: [], stopped: { done: "refused", reason: "pass_running" } };
  }
  return pressurePass(ctx, boardId, token);
}

/** The pressure pass itself, holding the pass mark under `token` until it ends (freeDemoSeats). */
async function pressurePass(ctx: DemoSweepContext, boardId: bigint, token: string): Promise<PressureOutcome> {
  const removed: PressureOutcome["removed"] = [];
  let stopped: PressureOutcome["stopped"] = { done: "limit" };
  try {
    while (removed.length < DEMO_FREE_SEATS) {
      // From this pass's own token to itself, so a write retried after a lost reply still answers yes.
      if (!(await ctx.store.compareAndSet(PASS_KEY, token, token, PASS_STEP_SECONDS).catch(() => false))) {
        stopped = { done: "refused", reason: "pass_lost" };
        break;
      }
      if ((await demoRelaysLeft(ctx.store, (ctx.wallClock ?? Date.now)())) < 1) {
        stopped = { done: "refused", reason: "demo_busy" };
        break;
      }
      const step = await removeOneLocked(ctx, boardId, "pressure");
      if (step.done !== "removed") {
        stopped = step;
        break;
      }
      removed.push(step);
      // The next removal is signed on the board's next nonce, which only a landed removal moves.
      if (!step.landed) {
        stopped = { done: "unlanded" };
        break;
      }
    }
  } finally {
    await releasePass(ctx.store, token);
  }
  logEvent("demo_pressure_pass", { removed: removed.length, stopped: stopped.done === "refused" ? stopped.reason : stopped.done });
  return { removed, stopped };
}

/**
 * Writes the pack's ciphertext to the blob store under `document/<sha256>`, from the server and not
 * through the public token route, then its verified mark with its size through the writer
 * handleDocumentVerify uses (threat model C28, C44), so the relay's post check accepts it. The name
 * is the SHA-256 of the bytes this server hashed and sent, and the URL the store answers is checked
 * to be the one built from that name and BLOB_ORIGIN, by the one URL parser, before anything is
 * signed for it. A blob left behind by a later refusal has no post on chain, so the document sweep
 * deletes it two hours after its upload.
 *
 * @throws DemoStop 500 server_misconfigured for a BLOB_ORIGIN that is not https, 502 upload_failed
 *   when the store refuses, 502 upload_mismatch for any other URL, 503 store_unavailable when the
 *   mark cannot be written, 503 out_of_time past the deadline.
 */
async function storePack(ctx: DemoSweepContext, ciphertext: Uint8Array, deadline: Deadline): Promise<Hex> {
  if (!isHttpsOrigin(ctx.env.BLOB_ORIGIN)) throw new DemoStop(500, "server_misconfigured");
  const hex = bytesToHex(sha256(ciphertext)).slice(2);
  const pathname = `document/${hex}`;
  let stored: { url: string };
  try {
    stored = await within(deadline, ctx.blobs.put(pathname, ciphertext), "the pack upload");
  } catch (error) {
    throw asStop(error, "upload_failed");
  }
  if (!sameUrl(stored.url, `${ctx.env.BLOB_ORIGIN}/${pathname}`)) throw new DemoStop(502, "upload_mismatch");
  try {
    await writeVerifiedMark(ctx.store, hex, ciphertext.length);
  } catch {
    throw new DemoStop(503, "store_unavailable");
  }
  return `0x${hex}`;
}

/**
 * Posts the demo pack for the demo board's current epoch when that epoch has none (threat model
 * C33, C41, C44), so every guest admitted to the board can open a pack.
 *
 * Under the "demo:join" lock the removals and joins take (150 s, waiting at most 20 s, else refused
 * busy), on its own 120 s deadline, and on the wall clock read once the lock is held, never on
 * `ctx.now`: the board is read at the latest block, its chair checked to be the bot. A board whose
 * documentCount is above 0 and whose latest document's epoch is the board's epoch answers current,
 * having reserved, opened, stored and signed nothing. Otherwise, in order: one of this clock hour's
 * demo relays reserved (refused demo_busy); the current epoch's key opened as the demo chair from
 * an envelope whose size and SHA-256 match the record (openCurrentEpochKey, an OpenedEpochKey,
 * C12); a fresh docRef; the pack text (demoPack.ts) as UTF-8, encrypted under that key with
 * encryptDocument; the ciphertext stored with its verified mark (storePack); postDocument built from
 * the bot's own board read and signed by the demo chair with signBoardAction, its deadline
 * DEMO_ACTION_SECONDS after that read's block time; then relayed through handleRelay in scope
 * "demo", so the demo's daily ledger and the post bytes budget apply, and its receipt waited for.
 * The bot signs nothing that came from a caller: there is no caller.
 *
 * A post's epoch is the one the board read showed, so a call after a pass that moved the epoch
 * several times posts once, for the last. A second call, or one that waited for the lock behind
 * this one, finds the pack in place. A post signed at a board nonce another action still holds in
 * flight is refused by the relay (409 nonce_in_flight). Any refusal changes nothing for any member.
 *
 * @returns posted, with the transaction (a claim it was sent, landed or not) and the epoch; current;
 *   or refused with a short reason: not_ready, pack_unavailable, busy, demo_busy, a board read or
 *   envelope refusal as a join gets them, storePack's, a relay refusal, reverted or out_of_time.
 *   Never throws.
 */
export async function ensureCurrentPack(sweep: DemoSweepContext): Promise<PackOutcome> {
  const boardId = sweep.env.DEMO_BOARD_ID;
  if (boardId === undefined || sweep.env.DEMO_CHAIR_MNEMONIC === undefined) return { done: "refused", reason: "not_ready" };
  const pack = DEMO_PACK;
  if (pack === undefined) return { done: "refused", reason: "pack_unavailable" };
  const deadline = startDeadline(DEMO_DEADLINE_MS, sweep.clock);
  const postLocked = async (): Promise<PackOutcome> => {
    // A run can start minutes after the join or sweep that asked for it, and waits on the lock.
    const run: DemoSweepContext = { ...sweep, now: (sweep.wallClock ?? Date.now)() };
    const chair = await demoChair(run.env);
    const snapshot = await readOwnBoard(run, boardId, chair, deadline);
    if (snapshot.documentCount > 0 && snapshot.latestDocumentEpoch === snapshot.epoch) return { done: "current" };
    if (!(await reserveDemoRelays(run.store, run.now, 1))) return { done: "refused", reason: "demo_busy" };
    const epochKey = await openCurrentEpochKey({
      snapshot,
      sealKeys: chair.seal,
      blobs: run.blobs,
      blobOrigin: run.env.BLOB_ORIGIN,
      signal: AbortSignal.timeout(Math.max(1, Math.floor(leftMs(deadline)))),
    });
    const docRef = bytesToHex(newDocRef());
    let ciphertext: Uint8Array;
    try {
      ciphertext = await encryptDocument({ epochKey, registry: REGISTRY_ADDRESS, boardRef: snapshot.boardRef, epoch: snapshot.epoch, docRef, plaintext: pack });
    } finally {
      epochKey.fill(0);
    }
    const cipherHash = await storePack(run, ciphertext, deadline);
    const body = signedAction(chair, snapshot, { kind: "post", docRef, cipherHash, cipherSize: BigInt(ciphertext.length), epoch: snapshot.epoch });
    const { txHash, landed } = await relayAndWait(run, SWEEP_CLIENT_IP, body, deadline, { value: false });
    logEvent("demo_pack_posted", { boardId: boardId.toString(), epoch: snapshot.epoch.toString(), size: ciphertext.length, txHash, landed });
    return { done: "posted", txHash, epoch: snapshot.epoch };
  };
  try {
    return await sweep.store.withLock(DEMO_LOCK, DEMO_LOCK_TTL_SECONDS, postLocked, { waitMs: DEMO_LOCK_WAIT_MS });
  } catch (error) {
    const reason = error instanceof LockBusy ? "busy" : asStop(error, "pack_failed").reason;
    logEvent("demo_pack_refused", { reason });
    return { done: "refused", reason };
  }
}
