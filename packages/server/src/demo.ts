import { KemKeyUnavailable, Mode, accountBytes, challengeMessage, identityFromMnemonic, newEpochKey, sameAccount, sameHash, sealEpochKey, toHex, type Identity } from "@ava/core";
import { mldsa87 } from "@qorechain/pqc";
import { validateMlkemPublicKey } from "@qorechain/qoreseal";
import { bytesToHex, hexToBytes, type Hex } from "viem";
import { z } from "zod";
import type { BlobBackend } from "./blob.ts";
import type { RelayerAddress } from "./chain/account.ts";
import { OutOfTime, elapsedMs, leftMs, startDeadline, within, type Deadline } from "./chain/deadline.ts";
import type { RelayChain } from "./chain/types.ts";
import {
  DEMO_CHALLENGE_LIMITS,
  DEMO_CHALLENGE_SECONDS,
  DEMO_DEADLINE_MS,
  DEMO_GUEST_CAP,
  DEMO_GUEST_TTL_SECONDS,
  DEMO_JOIN_LIMITS,
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
import { requireDemoChairMnemonic, type ServerEnv } from "./env.ts";
import { declaredLength, json, readCapped, refuse, TooLarge, type HandlerContext } from "./http.ts";
import { logEvent } from "./log.ts";
import { clientKey, limit } from "./ratelimit.ts";
import type { RelayContext } from "./relay.ts";
import { accountBytesStrict } from "./requestAddress.ts";
import { LockBusy, type SharedStore } from "./store.ts";

export interface DemoLimits {
  /** Joins per IP per window, and joins with a valid signature per UTC day. */
  join: { perIp: number; windowSeconds: number; perDay: number };
  challenge: { perIp: number; total: number; windowSeconds: number };
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
  /** Passed to the relay for the pause after a window opens. */
  sleep?: (ms: number) => Promise<void>;
};

/** What the scheduled sweep needs: no caller, so no client IP. */
export type DemoSweepContext = Omit<DemoContext, "clientIp" | "limits">;

/** Why the bot removes a guest: its six hours are up, its ML-KEM key is unusable, or a judge needs its seat. */
export type RemovalReason = "expired" | "key_missing" | "key_invalid" | "key_changed" | "board_full";

type Removed = { done: "removed"; member: Hex; reason: RemovalReason; txHash: Hex; epochAfter: string; landed: boolean };

export type SweepOutcome = { done: "not_ready" } | { done: "nothing_due"; guests: number; unknown: number } | Removed | { done: "refused"; reason: string };

export const DEMO_LOCK = "demo:join";
/** An admission is recorded for ten years: "ever admitted" outlives the demo. */
const ADMITTED_SECONDS = 315_360_000;
const DAY_KEY_SECONDS = 2 * 86_400;
const CHALLENGE_BODY_CAP = 256;
/** A join body is about 9.5 KB: the 4,627-byte signature as hex plus four short fields. */
const JOIN_BODY_CAP = 16_384;
/** The sweep acts for nobody outside, so its uploads and relays count under the loopback address. */
const SWEEP_CLIENT_IP = "127.0.0.1";
/** KEM lookups run a few at a time, so a sweep of 39 recipients neither crawls nor floods the RPC. */
const KEM_PARALLEL = 4;
const DEFAULT_LIMITS: DemoLimits = { join: DEMO_JOIN_LIMITS, challenge: DEMO_CHALLENGE_LIMITS };

export const challengeKey = (guest: Uint8Array): string => `demo:challenge:${bytesToHex(guest)}`;
export const admittedKey = (guest: Uint8Array): string => `demo:admitted:${bytesToHex(guest)}`;
const joinDayKey = (now: number): string => `demo:join:count:${new Date(now).toISOString().slice(0, 10)}`;

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

const nowSeconds = (now: number): bigint => BigInt(Math.floor(now / 1000));

async function readJson(request: Request, cap: number): Promise<{ value: unknown } | { response: Response }> {
  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") return { response: refusal(415, "json_only") };
  const stated = declaredLength(request);
  if (stated !== undefined && stated > cap) return { response: refusal(413, "body_too_large") };
  if (request.body === null) return { response: refusal(400, "bad_body") };
  try {
    return { value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readCapped(request.body, cap))) };
  } catch (error) {
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

function challengeAnswer(boardId: bigint, guest: Uint8Array, record: { botNonce: Hex; expiry: bigint }): Response {
  const message = challengeMessage({ registry: REGISTRY_ADDRESS, boardId, guest: toHex(guest), botNonce: record.botNonce, expiry: record.expiry });
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
 * while it lives gets the same challenge back.
 *
 * Refuses with 405 for another method, 503 not_ready before the board is seeded, 429 over the
 * per-IP or total hourly limits, 415, 413 and 400 for a body that is not exactly `{ guest }` with a
 * valid non-zero address, and 503 when the shared store fails.
 */
export async function handleDemoChallenge(request: Request, ctx: DemoContext): Promise<Response> {
  if (request.method !== "POST") return refusal(405, "method_not_allowed", {}, { allow: "POST" });
  const boardId = ctx.env.DEMO_BOARD_ID;
  if (boardId === undefined) return refusal(503, "not_ready");
  const rules = (ctx.limits ?? DEFAULT_LIMITS).challenge;
  const verdict = await limit(ctx.store, { scope: "demo-challenge", clientIp: ctx.clientIp, ...rules });
  if (!verdict.ok) return refusal(429, "rate_limited", {}, { "retry-after": String(verdict.retryAfter) });

  const read = await readJson(request, CHALLENGE_BODY_CAP);
  if ("response" in read) return read.response;
  const checked = ChallengeBody.safeParse(read.value);
  const guest = checked.success ? guestBytes(checked.data.guest) : undefined;
  if (guest === undefined) return refusal(400, "bad_guest");

  const record = { botNonce: freshNonce(), expiry: nowSeconds(ctx.now) + BigInt(DEMO_CHALLENGE_SECONDS) };
  const key = challengeKey(guest);
  try {
    if (await ctx.store.setIfAbsent(key, JSON.stringify({ botNonce: record.botNonce, expiry: record.expiry.toString() }), DEMO_CHALLENGE_SECONDS)) {
      return challengeAnswer(boardId, guest, record);
    }
    const live = parseChallenge(await ctx.store.get(key));
    if (live !== undefined && live.expiry > nowSeconds(ctx.now)) return challengeAnswer(boardId, guest, live);
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

function relayContext(ctx: DemoSweepContext, clientIp: string): RelayContext {
  return { clientIp, now: ctx.now, store: ctx.store, relayer: ctx.relayer, chain: ctx.relayChain, clock: ctx.clock, sleep: ctx.sleep };
}

/**
 * Relays one signed action and waits, within the deadline, for it to land, so the next queued
 * action reads the moved board nonce.
 *
 * @returns The hash and whether its receipt was seen. A send whose outcome is unknown is not
 *   undone: `sent` is true from the moment the relay may have broadcast it.
 */
async function relayAndWait(ctx: DemoSweepContext, clientIp: string, body: Parameters<typeof relayAction>[0], deadline: Deadline, sent: { value: boolean }): Promise<{ txHash: Hex; landed: boolean }> {
  if (elapsedMs(deadline) > DEMO_RELAY_CUTOFF_MS) throw new DemoStop(503, "out_of_time");
  const outcome = await relayAction(body, relayContext(ctx, clientIp));
  if (outcome.txHash === undefined) {
    // Only a lost broadcast can have reached the chain; every other relay refusal sent nothing.
    sent.value = outcome.error === "broadcast_failed";
    throw new DemoStop(outcome.status === 429 || outcome.status === 503 ? outcome.status : 502, `relay_${outcome.error ?? "unknown"}`);
  }
  sent.value = true;
  const status = await ctx.chain.receipt(outcome.txHash, Math.floor(Math.min(DEMO_RECEIPT_WAIT_MS, leftMs(deadline)))).catch(() => undefined);
  if (status === "reverted") {
    sent.value = false;
    throw new DemoStop(502, "reverted");
  }
  return { txHash: outcome.txHash, landed: status === "success" };
}

async function kemKeyFor(ctx: DemoSweepContext, account: Hex, deadline: Deadline): Promise<Uint8Array> {
  try {
    return await within(deadline, ctx.chain.kemKey(account), "the KEM lookup");
  } catch (error) {
    if (error instanceof KemKeyUnavailable && error.reason === "NOT_FOUND") throw new DemoStop(403, "no_kem_key");
    throw new DemoStop(502, "kem_unavailable");
  }
}

/** The admission itself, under the "demo:join" lock. */
async function admit(ctx: DemoContext, boardId: bigint, guest: Uint8Array, deadline: Deadline, sent: { value: boolean }): Promise<Response> {
  const guestHex = toHex(guest);
  const chair = await demoChair(ctx.env);
  let snapshot = await readOwnBoard(ctx, boardId, chair, deadline);
  if (snapshot.members.some((m) => sameAccount(m, guest))) throw new DemoStop(409, "already_member");
  if (snapshot.members.length >= DEMO_GUEST_CAP) snapshot = await makeRoom(ctx, chair, snapshot, deadline);

  const epochKey = await openCurrentEpochKey({
    snapshot,
    sealKeys: chair.seal,
    blobs: ctx.blobs,
    blobOrigin: ctx.env.BLOB_ORIGIN,
    signal: AbortSignal.timeout(Math.max(1, Math.floor(leftMs(deadline)))),
  });
  let envelope: Uint8Array;
  try {
    const kemPublicKey = await kemKeyFor(ctx, guestHex, deadline);
    envelope = sealEpochKey({ registry: REGISTRY_ADDRESS, boardRef: snapshot.boardRef, epoch: snapshot.epoch, epochKey, recipients: [{ address: guestHex, kemPublicKey }] });
  } finally {
    epochKey.fill(0);
  }
  const uploaded = await within(deadline, uploadEnvelope(envelope, { clientIp: ctx.clientIp, now: ctx.now, store: ctx.store, blobs: ctx.blobs, blobOrigin: ctx.env.BLOB_ORIGIN }), "the envelope upload");
  const body = signedAction(chair, snapshot, {
    kind: "add",
    member: guestHex,
    mode: Mode.SEAL_CURRENT,
    envelopeHash: uploaded.hash,
    envelopeSize: uploaded.size,
    epochAfter: snapshot.epoch,
  });
  const { txHash } = await relayAndWait(ctx, ctx.clientIp, body, deadline, sent);
  logEvent("demo_admitted", { boardId: boardId.toString(), guest: guestHex, epoch: snapshot.epoch.toString(), txHash });
  return json(202, { txHash });
}

/** The once-per-guest mark, then the admission; the mark is taken back whenever nothing was sent. */
async function joinOnce(ctx: DemoContext, boardId: bigint, guest: Uint8Array, deadline: Deadline): Promise<Response> {
  const fields: Fields = { guest: toHex(guest) };
  try {
    if (!(await ctx.store.setIfAbsent(admittedKey(guest), String(ctx.now), ADMITTED_SECONDS))) return refusal(409, "already_admitted", fields);
  } catch {
    return refusal(503, "store_unavailable", fields);
  }
  const sent = { value: false };
  try {
    return await admit(ctx, boardId, guest, deadline, sent);
  } catch (error) {
    if (!sent.value) {
      await ctx.store.delete(admittedKey(guest)).catch(() => logEvent("demo_mark_release_failed", fields));
    }
    const stop = asStop(error, "join_failed");
    return refusal(stop.status, stop.reason, fields, stop.status === 503 || stop.status === 429 ? { "retry-after": "30" } : {});
  }
}

/**
 * Admits one guest to the demo board (threat model C12, C15, C16, C33, C34, C35, C37, C41, C43).
 *
 * POST `{ guest, botNonce, expiry, signature }` as JSON; any other field is dropped unread. In order,
 * with nothing opened or signed until all of them pass: POST only (405); the board seeded and the
 * demo chair's phrase set (503 not_ready); this IP's hourly join limit (429); the body (415, 413,
 * 400, and 400 bad_guest for anything but qor1 or exact EIP-55); the guest's stored challenge (409
 * no_challenge); botNonce and expiry equal to the stored ones (403 challenge_mismatch) and the
 * expiry not passed (403 challenge_expired); the guest's key from pqcKeyStatus, all four values:
 * registered, algorithm 1, possession proven, 2,592 bytes (403 no_proven_key); a pure ML-DSA-87
 * signature, empty context, over the challenge bytes the bot rebuilds from its own record (403
 * bad_signature). Every refusal so far leaves the challenge in place. Only then is the challenge
 * deleted, going on only if the delete reported a removal, so one challenge serves one join at
 * most (409 no_challenge); then never admitted before (409 already_admitted) and the day's total
 * (503 daily_limit).
 *
 * Then, under the lock "demo:join" (150 s, waiting at most 20 s, else 503 busy), all inside one
 * 120 s deadline: the once-per-guest mark; the board read at one block, its chair checked to be the
 * bot; the guest not a member (409); at DEMO_GUEST_CAP, the oldest guest removed first by the
 * sweep's own removal and the board read again once it lands (409 board_full when no guest can go,
 * 503 when the removal is refused or its receipt is not seen); the current
 * epoch's envelope downloaded by its on-chain hash and opened only once its size and SHA-256 match
 * the record (502 envelope_mismatch otherwise); the guest's ML-KEM key from fetchKemKey (403
 * no_kem_key, 502 on any other failure); the epoch key sealed to the guest alone; the envelope
 * uploaded through handleUpload; addMember (SEAL_CURRENT, epochAfter = the epoch read) built and
 * signed by the bot; handleRelay, started no later than 65 s in (503 out_of_time); then the receipt,
 * waited for up to 30 s. If nothing was sent, the mark is taken back so the guest can try again.
 *
 * @returns 202 `{ txHash }`: a claim that the addMember was sent, which the browser confirms on chain (C26).
 */
export async function handleDemoJoin(request: Request, ctx: DemoContext): Promise<Response> {
  const deadline = startDeadline(DEMO_DEADLINE_MS, ctx.clock);
  if (request.method !== "POST") return refusal(405, "method_not_allowed", {}, { allow: "POST" });
  const boardId = ctx.env.DEMO_BOARD_ID;
  if (boardId === undefined || ctx.env.DEMO_CHAIR_MNEMONIC === undefined) return refusal(503, "not_ready");
  const rules = (ctx.limits ?? DEFAULT_LIMITS).join;
  const retry = { "retry-after": String(rules.windowSeconds) };
  const ip = clientKey(ctx.clientIp);
  if (ip === undefined) return refusal(429, "rate_limited", { limit: "bad_client_ip" }, retry);
  try {
    if ((await ctx.store.incrWindow(`rate:demo-join:ip:${ip}`, rules.windowSeconds)) > rules.perIp) return refusal(429, "rate_limited", { ip, limit: "per_ip" }, retry);
  } catch {
    return refusal(429, "rate_limited", { limit: "store_error" }, retry);
  }

  const read = await readJson(request, JOIN_BODY_CAP);
  if ("response" in read) return read.response;
  const checked = JoinBody.safeParse(read.value);
  if (!checked.success) return refusal(400, "bad_body");
  const guest = guestBytes(checked.data.guest);
  if (guest === undefined) return refusal(400, "bad_guest");
  const fields: Fields = { guest: toHex(guest) };

  let stored: { botNonce: Hex; expiry: bigint } | undefined;
  try {
    stored = parseChallenge(await ctx.store.get(challengeKey(guest)));
  } catch {
    return refusal(503, "store_unavailable", fields);
  }
  if (stored === undefined) return refusal(409, "no_challenge", fields);
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

  // Only a join that proves the challenge consumes it (threat model C43), so a stranger naming this
  // guest cannot cancel it. Of two racing joins, exactly one delete reports the removal.
  try {
    if (!(await ctx.store.delete(challengeKey(guest)))) return refusal(409, "no_challenge", fields);
  } catch {
    return refusal(503, "store_unavailable", fields);
  }

  try {
    if ((await ctx.store.get(admittedKey(guest))) !== null) return refusal(409, "already_admitted", fields);
    if ((await ctx.store.incrWindow(joinDayKey(ctx.now), DAY_KEY_SECONDS)) > rules.perDay) {
      return refusal(503, "daily_limit", { ...fields, limit: "per_day" }, { "retry-after": untilTomorrow(ctx.now) });
    }
  } catch {
    return refusal(503, "store_unavailable", fields);
  }

  const waitMs = Math.floor(Math.max(0, Math.min(DEMO_LOCK_WAIT_MS, DEMO_RELAY_CUTOFF_MS - elapsedMs(deadline))));
  try {
    return await ctx.store.withLock(DEMO_LOCK, DEMO_LOCK_TTL_SECONDS, () => joinOnce(ctx, boardId, guest, deadline), { waitMs });
  } catch (error) {
    if (error instanceof LockBusy) return refusal(503, "busy", fields, { "retry-after": "30" });
    return refusal(503, "store_unavailable", fields);
  }
}

async function admittedAt(store: SharedStore, member: Hex): Promise<number | undefined> {
  const raw = await store.get(admittedKey(accountBytes(member)));
  if (raw === null || !/^\d{1,16}$/.test(raw)) return undefined;
  return Number(raw);
}

type KeyProblem = "key_missing" | "key_invalid" | "key_changed";

/**
 * One member's ML-KEM key as a removal sees it. `unreadable` says nothing about the member: the
 * lookup itself failed (a timeout, the network, a malformed answer), so nobody is judged by it.
 */
type MemberKey = { member: Hex; key: Uint8Array } | { member: Hex; problem: KeyProblem } | { member: Hex; unreadable: true };

interface RemovalPlan {
  member: Hex;
  reason: RemovalReason;
  /** Every member the next epoch is sealed to: all whose key is usable, the one removed excepted. */
  recipients: { address: Hex; kemPublicKey: Uint8Array }[];
}

async function memberKey(ctx: DemoSweepContext, member: Hex, sealed: (key: Uint8Array) => boolean, deadline: Deadline): Promise<MemberKey> {
  let key: Uint8Array;
  try {
    key = await within(deadline, ctx.chain.kemKey(member), "the KEM lookup");
  } catch (error) {
    if (error instanceof KemKeyUnavailable && error.reason === "NOT_FOUND") return { member, problem: "key_missing" };
    if (error instanceof KemKeyUnavailable && (error.reason === "INVALID_KEY" || error.reason === "WRONG_ALGORITHM")) return { member, problem: "key_invalid" };
    return { member, unreadable: true };
  }
  try {
    validateMlkemPublicKey(key);
  } catch {
    return { member, problem: "key_invalid" };
  }
  return sealed(key) ? { member, key } : { member, problem: "key_changed" };
}

/** Every member's key, a few lookups at a time, in the members' order, each checked against the current epoch's envelopes. */
async function memberKeys(ctx: DemoSweepContext, snapshot: BoardSnapshot, deadline: Deadline): Promise<MemberKey[]> {
  const signal = AbortSignal.timeout(Math.max(1, Math.floor(leftMs(deadline))));
  const sealed = await sealedTo({ snapshot, blobs: ctx.blobs, blobOrigin: ctx.env.BLOB_ORIGIN, signal });
  const out: MemberKey[] = [];
  for (let start = 0; start < snapshot.members.length; start += KEM_PARALLEL) {
    const batch = snapshot.members.slice(start, start + KEM_PARALLEL);
    out.push(...(await Promise.all(batch.map((member) => memberKey(ctx, member, sealed, deadline)))));
  }
  return out;
}

/**
 * Picks the one guest to remove and the members the next epoch is sealed to (threat model C34,
 * C41, C42). Every member's ML-KEM key is looked up first. A guest whose key is missing, invalid, or
 * not the one the current epoch was sealed to is the target whatever its age, the oldest admitted
 * first, and every such guest is left out of the next epoch. A problem with the chair's or a seeded
 * director's key logs an alert and removes no one; so does a lookup that fails for any member,
 * because it says nothing about who is at fault. Otherwise the target is the guest admitted
 * longest ago: once its admission is older than DEMO_GUEST_TTL_SECONDS, or at once when `force` is
 * set because a judge needs the seat. A guest with no admission record goes only when `force` finds
 * no guest with one.
 */
async function planRemoval(ctx: DemoSweepContext, snapshot: BoardSnapshot, force: boolean, deadline: Deadline): Promise<RemovalPlan | SweepOutcome> {
  const seeded = ctx.env.DEMO_SEEDED ?? [];
  const isProtected = (m: Hex): boolean => sameAccount(m, snapshot.chair) || seeded.some((s) => sameAccount(s, m));
  const guests = snapshot.members.filter((m) => !isProtected(m));
  if (guests.length === 0) return { done: "nothing_due", guests: 0, unknown: 0 };
  const times = await Promise.all(guests.map((m) => admittedAt(ctx.store, m)));
  const keys = await memberKeys(ctx, snapshot, deadline);
  for (const k of keys) {
    if (isProtected(k.member) && !("key" in k)) {
      logEvent("demo_sweep_alert", { member: k.member, problem: "problem" in k ? k.problem : "kem_unavailable" });
      return { done: "refused", reason: "protected_key_unusable" };
    }
  }
  if (keys.some((k) => "unreadable" in k)) return { done: "refused", reason: "kem_unavailable" };

  const ageOf = new Map(guests.map((m, i) => [m, times[i]]));
  // No admission record sorts last, so a guest of unknown age is never taken before a dated one.
  const rank = (m: Hex): number => ageOf.get(m) ?? Number.MAX_SAFE_INTEGER;
  const oldestFirst = (a: Hex, b: Hex): number => rank(a) - rank(b);
  const bad = keys.flatMap((k) => ("problem" in k ? [k] : [])).sort((a, b) => oldestFirst(a.member, b.member));
  let pick: { member: Hex; reason: RemovalReason } | undefined = bad[0] === undefined ? undefined : { member: bad[0].member, reason: bad[0].problem };
  if (pick === undefined) {
    const oldest = [...guests].sort(oldestFirst)[0];
    const at = oldest === undefined ? undefined : ageOf.get(oldest);
    if (oldest !== undefined && force) pick = { member: oldest, reason: "board_full" };
    else if (oldest !== undefined && at !== undefined && ctx.now - at >= DEMO_GUEST_TTL_SECONDS * 1000) pick = { member: oldest, reason: "expired" };
  }
  if (pick === undefined) return { done: "nothing_due", guests: guests.length, unknown: times.filter((t) => t === undefined).length };
  const target = pick.member;
  const recipients = keys.flatMap((k) => ("key" in k && !sameAccount(k.member, target) ? [{ address: k.member, kemPublicKey: k.key }] : []));
  return { member: target, reason: pick.reason, recipients };
}

/**
 * Removes the planned guest: a fresh epoch key sealed to the plan's recipients, the envelope
 * uploaded through handleUpload, removeMember signed by the demo chair and relayed through
 * handleRelay, then its receipt waited for.
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
  const uploaded = await within(deadline, uploadEnvelope(envelope, { clientIp, now: ctx.now, store: ctx.store, blobs: ctx.blobs, blobOrigin: ctx.env.BLOB_ORIGIN }), "the envelope upload");
  // A chain read may give lowercase hex; the relay takes an address only in its EIP-55 form.
  const member = toHex(accountBytes(plan.member));
  const body = signedAction(chair, snapshot, { kind: "remove", member, envelopeHash: uploaded.hash, envelopeSize: uploaded.size, epochAfter });
  const { txHash, landed } = await relayAndWait(ctx, clientIp, body, deadline, { value: false });
  logEvent("demo_guest_removed", { boardId: snapshot.boardId.toString(), member, reason: plan.reason, epochAfter: epochAfter.toString(), txHash, landed });
  return { done: "removed", member, reason: plan.reason, txHash, epochAfter: epochAfter.toString(), landed };
}

/**
 * Frees one seat on a full board before a judge is admitted (threat model C41), by the same
 * removal the sweep makes, then reads the board again. The admission is signed with the board's
 * next nonce, so it goes on only once the removal's receipt has been seen.
 */
async function makeRoom(ctx: DemoContext, chair: Identity, snapshot: BoardSnapshot, deadline: Deadline): Promise<BoardSnapshot> {
  const plan = await planRemoval(ctx, snapshot, true, deadline);
  if ("done" in plan) throw plan.done === "refused" ? new DemoStop(503, plan.reason) : new DemoStop(409, "board_full");
  const removed = await removeGuest(ctx, chair, snapshot, plan, ctx.clientIp, deadline);
  if (!removed.landed) throw new DemoStop(503, "busy");
  const after = await readOwnBoard(ctx, snapshot.boardId, chair, deadline);
  if (after.members.length >= DEMO_GUEST_CAP) throw new DemoStop(409, "board_full");
  return after;
}

async function sweepOnce(ctx: DemoSweepContext, boardId: bigint, deadline: Deadline): Promise<SweepOutcome> {
  const chair = await demoChair(ctx.env);
  const snapshot = await readOwnBoard(ctx, boardId, chair, deadline);
  const plan = await planRemoval(ctx, snapshot, false, deadline);
  if ("done" in plan) return plan;
  return removeGuest(ctx, chair, snapshot, plan, SWEEP_CLIENT_IP, deadline);
}

/**
 * Removes at most one demo guest per call (threat model C34, C42). Every remaining member's ML-KEM
 * key is looked up first and checked against the current epoch's envelopes. A guest whose key is
 * missing, invalid, or changed since the board was sealed to it is removed first, whatever its age;
 * otherwise the guest admitted longest ago, once its admission is older than DEMO_GUEST_TTL_SECONDS
 * (six hours). The chair and every DEMO_SEEDED director are never candidates: a problem with one of
 * their keys, or a lookup that fails, logs an alert and removes no one. A member with no admission
 * record is never removed for its age. The new epoch key is fresh and sealed to every remaining
 * member whose key is usable, with the key fetchKemKey returns for each (C15). The envelope goes
 * through handleUpload, the removeMember is signed by the demo chair and relayed through
 * handleRelay, under the same "demo:join" lock and 120 s deadline as a join.
 *
 * @returns What it did: not_ready, nothing_due (with the number of guests and of guests with no
 *   admission record), removed (with why, the transaction and whether its receipt was seen), or
 *   refused with a short reason. Never throws for a failed step.
 */
export async function sweepDemoGuests(ctx: DemoSweepContext): Promise<SweepOutcome> {
  const boardId = ctx.env.DEMO_BOARD_ID;
  if (boardId === undefined || ctx.env.DEMO_CHAIR_MNEMONIC === undefined) return { done: "not_ready" };
  const deadline = startDeadline(DEMO_DEADLINE_MS, ctx.clock);
  let outcome: SweepOutcome;
  try {
    outcome = await ctx.store.withLock(DEMO_LOCK, DEMO_LOCK_TTL_SECONDS, () => sweepOnce(ctx, boardId, deadline), { waitMs: DEMO_LOCK_WAIT_MS });
  } catch (error) {
    outcome = { done: "refused", reason: error instanceof LockBusy ? "busy" : asStop(error, "sweep_failed").reason };
  }
  if (outcome.done === "refused") logEvent("demo_sweep_refused", { reason: outcome.reason });
  return outcome;
}
