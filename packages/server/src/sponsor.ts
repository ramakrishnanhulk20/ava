import { randomUUID } from "node:crypto";
import { toHex, toQor1 } from "@ava/core";
import { BroadcastTxError } from "@cosmjs/stargate";
import { fetchPqcStatus, msg } from "@qorechain/sdk";
import { bytesToHex, type Hex } from "viem";
import { z } from "zod";
import { publicAddress, relayerFromMnemonic, type RelayerAccount, type RelayerAddress } from "./chain/account.ts";
import { leftMs, startDeadline, within, type Deadline } from "./chain/deadline.ts";
import { evmClient } from "./chain/evm.ts";
import { RefusedBeforeInclusion, balanceOf, sendNative } from "./chain/native.ts";
import {
  DENOM,
  HTTP,
  LOCK_TTL_SECONDS,
  NATIVE_TX_BUDGET_MS,
  REST,
  SPONSOR_AMOUNT_UQOR,
  SPONSOR_DEADLINE_MS,
  SPONSOR_LIMITS,
  SPONSOR_LOCK_WAIT_MS,
  SPONSOR_SEND_FEE,
  SPONSOR_SEND_FEE_UQOR,
} from "./config.ts";
import { BodyTimeout, declaredLength, json, readBody, refuse, refuseCrossSite, TooLarge, type HandlerContext } from "./http.ts";
import { logEvent } from "./log.ts";
import { countClient } from "./ratelimit.ts";
import { accountBytesStrict } from "./requestAddress.ts";
import { LockBusy, claimOnce, type SharedStore } from "./store.ts";

/**
 * What the sponsor endpoint needs from the chain. The live implementation keeps the sponsor's keys
 * inside its closure; a handler holding this object cannot leak one.
 */
export interface SponsorChain {
  /** Whether the account has any post-quantum key on file (REST /qorechain/pqc/v1/account). Throws when the answer is unknown. */
  hasPqKey(qor1: string): Promise<boolean>;
  /** The account's uqor balance. Throws when it cannot be read. */
  balance(qor1: string): Promise<bigint>;
  /** Whether eth_getCode on the public EVM JSON-RPC shows contract code at the address. Throws when it cannot be read. */
  hasCode(evm: Hex): Promise<boolean>;
  /**
   * Sends exactly SPONSOR_AMOUNT_UQOR from the sponsor to `toQor1` by one hybrid-signed MsgSend and
   * resolves with the committed hash, all by `deadline`. The amount is not a parameter on purpose.
   * Throws RefusedBeforeInclusion (or the cosmjs BroadcastTxError it wraps) only when the node
   * refused the transaction before any block, so nothing can land.
   */
  send(toQor1: string, deadline: Deadline): Promise<string>;
}

export interface SponsorLimits {
  perIp: number;
  windowSeconds: number;
  perDay: number;
  dailyCapUqor: bigint;
}

export type SponsorContext = HandlerContext & {
  /** The sponsor's public addresses. Its keys live only inside `chain`. */
  sponsor: RelayerAddress;
  chain: SponsorChain;
  /** Overrides SPONSOR_LIMITS. */
  limits?: SponsorLimits;
  /** A monotonic clock in milliseconds for the time budget; the process's own by default. */
  clock?: () => number;
};

export const SPONSOR_LOCK = "sponsor:send";
/** An address is sponsored once, ever. SharedStore writes always carry a lifetime, so ten years stands for ever. */
export const SPONSOR_MARK_SECONDS = 315_360_000;
/** A day's counters outlive their day, so a late request near midnight never starts afresh. */
const DAY_KEY_SECONDS = 2 * 86_400;
/** `{"address":"qor1..."}` is under 70 bytes. */
const BODY_CAP = 256;
// The daily cap counts the amount plus the fee of every send, the most one send can lose, so at
// 0.31 QOR a send the 25 QOR cap stops sponsoring at 80 a day, before the count of 100 is reached.
const COST_UQOR = SPONSOR_AMOUNT_UQOR + SPONSOR_SEND_FEE_UQOR;

const SponsorBody = z.strictObject({ address: z.string().max(64) });

/**
 * Whether a failed send certainly sent nothing: the node refused it at broadcast, before any block.
 * sendNative turns the cosmjs BroadcastTxError into RefusedBeforeInclusion; both mean the same.
 */
const refusedBeforeInclusion = (error: unknown): boolean => error instanceof RefusedBeforeInclusion || error instanceof BroadcastTxError;

/** The once-per-address mark, keyed on the 20 bytes so every form of one account lands on one key (C16). */
export function sponsoredKey(account: Uint8Array): string {
  return `sponsor:once:${bytesToHex(account)}`;
}

/** The day's send count and spend (amount plus fee) for the UTC day of `now`. */
export function sponsorDayKeys(now: number): { count: string; spend: string } {
  const day = new Date(now).toISOString().slice(0, 10);
  return { count: `sponsor:count:${day}`, spend: `sponsor:spend:${day}` };
}

type Fields = Record<string, string | number | boolean>;

function refusal(status: number, reason: string, fields: Fields = {}, headers: Record<string, string> = {}): Response {
  logEvent("sponsor_refused", { reason, status, ...fields });
  return refuse(status, reason, headers);
}

/** Seconds until the next UTC midnight, when the day's counters start again. */
function untilTomorrow(now: number): string {
  const next = new Date(now);
  next.setUTCHours(24, 0, 0, 0);
  return String(Math.max(1, Math.ceil((next.getTime() - now) / 1000)));
}

async function readCount(store: SharedStore, key: string): Promise<bigint> {
  const raw = await store.get(key);
  if (raw === null) return 0n;
  if (!/^\d{1,15}$/.test(raw)) throw new Error("A sponsor counter holds an unexpected value.");
  return BigInt(raw);
}

async function readAccount(request: Request): Promise<{ account: Uint8Array } | { response: Response }> {
  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") return { response: refusal(415, "json_only") };
  const stated = declaredLength(request);
  if (stated !== undefined && stated > BODY_CAP) return { response: refusal(413, "body_too_large") };
  if (request.body === null) return { response: refusal(400, "bad_body") };
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBody(request.body, BODY_CAP)));
  } catch (error) {
    if (error instanceof BodyTimeout) return { response: refusal(408, "body_timeout") };
    return { response: error instanceof TooLarge ? refusal(413, "body_too_large") : refusal(400, "bad_body") };
  }
  const checked = SponsorBody.safeParse(parsed);
  if (!checked.success) return { response: refusal(400, "bad_body") };
  let account: Uint8Array;
  try {
    account = accountBytesStrict(checked.data.address);
  } catch {
    return { response: refusal(400, "bad_address") };
  }
  // Nobody holds the key of the zero account, so anything sent there is gone.
  if (account.every((b) => b === 0)) return { response: refusal(400, "bad_address") };
  return { account };
}

/** Takes the address's mark back after a refusal that sent nothing. A failure is logged; a mark not yet kept still ends with the lock. */
async function releaseMark(store: SharedStore, account: Uint8Array, fields: Fields): Promise<void> {
  await store.delete(sponsoredKey(account)).catch(() => logEvent("sponsor_mark_release_failed", fields));
}

/**
 * Makes the address's mark permanent, as this request wrote it. With `next` equal to `expected`, a
 * retried write that had already landed still answers true; false means the mark is no longer this
 * request's or the store failed, so nothing may be sent.
 */
async function keepMark(store: SharedStore, account: Uint8Array, mine: string): Promise<boolean> {
  try {
    return await store.compareAndSet(sponsoredKey(account), mine, mine, SPONSOR_MARK_SECONDS);
  } catch {
    return false;
  }
}

/** Everything that spends, while holding "sponsor:send": one send at a time, so the sponsor's sequence never collides. */
async function sendOnce(ctx: SponsorContext, account: Uint8Array, qor1: string, limits: SponsorLimits, deadline: Deadline, fields: Fields): Promise<Response> {
  if (leftMs(deadline) < NATIVE_TX_BUDGET_MS) return refusal(503, "out_of_time", fields, { "retry-after": "30" });
  const day = sponsorDayKeys(ctx.now);
  const tomorrow = { "retry-after": untilTomorrow(ctx.now) };
  try {
    // Checked before the mark, so a refusal for the day never uses up the address's one chance.
    const [count, spent] = await Promise.all([readCount(ctx.store, day.count), readCount(ctx.store, day.spend)]);
    if (count + 1n > BigInt(limits.perDay)) return refusal(503, "daily_limit", { ...fields, limit: "per_day" }, tomorrow);
    if (spent + COST_UQOR > limits.dailyCapUqor) return refusal(503, "daily_limit", { ...fields, limit: "daily_cap" }, tomorrow);
  } catch {
    return refusal(503, "store_unavailable", fields);
  }

  // The once-per-address mark lives only as long as the lock until the send is about to start, so a
  // refusal before it gives the address its chance back, even when taking the mark back fails too.
  // Its value is this request's alone: two requests for one address can arrive in one millisecond,
  // and the read-back that counts a retried write as this request's must never count the other's.
  const mine = `${ctx.now}:${randomUUID()}`;
  let first: boolean;
  try {
    first = await claimOnce(ctx.store, sponsoredKey(account), mine, LOCK_TTL_SECONDS);
  } catch {
    return refusal(503, "store_unavailable", fields);
  }
  if (!first) return refusal(409, "already_sponsored", fields);

  try {
    const count = await ctx.store.incrWindow(day.count, DAY_KEY_SECONDS);
    const spent = await ctx.store.incrWindow(day.spend, DAY_KEY_SECONDS, Number(COST_UQOR));
    if (count > limits.perDay || BigInt(spent) > limits.dailyCapUqor) {
      await releaseMark(ctx.store, account, fields);
      return refusal(503, "daily_limit", { ...fields, limit: "race" }, tomorrow);
    }
  } catch {
    await releaseMark(ctx.store, account, fields);
    return refusal(503, "store_unavailable", fields);
  }

  // From here a lost answer or a timeout may still land, so the mark is kept for good before the
  // send starts: a second request answers 409 even if this send fails, unless the node refused it
  // before any block, and no failure can turn into a second payment.
  if (!(await keepMark(ctx.store, account, mine))) {
    await releaseMark(ctx.store, account, fields);
    return refusal(503, "store_unavailable", fields);
  }

  let hash: string;
  try {
    hash = await ctx.chain.send(qor1, deadline);
  } catch (error) {
    if (refusedBeforeInclusion(error)) {
      await releaseMark(ctx.store, account, fields);
      return refusal(502, "send_failed", { ...fields, mark: "released" });
    }
    return refusal(502, "send_failed", fields);
  }
  if (!/^[0-9A-F]{64}$/.test(hash)) return refusal(502, "send_failed", fields);
  logEvent("sponsor_sent", { ...fields, txHash: hash, amountUqor: Number(SPONSOR_AMOUNT_UQOR), feeUqor: Number(SPONSOR_SEND_FEE_UQOR) });
  return json(202, { txHash: hash });
}

/**
 * Sends a new identity the QOR for its two key registrations, once (threat model C16, C23, C27,
 * C31, C32).
 *
 * Admission, in order: a request another site's page could have sent (403 cross_site), before
 * anything is counted or read; POST only (405); this IP's hourly limit, counted before the body is
 * read, with every /64 of one IPv6 /48 also sharing 4 times it (countClient, 429);
 * `application/json` (415); at most 256 bytes (413), ending within 20 seconds (408
 * body_timeout); exactly `{ address }`, decoded by the
 * strict shared address codec (qor1, or 0x in exact EIP-55 form), never the zero account (400); an
 * address already sponsored (409); the
 * chain's answers, read with timeouts, where any failed lookup refuses (502): an address with
 * contract code, any post-quantum key on file, or any uqor balance above 0, is not eligible (403).
 *
 * Then, under the shared lock "sponsor:send" (waiting up to 20 s, else 503 busy): at least 15 s of
 * the 55 s budget left (503 out_of_time); the day's 100 sends and 25 QOR, amount and fee counted
 * (503 daily_limit until UTC midnight); the once-per-address mark written atomically with a value
 * this request alone holds, living only the lock's 60 s for now (409 if another request won; a
 * write retried after a lost reply reads back as this request's, claimOnce); the day's counters, the mark taken back if
 * they refuse (503 daily_limit) or fail; the mark made permanent; one hybrid-signed MsgSend of
 * SPONSOR_AMOUNT_UQOR, waited for until its block. Classical keys never send it. A store failure
 * anywhere refuses (503), and before the send it never uses up the address's chance. A failed
 * send answers 502 send_failed and keeps the mark, so no lost answer can become a second payment;
 * only a send the node refused before any block (RefusedBeforeInclusion, the cosmjs
 * BroadcastTxError) gives the mark back, because nothing of it can land.
 *
 * @returns 202 with `{ txHash }` only: the committed transaction's hash, never a claim that the
 *   identity is ready. The caller reads its balance before registering keys.
 */
export async function handleSponsor(request: Request, ctx: SponsorContext): Promise<Response> {
  const crossSite = refuseCrossSite(request);
  if (crossSite !== undefined) return crossSite;
  const deadline = startDeadline(SPONSOR_DEADLINE_MS, ctx.clock);
  if (request.method !== "POST") return refusal(405, "method_not_allowed", {}, { allow: "POST" });
  const limits = ctx.limits ?? SPONSOR_LIMITS;
  const retry = { "retry-after": String(limits.windowSeconds) };
  // Per IP, and per IPv6 /48 at 4 times that, with the one rule every endpoint uses (C23).
  const client = await countClient(ctx.store, { scope: "sponsor", clientIp: ctx.clientIp, perIp: limits.perIp, windowSeconds: limits.windowSeconds });
  if (!client.ok) return refusal(429, "rate_limited", { limit: client.refusedBy ?? "per_ip" }, retry);

  const read = await readAccount(request);
  if ("response" in read) return read.response;
  const { account } = read;
  const qor1 = toQor1(account);
  const fields: Fields = { address: qor1 };

  try {
    if ((await ctx.store.get(sponsoredKey(account))) !== null) return refusal(409, "already_sponsored", fields);
  } catch {
    return refusal(503, "store_unavailable", fields);
  }

  let hasKey: boolean;
  let balance: bigint;
  let hasCode: boolean;
  try {
    [hasKey, balance, hasCode] = await within(
      deadline,
      Promise.all([ctx.chain.hasPqKey(qor1), ctx.chain.balance(qor1), ctx.chain.hasCode(toHex(account))]),
      "the eligibility reads",
    );
  } catch {
    return refusal(502, "chain_unreachable", fields);
  }
  // A contract can never register a key, so whatever it is sent stays there unused.
  if (hasCode) return refusal(403, "contract_address", fields);
  if (hasKey) return refusal(403, "has_pq_key", fields);
  // C27 "no balance": an account that holds anything at all has been funded by someone already.
  if (balance !== 0n) return refusal(403, "already_funded", fields);

  const waitMs = Math.floor(Math.max(0, Math.min(SPONSOR_LOCK_WAIT_MS, leftMs(deadline) - NATIVE_TX_BUDGET_MS)));
  try {
    return await ctx.store.withLock(SPONSOR_LOCK, LOCK_TTL_SECONDS, () => sendOnce(ctx, account, qor1, limits, deadline, fields), { waitMs });
  } catch (error) {
    if (error instanceof LockBusy) return refusal(503, "busy", fields, { "retry-after": "30" });
    return refusal(503, "store_unavailable", fields);
  }
}

/** The REST read with the server's own timeout and no redirects, because the SDK's read sets neither. */
const timedFetch = (input: string, init?: RequestInit): Promise<Response> =>
  fetch(input, { ...init, redirect: "error", signal: AbortSignal.timeout(HTTP.timeoutMs) });

function liveSponsorChain(account: RelayerAccount): SponsorChain {
  const evm = evmClient();
  return {
    hasPqKey: async (qor1) => (await fetchPqcStatus({ rest: REST, address: qor1, fetch: timedFetch })).registered,
    balance: (qor1) => balanceOf(qor1),
    hasCode: async (address) => {
      const code = await evm.getCode({ address });
      return code !== undefined && code !== "0x";
    },
    send: async (toQor1, deadline) => {
      const message = msg.bank.send({ fromAddress: account.qor1, toAddress: toQor1, amount: [{ denom: DENOM, amount: SPONSOR_AMOUNT_UQOR.toString() }] });
      return (await sendNative(account, "hybrid", [message], SPONSOR_SEND_FEE, deadline)).hash;
    },
  };
}

/** The sponsor's public address and its live chain access, from its phrase: what handleSponsor's context needs. */
export async function liveSponsor(mnemonic: string): Promise<{ sponsor: RelayerAddress; chain: SponsorChain }> {
  const account = await relayerFromMnemonic(mnemonic);
  return { sponsor: publicAddress(account), chain: liveSponsorChain(account) };
}
