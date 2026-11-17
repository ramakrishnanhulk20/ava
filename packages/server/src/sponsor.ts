import { toHex, toQor1 } from "@ava/core";
import { fetchPqcStatus, msg } from "@qorechain/sdk";
import { bytesToHex, type Hex } from "viem";
import { z } from "zod";
import { publicAddress, relayerFromMnemonic, type RelayerAccount, type RelayerAddress } from "./chain/account.ts";
import { leftMs, startDeadline, within, type Deadline } from "./chain/deadline.ts";
import { evmClient } from "./chain/evm.ts";
import { balanceOf, sendNative } from "./chain/native.ts";
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
import { declaredLength, json, readCapped, refuse, TooLarge, type HandlerContext } from "./http.ts";
import { logEvent } from "./log.ts";
import { clientKey } from "./ratelimit.ts";
import { accountBytesStrict } from "./requestAddress.ts";
import { LockBusy, type SharedStore } from "./store.ts";

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
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readCapped(request.body, BODY_CAP)));
  } catch (error) {
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

  // The once-per-address mark is written before anything is sent. A second request for this
  // address answers 409 even if this send then fails: there are no retries, by design, so no
  // failure, lost answer or race can ever turn into a second payment to one account.
  let first: boolean;
  try {
    first = await ctx.store.setIfAbsent(sponsoredKey(account), String(ctx.now), SPONSOR_MARK_SECONDS);
  } catch {
    return refusal(503, "store_unavailable", fields);
  }
  if (!first) return refusal(409, "already_sponsored", fields);

  try {
    const count = await ctx.store.incrWindow(day.count, DAY_KEY_SECONDS);
    const spent = await ctx.store.incrWindow(day.spend, DAY_KEY_SECONDS, Number(COST_UQOR));
    if (count > limits.perDay || BigInt(spent) > limits.dailyCapUqor) return refusal(503, "daily_limit", { ...fields, limit: "race" }, tomorrow);
  } catch {
    return refusal(503, "store_unavailable", fields);
  }

  let hash: string;
  try {
    hash = await ctx.chain.send(qor1, deadline);
  } catch {
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
 * Admission, in order: POST only (405); this IP's hourly limit, counted before the body is read
 * (429); `application/json` (415); at most 256 bytes (413); exactly `{ address }`, decoded by the
 * strict shared address codec (qor1, or 0x in exact EIP-55 form), never the zero account (400); an
 * address already sponsored (409); the
 * chain's answers, read with timeouts, where any failed lookup refuses (502): an address with
 * contract code, any post-quantum key on file, or any uqor balance above 0, is not eligible (403).
 *
 * Then, under the shared lock "sponsor:send" (waiting up to 20 s, else 503 busy): at least 15 s of
 * the 55 s budget left (503 out_of_time); the day's 100 sends and 25 QOR, amount and fee counted
 * (503 daily_limit until UTC midnight); the once-per-address mark written atomically (409 if another
 * request won); the day's counters; one hybrid-signed MsgSend of SPONSOR_AMOUNT_UQOR, waited for
 * until its block. Classical keys never send it. A store failure anywhere refuses (503).
 *
 * @returns 202 with `{ txHash }` only: the committed transaction's hash, never a claim that the
 *   identity is ready. The caller reads its balance before registering keys.
 */
export async function handleSponsor(request: Request, ctx: SponsorContext): Promise<Response> {
  const deadline = startDeadline(SPONSOR_DEADLINE_MS, ctx.clock);
  if (request.method !== "POST") return refusal(405, "method_not_allowed", {}, { allow: "POST" });
  const limits = ctx.limits ?? SPONSOR_LIMITS;
  const retry = { "retry-after": String(limits.windowSeconds) };
  const ip = clientKey(ctx.clientIp);
  if (ip === undefined) return refusal(429, "rate_limited", { limit: "bad_client_ip" }, retry);
  try {
    if ((await ctx.store.incrWindow(`rate:sponsor:ip:${ip}`, limits.windowSeconds)) > limits.perIp) {
      return refusal(429, "rate_limited", { ip, limit: "per_ip" }, retry);
    }
  } catch {
    return refusal(429, "rate_limited", { limit: "store_error" }, retry);
  }

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
