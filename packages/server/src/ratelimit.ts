import { isIP } from "node:net";
import { logEvent } from "./log.ts";
import type { SharedStore } from "./store.ts";

export interface LimitRule {
  /** Which endpoint is counting, like "proxy" or "upload". Lowercase letters, digits, "-" and "_". */
  scope: string;
  /** The caller's IP as the hosting platform reports it, never a header the client sets. */
  clientIp: string;
  perIp: number;
  total: number;
  windowSeconds: number;
}

export interface BudgetRule {
  scope: string;
  clientIp: string;
  /** The most this IP may spend in one window, in whatever unit the caller counts (bytes for uploads). */
  max: number;
  windowSeconds: number;
}

/**
 * `ok` false means refuse. `retryAfter` is in seconds: 0 when ok, otherwise the window length,
 * which is the longest the caller can have to wait (the window may end sooner).
 */
export interface LimitResult {
  ok: boolean;
  retryAfter: number;
}

const SCOPE = /^[a-z0-9_-]{1,32}$/;
const FALLBACK_RETRY_SECONDS = 60;

function ipv6Groups(compressed: string): number[] | undefined {
  const halves = compressed.split("::");
  if (halves.length > 2) return undefined;
  const parse = (part: string): number[] => (part === "" ? [] : part.split(":").map((group) => Number.parseInt(group, 16)));
  const head = parse(halves[0] ?? "");
  const tail = halves.length === 2 ? parse(halves[1] ?? "") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0) return undefined;
  const groups = [...head, ...new Array<number>(fill).fill(0), ...tail];
  const valid = groups.length === 8 && groups.every((group) => Number.isInteger(group) && group >= 0 && group <= 0xffff);
  return valid ? groups : undefined;
}

/**
 * The key one client is counted under, or undefined when `clientIp` is not an IP address (the
 * callers then refuse). IPv4 counts per address; Node's isIP accepts only the canonical dotted
 * form, so one address has one key. IPv6 counts per /64, because one subscriber is usually handed
 * a whole /64 and could otherwise step through 2^64 addresses. The URL parser writes the IPv6 form
 * first, so every spelling of one address lands on one key, and an IPv4-mapped address counts as
 * its IPv4 address. Zone ids are refused.
 */
export function clientKey(clientIp: string): string | undefined {
  if (typeof clientIp !== "string") return undefined;
  const family = isIP(clientIp);
  if (family === 4) return clientIp;
  if (family !== 6) return undefined;
  let host: string;
  try {
    host = new URL(`http://[${clientIp}]/`).hostname;
  } catch {
    return undefined;
  }
  const groups = ipv6Groups(host.slice(1, -1));
  if (groups === undefined) return undefined;
  const [, , , , , mapped, high = 0, low = 0] = groups;
  if (groups.slice(0, 5).every((group) => group === 0) && mapped === 0xffff) {
    return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
  }
  return `${groups.slice(0, 4).map((group) => group.toString(16)).join(":")}::/64`;
}

function positive(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

function refused(windowSeconds: number): LimitResult {
  return { ok: false, retryAfter: positive(windowSeconds) ? windowSeconds : FALLBACK_RETRY_SECONDS };
}

/**
 * Counts one request against this IP's limit and the scope's total (threat model C23), in shared
 * state so every server instance sees the same counts (C31).
 *
 * The per-IP count goes first and a request refused there is not added to the total, so one noisy
 * IP cannot use up everyone's total by sending requests it is already refused for.
 *
 * Fails closed: a store error, a `clientIp` that is not an IP address, or a rule with a bad number
 * or scope all return not ok.
 */
export async function limit(store: SharedStore, rule: LimitRule): Promise<LimitResult> {
  const { scope, clientIp, perIp, total, windowSeconds } = rule;
  if (!SCOPE.test(scope) || !positive(perIp) || !positive(total) || !positive(windowSeconds)) {
    logEvent("rate_refused", { scope: String(scope).slice(0, 32), reason: "bad_rule" });
    return refused(windowSeconds);
  }
  const ip = clientKey(clientIp);
  if (ip === undefined) {
    logEvent("rate_refused", { scope, reason: "bad_client_ip" });
    return refused(windowSeconds);
  }
  try {
    if ((await store.incrWindow(`rate:${scope}:ip:${ip}`, windowSeconds)) > perIp) {
      logEvent("rate_limited", { scope, ip, reason: "per_ip" });
      return refused(windowSeconds);
    }
    if ((await store.incrWindow(`rate:${scope}:all`, windowSeconds)) > total) {
      logEvent("rate_limited", { scope, ip, reason: "total" });
      return refused(windowSeconds);
    }
    return { ok: true, retryAfter: 0 };
  } catch {
    logEvent("rate_refused", { scope, reason: "store_error" });
    return refused(windowSeconds);
  }
}

function budgetKey(rule: BudgetRule): string | undefined {
  if (!SCOPE.test(rule.scope) || !positive(rule.max) || !positive(rule.windowSeconds)) return undefined;
  const ip = clientKey(rule.clientIp);
  return ip === undefined ? undefined : `budget:${rule.scope}:ip:${ip}`;
}

/**
 * Whether this IP has any budget left in the current window, without spending any. Lets a caller
 * refuse before doing expensive work. Fails closed like `limit`.
 */
export async function hasBudget(store: SharedStore, rule: BudgetRule): Promise<LimitResult> {
  const key = budgetKey(rule);
  if (key === undefined) return refused(rule.windowSeconds);
  try {
    const raw = await store.get(key);
    const spent = raw === null ? 0 : Number(raw);
    if (Number.isSafeInteger(spent) && spent >= 0 && spent < rule.max) return { ok: true, retryAfter: 0 };
    logEvent("budget_limited", { scope: rule.scope, reason: "spent" });
  } catch {
    logEvent("budget_refused", { scope: rule.scope, reason: "store_error" });
  }
  return refused(rule.windowSeconds);
}

/**
 * Spends `amount` from this IP's budget for the window. Not ok when the total after spending is
 * over `max`. The amount is counted even then, so a refused attempt is not free. Fails closed like
 * `limit`.
 */
export async function spendBudget(store: SharedStore, rule: BudgetRule, amount: number): Promise<LimitResult> {
  const key = budgetKey(rule);
  if (key === undefined || !positive(amount)) return refused(rule.windowSeconds);
  try {
    if ((await store.incrWindow(key, rule.windowSeconds, amount)) <= rule.max) return { ok: true, retryAfter: 0 };
    logEvent("budget_limited", { scope: rule.scope, reason: "over" });
  } catch {
    logEvent("budget_refused", { scope: rule.scope, reason: "store_error" });
  }
  return refused(rule.windowSeconds);
}
