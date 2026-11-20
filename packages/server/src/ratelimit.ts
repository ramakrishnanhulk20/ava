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
  /**
   * The most this IP may spend in one window, in whatever unit the caller counts (bytes for
   * uploads). Every /64 of one IPv6 /48 also shares 4 times this.
   */
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

/** One caller's per-IP count: the limit rule without a scope-wide total. */
export interface ClientRule {
  /** Which endpoint is counting, as for LimitRule. */
  scope: string;
  /** The caller's IP as the hosting platform reports it, never a header the client sets. */
  clientIp: string;
  perIp: number;
  windowSeconds: number;
}

/** What countClient decided. `refusedBy` names the check that refused, for the caller's log line; absent when ok. */
export interface Verdict extends LimitResult {
  refusedBy?: "bad_rule" | "bad_client_ip" | "per_ip" | "per_net48" | "store_error";
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

/** A client's key and, for IPv6 that is not IPv4-mapped, the /48 it sits in. */
function clientKeys(clientIp: string): { ip: string; net48?: string } | undefined {
  if (typeof clientIp !== "string") return undefined;
  const family = isIP(clientIp);
  if (family === 4) return { ip: clientIp };
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
    return { ip: `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}` };
  }
  const hex = groups.map((group) => group.toString(16));
  return { ip: `${hex.slice(0, 4).join(":")}::/64`, net48: `${hex.slice(0, 3).join(":")}::/48` };
}

/**
 * The key one client is counted under, or undefined when `clientIp` is not an IP address (the
 * callers then refuse). IPv4 counts per address; Node's isIP accepts only the canonical dotted
 * form, so one address has one key. IPv6 counts per /64, because one subscriber is usually handed
 * a whole /64 and could otherwise step through 2^64 addresses. The URL parser writes the IPv6 form
 * first, so every spelling of one address lands on one key, and an IPv4-mapped address counts as
 * its IPv4 address. Zone ids are refused. `countClient`, `limit`, `hasBudget` and `spendBudget`
 * also count the /48 around an IPv6 key.
 */
export function clientKey(clientIp: string): string | undefined {
  return clientKeys(clientIp)?.ip;
}

/**
 * A /48 is the usual allocation to one site and holds 65,536 /64s, so every /64 of it shares one
 * count of this many times the per-IP limit: room for a few neighbours, not for one holder of all.
 */
const NET48_PER_IP_FACTOR = 4;

function positive(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

function refused(windowSeconds: number): LimitResult {
  return { ok: false, retryAfter: positive(windowSeconds) ? windowSeconds : FALLBACK_RETRY_SECONDS };
}

/**
 * Counts one request against this IP's limit alone (threat model C23), in shared state so every
 * server instance sees the same counts (C31): the per-client half of `limit`, under the same keys,
 * for a caller whose wider count is its own (the relay, which counts per chair, per board and in
 * total after its pre-flight).
 *
 * An IPv6 client is also counted per /48, at 4 times `perIp`, so one holder of a /48 cannot step
 * through its 65,536 /64s. IPv4 has no wider count. The /64 goes first and a request refused there
 * is not added to its /48, so one noisy /64 cannot use up its neighbours' room.
 *
 * Fails closed: a store error, a `clientIp` that is not an IP address, or a rule with a bad number
 * or scope all return not ok, with `refusedBy` saying which.
 */
export async function countClient(store: SharedStore, rule: ClientRule): Promise<Verdict> {
  const { scope, clientIp, perIp, windowSeconds } = rule;
  if (!SCOPE.test(scope) || !positive(perIp) || !positive(windowSeconds)) {
    logEvent("rate_refused", { scope: String(scope).slice(0, 32), reason: "bad_rule" });
    return { ...refused(windowSeconds), refusedBy: "bad_rule" };
  }
  const client = clientKeys(clientIp);
  if (client === undefined) {
    logEvent("rate_refused", { scope, reason: "bad_client_ip" });
    return { ...refused(windowSeconds), refusedBy: "bad_client_ip" };
  }
  const { ip, net48 } = client;
  try {
    if ((await store.incrWindow(`rate:${scope}:ip:${ip}`, windowSeconds)) > perIp) {
      logEvent("rate_limited", { scope, ip, reason: "per_ip" });
      return { ...refused(windowSeconds), refusedBy: "per_ip" };
    }
    if (net48 !== undefined && (await store.incrWindow(`rate:${scope}:net48:${net48}`, windowSeconds)) > NET48_PER_IP_FACTOR * perIp) {
      logEvent("rate_limited", { scope, ip: net48, reason: "per_net48" });
      return { ...refused(windowSeconds), refusedBy: "per_net48" };
    }
  } catch {
    logEvent("rate_refused", { scope, reason: "store_error" });
    return { ...refused(windowSeconds), refusedBy: "store_error" };
  }
  return { ok: true, retryAfter: 0 };
}

/**
 * Counts one request against this IP's limit and the scope's total (threat model C23), in shared
 * state so every server instance sees the same counts (C31).
 *
 * The per-IP and per-/48 counts are countClient's. The narrower counts go first and a request
 * refused there is added to no wider one, so one noisy IP cannot use up its /48's or everyone's
 * total by sending requests it is already refused for.
 *
 * Fails closed: a store error, a `clientIp` that is not an IP address, or a rule with a bad number
 * or scope all return not ok.
 */
export async function limit(store: SharedStore, rule: LimitRule): Promise<LimitResult> {
  const { scope, total, windowSeconds } = rule;
  if (!positive(total)) {
    logEvent("rate_refused", { scope: String(scope).slice(0, 32), reason: "bad_rule" });
    return refused(windowSeconds);
  }
  const client = await countClient(store, rule);
  if (!client.ok) return refused(windowSeconds);
  try {
    if ((await store.incrWindow(`rate:${scope}:all`, windowSeconds)) > total) {
      logEvent("rate_limited", { scope, ip: clientKey(rule.clientIp) ?? "none", reason: "total" });
      return refused(windowSeconds);
    }
    return { ok: true, retryAfter: 0 };
  } catch {
    logEvent("rate_refused", { scope, reason: "store_error" });
    return refused(windowSeconds);
  }
}

/**
 * The budget counters one client spends from, narrowest first: its own key, then for IPv6 that is
 * not IPv4-mapped its /48 at NET48_PER_IP_FACTOR times `max`, the rule countClient uses (C23).
 */
function budgetKeys(rule: BudgetRule): { key: string; max: number; reason: "per_ip" | "per_net48" }[] | undefined {
  if (!SCOPE.test(rule.scope) || !positive(rule.max) || !positive(rule.windowSeconds)) return undefined;
  const client = clientKeys(rule.clientIp);
  if (client === undefined) return undefined;
  const own = { key: `budget:${rule.scope}:ip:${client.ip}`, max: rule.max, reason: "per_ip" as const };
  if (client.net48 === undefined) return [own];
  return [own, { key: `budget:${rule.scope}:net48:${client.net48}`, max: NET48_PER_IP_FACTOR * rule.max, reason: "per_net48" as const }];
}

/**
 * Whether this client has any budget left in the current window, without spending any (threat model
 * C23): its own count under `max`, and for IPv6 its /48's under 4 times `max`. Lets a caller refuse
 * before doing expensive work. Fails closed like `limit`.
 */
export async function hasBudget(store: SharedStore, rule: BudgetRule): Promise<LimitResult> {
  const keys = budgetKeys(rule);
  if (keys === undefined) return refused(rule.windowSeconds);
  try {
    for (const { key, max, reason } of keys) {
      const raw = await store.get(key);
      const spent = raw === null ? 0 : Number(raw);
      if (!Number.isSafeInteger(spent) || spent < 0 || spent >= max) {
        logEvent("budget_limited", { scope: rule.scope, reason: "spent", by: reason });
        return refused(rule.windowSeconds);
      }
    }
    return { ok: true, retryAfter: 0 };
  } catch {
    logEvent("budget_refused", { scope: rule.scope, reason: "store_error" });
  }
  return refused(rule.windowSeconds);
}

/**
 * Spends `amount` from this client's budget for the window (threat model C23). Not ok when its own
 * total after spending is over `max`, or for IPv6 when its /48's is over 4 times `max`, so one holder
 * of a /48 cannot step through its 65,536 /64s. The amount is counted even when refused, so a
 * refused attempt is not free; one refused at its own count is not added to its /48, so one noisy
 * /64 cannot use up its neighbours' room. Fails closed like `limit`.
 */
export async function spendBudget(store: SharedStore, rule: BudgetRule, amount: number): Promise<LimitResult> {
  const keys = budgetKeys(rule);
  if (keys === undefined || !positive(amount)) return refused(rule.windowSeconds);
  try {
    for (const { key, max, reason } of keys) {
      if ((await store.incrWindow(key, rule.windowSeconds, amount)) > max) {
        logEvent("budget_limited", { scope: rule.scope, reason: "over", by: reason });
        return refused(rule.windowSeconds);
      }
    }
    return { ok: true, retryAfter: 0 };
  } catch {
    logEvent("budget_refused", { scope: rule.scope, reason: "store_error" });
  }
  return refused(rule.windowSeconds);
}
