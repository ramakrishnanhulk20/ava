import { sameAccount } from "@ava/core";
import type { EvmWindow } from "@qorechain/evm";
import type { RelayerAddress } from "./chain/account.ts";
import { OutOfTime, elapsedMs, leftMs, narrowed, pause, startDeadline, within, type Deadline } from "./chain/deadline.ts";
import type { WindowChain, WindowRequest } from "./chain/types.ts";
import {
  DAILY_SPEND_CEILING_UQOR,
  LOCK_TTL_SECONDS,
  NATIVE_TX_BUDGET_MS,
  OPEN_CUTOFF_MS,
  REGISTRY_ADDRESS,
  RELAY_DEADLINE_MS,
  WAIT_AFTER_WINDOW_MS,
  WINDOW,
  WINDOW_CLOSE_FEE_UQOR,
  WINDOW_LOCK_WAIT_MS,
  WINDOW_OPEN_FEE_UQOR,
  WORST_TX_COST_UQOR,
} from "./config.ts";
import { logEvent } from "./log.ts";
import type { SharedStore } from "./store.ts";

export const WINDOW_LOCK = "relayer:window";
/** A day's ledger and halt keys outlive their day, so a late request near midnight never starts afresh. */
const SPEND_KEY_LIFETIME_SECONDS = 2 * 86_400;
/** Longer than any window can stay stored unnoticed, so an old window is never compared with a forgotten record. */
const SENT_KEY_LIFETIME_SECONDS = 30 * 86_400;
/**
 * Our sends through one window live in one counter: the value in uqor times SENT_COUNT_BASE plus the
 * number of sends, so one INCRBY records both at once. A window admits at most 40 transactions, far
 * under the base, and 40 worst-case values times the base stay well inside a safe integer.
 */
const SENT_COUNT_BASE = 10_000n;

/** Today's spending ceiling would be passed. Nothing was sent and no window was opened. */
export class DailyCeilingReached extends Error {
  constructor() {
    super("The relayer's daily spending ceiling is reached.");
    this.name = "DailyCeilingReached";
  }
}

export type WindowRefusal = "open_failed" | "readback_mismatch" | "unexpected_window" | "suspected_key_leak" | "halted_window";

/** No usable window: the open failed, or a window we did not ask for was found and closed. */
export class WindowUnavailable extends Error {
  readonly reason: WindowRefusal;

  constructor(reason: WindowRefusal) {
    super(`The relayer's EVM window is not usable: ${reason}.`);
    this.name = "WindowUnavailable";
    this.reason = reason;
  }
}

/** Someone else spent the relayer's window today. Every relay and every open is refused until the next UTC day. */
export class RelayerHalted extends Error {
  constructor() {
    super("The relayer is halted for the rest of this UTC day: its window was spent outside our own sends.");
    this.name = "RelayerHalted";
  }
}

export interface WindowDeps {
  store: SharedStore;
  /** Milliseconds since the epoch; picks the UTC day the spend is counted against. */
  now: number;
  relayer: RelayerAddress;
  chain: WindowChain;
  /** The relay's time budget. A standalone call gets a fresh RELAY_DEADLINE_MS. */
  deadline?: Deadline;
  /** The pause after an open. Tests pass one that moves their clock instead of waiting. */
  sleep?: (ms: number) => Promise<void>;
}

export interface WindowState {
  opened: boolean;
  window: EvmWindow;
  /** The open's transaction hash, when this call opened the window. */
  hash?: string;
}

/** The ledger key for the UTC day of `now`. */
export function spendKey(now: number): string {
  return `relayer:spend:${new Date(now).toISOString().slice(0, 10)}`;
}

/** The halt flag for the UTC day of `now`. */
export function haltKey(now: number): string {
  return `relayer:halt:${new Date(now).toISOString().slice(0, 10)}`;
}

/** Whether today (UTC) is halted. A store error is thrown, so callers fail closed. */
export async function isHalted(store: SharedStore, now: number): Promise<boolean> {
  return (await store.get(haltKey(now))) !== null;
}

function sentKey(openedHeight: bigint): string {
  return `relayer:window:${openedHeight}:sent`;
}

/**
 * Records one send through the window opened at `openedHeight`, with its worst case (gas limit
 * times fee cap, the figure the ledger reserves), in one atomic increment before the send.
 */
export async function recordWindowSend(store: SharedStore, openedHeight: bigint, worst: bigint): Promise<void> {
  checkAmount(worst);
  const amount = worst * SENT_COUNT_BASE + 1n;
  if (amount > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("A send's worst case is too large to record.");
  await store.incrWindow(sentKey(openedHeight), SENT_KEY_LIFETIME_SECONDS, Number(amount));
}

/** What we have recorded sending through the window opened at `openedHeight`: total worst-case value and count. */
export async function sentThrough(store: SharedStore, openedHeight: bigint): Promise<{ value: bigint; txs: bigint }> {
  const raw = await store.get(sentKey(openedHeight));
  if (raw === null) return { value: 0n, txs: 0n };
  if (!/^\d{1,16}$/.test(raw)) throw new Error("The window send record holds an unexpected value.");
  const total = BigInt(raw);
  return { value: total / SENT_COUNT_BASE, txs: total % SENT_COUNT_BASE };
}

const larger = (a: bigint, b: bigint): bigint => (a > b ? a : b);

/**
 * What the chain says the window has used: max minus remaining, or the chain's own used counter
 * when that is larger. Once no blocks remain, the remaining figures may describe the expiry rather
 * than the spending, so only the used counters count.
 */
export function usedByChain(window: EvmWindow): { value: bigint; txs: bigint } {
  if (window.remainingBlocks === 0n) return { value: window.usedValue, txs: window.usedTxs };
  return { value: larger(window.usedValue, window.maxValue - window.remainingValue), txs: larger(window.usedTxs, window.maxTxs - window.remainingTxs) };
}

/** Whether the window shows more value or more transactions used than every send we recorded through it. */
export async function spentOutsideUs(store: SharedStore, window: EvmWindow): Promise<boolean> {
  const chain = usedByChain(window);
  const ours = await sentThrough(store, window.openedHeight);
  return chain.value > ours.value || chain.txs > ours.txs;
}

/** uqor the relayer has committed to spend today (UTC). Throws on a ledger value it cannot read, so callers fail closed. */
export async function spentToday(store: SharedStore, now: number): Promise<bigint> {
  const raw = await store.get(spendKey(now));
  if (raw === null) return 0n;
  if (!/^\d{1,15}$/.test(raw)) throw new Error("The spend ledger holds an unexpected value.");
  return BigInt(raw);
}

function checkAmount(amount: bigint): void {
  if (amount <= 0n || amount > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("A spend is a positive whole number of uqor.");
}

/**
 * Records `amount` uqor against today's ceiling, before anything is spent (threat model C24, C31).
 * The amount is the worst case the spend can cost, never the expected cost.
 *
 * @param headroom uqor that must still fit under the ceiling after this spend, without being
 *   recorded. A window open asks for one worst-case transaction, so its fee is never paid for a
 *   window nothing could then use.
 * @returns The day's total after this spend.
 * @throws DailyCeilingReached when the total plus the headroom would pass DAILY_SPEND_CEILING_UQOR.
 *   If two writers raced past the read, the one that crosses the ceiling is refused and its amount
 *   stays counted.
 */
export async function reserveSpend(store: SharedStore, now: number, amount: bigint, what: string, headroom = 0n): Promise<bigint> {
  checkAmount(amount);
  const spent = await spentToday(store, now);
  if (spent + amount + headroom > DAILY_SPEND_CEILING_UQOR) {
    logEvent("relayer_spend_refused", { what, reason: "daily_ceiling", spentUqor: Number(spent), askedUqor: Number(amount) });
    throw new DailyCeilingReached();
  }
  const total = BigInt(await store.incrWindow(spendKey(now), SPEND_KEY_LIFETIME_SECONDS, Number(amount)));
  if (total > DAILY_SPEND_CEILING_UQOR) {
    logEvent("relayer_spend_refused", { what, reason: "daily_ceiling_race", totalUqor: Number(total) });
    throw new DailyCeilingReached();
  }
  logEvent("relayer_spend_recorded", { what, amountUqor: Number(amount), totalUqor: Number(total) });
  return total;
}

/** Counts a spend that must happen whatever the ceiling says. The day's total, or undefined when the ledger could not be written. */
async function recordSpend(store: SharedStore, now: number, amount: bigint): Promise<number | undefined> {
  checkAmount(amount);
  return store.incrWindow(spendKey(now), SPEND_KEY_LIFETIME_SECONDS, Number(amount)).catch(() => undefined);
}

/**
 * Whether the window admits only calls to the registry. One predicate on the parsed 20 bytes: an
 * empty list (unscoped), native-only, a second target or an address that does not decode all fail.
 */
export function isRegistryOnly(window: EvmWindow): boolean {
  if (window.nativeOnly || window.allowedTargets.length !== 1) return false;
  try {
    return sameAccount(window.allowedTargets[0] ?? "", REGISTRY_ADDRESS);
  } catch {
    return false;
  }
}

/**
 * Whether a stored window has a shape the relayer could have asked for (threat model C25): the
 * registry alone, 40 transactions, 12,000 blocks, and no more value than a full window. Anything
 * else is closed on sight.
 */
export function isOurShape(window: EvmWindow): boolean {
  return (
    isRegistryOnly(window) &&
    window.maxTxs === BigInt(WINDOW.maxTxs) &&
    window.expiryHeight - window.openedHeight === BigInt(WINDOW.blocks) &&
    window.maxValue > 0n &&
    window.maxValue <= WINDOW.maxValue
  );
}

/** What a window opened now could be given: a full window, or what is left of the day after the open fee. */
export function valueFor(spent: bigint): bigint {
  const left = DAILY_SPEND_CEILING_UQOR - spent - WINDOW_OPEN_FEE_UQOR;
  if (left <= 0n) return 0n;
  return left < WINDOW.maxValue ? left : WINDOW.maxValue;
}

/**
 * Why the window must be replaced before the next relayed transaction, or undefined when it may be
 * used. `wouldGet` is valueFor today's spend. A window the day's budget cut down would otherwise
 * renew on every relay for nothing, so low value renews only when a new window would hold more,
 * or when the next worst-case transaction no longer fits.
 */
export function renewalReason(window: EvmWindow, wouldGet: bigint): string | undefined {
  if (!window.found) return "none";
  if (!window.live) return "not_live";
  if (window.remainingTxs < WINDOW.renewBelowTxs) return "low_txs";
  if (window.remainingBlocks < WINDOW.renewBelowBlocks) return "low_blocks";
  if (window.remainingValue < WORST_TX_COST_UQOR) return "low_value";
  if (window.remainingValue < WINDOW.renewBelowValue && wouldGet > window.remainingValue) return "low_value";
  return undefined;
}

/** The one window the relayer ever opens (threat model C25): the registry alone, never unscoped, never native-only. */
export function windowRequest(maxValue: bigint): WindowRequest {
  return { blocks: WINDOW.blocks, maxTxs: WINDOW.maxTxs, maxValue, allowedTargets: [REGISTRY_ADDRESS] };
}

function matchesRequest(window: EvmWindow, request: WindowRequest): boolean {
  return (
    window.found &&
    window.live &&
    isRegistryOnly(window) &&
    window.maxTxs === BigInt(request.maxTxs) &&
    window.maxValue === request.maxValue &&
    window.expiryHeight - window.openedHeight === BigInt(request.blocks)
  );
}

/**
 * Closes the relayer's window with MsgCloseEVMWindow, logs one line, and refuses. The close fee is
 * counted but never refused: closing a window we did not ask for must not wait on the budget. A
 * close that fails is retried by the next read, which finds the same window.
 */
async function closeAndRefuse(deps: WindowDeps, deadline: Deadline, reason: WindowRefusal, extra: Record<string, string | boolean> = {}): Promise<never> {
  const ledger = await recordSpend(deps.store, deps.now, WINDOW_CLOSE_FEE_UQOR);
  const fields = { reason, relayer: deps.relayer.qor1, ledgerUqor: ledger ?? -1, ...extra };
  try {
    const { hash } = await deps.chain.closeWindow(deadline);
    logEvent("relayer_window_closed", { ...fields, hash });
  } catch {
    logEvent("relayer_window_close_failed", fields);
  }
  throw reason === "suspected_key_leak" || reason === "halted_window" ? new RelayerHalted() : new WindowUnavailable(reason);
}

/**
 * Someone else spent this window: our key may have leaked. Halts the day first, then closes. If the
 * flag cannot be written the close still happens and the line says so.
 */
async function haltAndClose(deps: WindowDeps, deadline: Deadline, window: EvmWindow): Promise<never> {
  const halted = await deps.store.setIfAbsent(haltKey(deps.now), "suspected_key_leak", SPEND_KEY_LIFETIME_SECONDS).then(
    () => true,
    () => false,
  );
  const used = usedByChain(window);
  const ours = await sentThrough(deps.store, window.openedHeight).catch(() => ({ value: -1n, txs: -1n }));
  return closeAndRefuse(deps, deadline, "suspected_key_leak", {
    window: window.openedHeight.toString(),
    chainUsedUqor: used.value.toString(),
    chainUsedTxs: used.txs.toString(),
    recordedUqor: ours.value.toString(),
    recordedTxs: ours.txs.toString(),
    halted,
  });
}

/**
 * Keeps the relayer's EVM window open, narrow, inside the day's budget and big enough for the next
 * transaction (threat model C24, C25, C31), under the shared lock "relayer:window" so two server
 * instances never both open one.
 *
 * Every read is checked first. On a halted day nothing opens, and a live window is closed. A window
 * of any shape the relayer could not have asked for (isOurShape) is closed at once and the call
 * refuses. A window that shows more value or transactions used than every send we recorded through
 * it (spentOutsideUs) means someone else holds the key: the day is halted and the window closed.
 * A usable window (renewalReason) is kept.
 * Otherwise, if no more than OPEN_CUTOFF_MS of the relay's time has gone, it records the open fee
 * against the day (refusing unless one worst-case transaction still fits after it), opens the one
 * window windowRequest describes with max_value the smaller of a full window and what is left of
 * the day, reads it back, closes and refuses if the chain stored anything else, and pauses
 * WAIT_AFTER_WINDOW_MS before any EVM transaction may follow.
 *
 * @throws RelayerHalted on a halted day or a suspected leak; DailyCeilingReached (renewal stops
 *   until the next UTC day); WindowUnavailable when the
 *   open fails or a window was closed; OutOfTime when it is too late to open or a read outran the
 *   deadline; LockBusy when another holder keeps the lock past WINDOW_LOCK_WAIT_MS.
 */
export async function ensureWindow(deps: WindowDeps): Promise<WindowState> {
  const deadline = deps.deadline ?? startDeadline(RELAY_DEADLINE_MS);
  const waitMs = Math.floor(Math.min(WINDOW_LOCK_WAIT_MS, leftMs(deadline)));
  return deps.store.withLock(
    WINDOW_LOCK,
    LOCK_TTL_SECONDS,
    async () => {
      const current = await within(deadline, deps.chain.readWindow(), "reading the window");
      if (await isHalted(deps.store, deps.now)) {
        if (current.found && current.live) return closeAndRefuse(deps, deadline, "halted_window");
        throw new RelayerHalted();
      }
      if (current.found && !isOurShape(current)) return closeAndRefuse(deps, deadline, "unexpected_window");
      if (current.found && (await spentOutsideUs(deps.store, current))) return haltAndClose(deps, deadline, current);
      const reason = renewalReason(current, valueFor(await spentToday(deps.store, deps.now)));
      if (reason === undefined) return { opened: false, window: current };

      if (elapsedMs(deadline) > OPEN_CUTOFF_MS) throw new OutOfTime("opening a window");
      const total = await reserveSpend(deps.store, deps.now, WINDOW_OPEN_FEE_UQOR, "window", WORST_TX_COST_UQOR);
      const room = DAILY_SPEND_CEILING_UQOR - total;
      const request = windowRequest(room < WINDOW.maxValue ? room : WINDOW.maxValue);
      let hash: string;
      try {
        ({ hash } = await deps.chain.openWindow(request, narrowed(deadline, NATIVE_TX_BUDGET_MS)));
      } catch {
        logEvent("relayer_window_refused", { reason: "open_failed", because: reason });
        throw new WindowUnavailable("open_failed");
      }
      const opened = await within(deadline, deps.chain.readWindow(), "reading the window back").catch(() => undefined);
      if (opened === undefined || !matchesRequest(opened, request)) return closeAndRefuse(deps, deadline, "readback_mismatch", { opened: hash });
      if (await spentOutsideUs(deps.store, opened)) return haltAndClose(deps, deadline, opened);
      logEvent("relayer_window_opened", {
        relayer: deps.relayer.qor1,
        hash,
        because: reason,
        maxTxs: request.maxTxs,
        blocks: request.blocks,
        maxValueUqor: request.maxValue.toString(),
        feeUqor: WINDOW_OPEN_FEE_UQOR.toString(),
      });
      await (deps.sleep ?? pause)(WAIT_AFTER_WINDOW_MS);
      return { opened: true, window: opened, hash };
    },
    { waitMs },
  );
}
