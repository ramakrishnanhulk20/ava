import { accountBytes, sameAccount } from "@ava/core";
import type { EvmWindow } from "@qorechain/evm";
import { bytesToHex } from "viem";
import type { RelayerAddress } from "./chain/account.ts";
import { OutOfTime, elapsedMs, leftMs, narrowed, pause, startDeadline, within, type Deadline } from "./chain/deadline.ts";
import { NotBroadcast } from "./chain/evm.ts";
import { RefusedBeforeInclusion } from "./chain/native.ts";
import type { BeforeBroadcast, SignedTx, TxStatus, WindowChain, WindowRequest } from "./chain/types.ts";
import {
  CHAIRS_DAILY_CEILING_UQOR,
  DEMO_DAILY_CEILING_UQOR,
  LOCK_TTL_SECONDS,
  NATIVE_TX_BUDGET_MS,
  NONCE_CONFIRM_POLL_MS,
  NONCE_CONFIRM_WAIT_MS,
  NONCE_GAP_CAP,
  OPEN_CUTOFF_MS,
  PER_CHAIR_DAILY_POST_BYTES,
  PER_CHAIR_DAILY_UQOR,
  REGISTRY_ADDRESS,
  RELAYER_DAILY_CEILING_UQOR,
  TOTAL_DAILY_POST_BYTES,
  RELAY_DEADLINE_MS,
  WAIT_AFTER_WINDOW_MS,
  WINDOW,
  WINDOW_CLOSE_FEE_UQOR,
  WINDOW_LOCK_WAIT_MS,
  WINDOW_OPEN_FEE_UQOR,
  WORST_TX_COST_UQOR,
} from "./config.ts";
import { logEvent } from "./log.ts";
import { addOnce, type SharedStore } from "./store.ts";

export const WINDOW_LOCK = "relayer:window";
/** A day's ledger keys outlive their day, so a late request near midnight never starts afresh. */
const SPEND_KEY_LIFETIME_SECONDS = 2 * 86_400;
/** Longer than any window can stay stored unnoticed, so an old window is never compared with a forgotten record. */
const SENT_KEY_LIFETIME_SECONDS = 30 * 86_400;
/** Ten years. The store gives every key a lifetime; the expected nonce and a leak halt must never lapse on their own. */
const DURABLE_SECONDS = 315_360_000;
/**
 * Our sends through one window live in one counter: the value in uqor times SENT_COUNT_BASE plus the
 * number of sends, so one INCRBY records both at once. A window admits at most 40 transactions, far
 * under the base, and 40 worst-case values times the base stay well inside a safe integer.
 */
const SENT_COUNT_BASE = 10_000n;

/**
 * Which of the day's ledgers a spend is booked on: `total` holds every spend, `chairs` every public
 * relay, `demo` the demo bot's relays, `chair` one chair address's public relays. `posts` and
 * `chair_posts` hold the bytes of documents posted, all chairs and one chair (threat model C44).
 */
export type LedgerName = "total" | "chairs" | "demo" | "chair" | "posts" | "chair_posts";

/** One of the day's ledgers: the counter it books on and the most it may hold, in uqor unless `unit` says bytes. */
export interface Ledger {
  readonly name: LedgerName;
  readonly key: string;
  readonly ceiling: bigint;
  readonly unit?: "bytes";
}

/** A spend booked on its ledgers before it happened, so it can be settled down or given back. */
export interface Reservation {
  readonly amount: bigint;
  readonly ledgers: readonly Ledger[];
  readonly what: string;
}

/** One of today's ledgers would pass its ceiling. Nothing was sent, no window was opened, and nothing stays booked. */
export class DailyCeilingReached extends Error {
  /** The ledger that refused; "total" for the relayer's whole day. */
  readonly ledger: LedgerName;

  constructor(ledger: LedgerName = "total") {
    super(ledger === "total" ? "The relayer's daily spending ceiling is reached." : `The relayer's daily ${ledger} ledger is full.`);
    this.name = "DailyCeilingReached";
    this.ledger = ledger;
  }
}

export type WindowRefusal = "open_failed" | "readback_mismatch" | "unexpected_window" | "suspected_key_leak" | "halted_window" | "nonce_unavailable" | "nonce_pending";

/**
 * No usable window: the open failed, a window we did not ask for was found and closed, the chain gave
 * no nonce to check, or one of our own transactions is still waiting for a block.
 */
export class WindowUnavailable extends Error {
  readonly reason: WindowRefusal;

  constructor(reason: WindowRefusal) {
    super(`The relayer's EVM window is not usable: ${reason}.`);
    this.name = "WindowUnavailable";
    this.reason = reason;
  }
}

/**
 * Someone else used the relayer's key: its window shows spending we did not record, or its nonce
 * moved past ours. Every relay and every open is refused until an operator clears the halt.
 */
export class RelayerHalted extends Error {
  constructor() {
    super("The relayer is halted: its key was used outside our own sends. It stays halted until an operator runs scripts/clear-relayer-halt.ts.");
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

const utcDay = (now: number): string => new Date(now).toISOString().slice(0, 10);

/** The total ledger's key for the UTC day of `now`. */
export function spendKey(now: number): string {
  return `relayer:spend:${utcDay(now)}`;
}

/**
 * The ledger `name` for the UTC day of `now`. A chair ledger (`chair`, `chair_posts`) needs `chair`,
 * any address form the shared codec reads, so one account always books under one key.
 */
export function ledgerFor(name: LedgerName, now: number, chair?: string): Ledger {
  const total = spendKey(now);
  const posts = `relayer:posts:${utcDay(now)}`;
  const account = (): string => {
    if (chair === undefined) throw new TypeError("A chair ledger needs the chair's address.");
    return bytesToHex(accountBytes(chair));
  };
  switch (name) {
    case "total":
      return { name, key: total, ceiling: RELAYER_DAILY_CEILING_UQOR };
    case "chairs":
      return { name, key: `${total}:chairs`, ceiling: CHAIRS_DAILY_CEILING_UQOR };
    case "demo":
      return { name, key: `${total}:demo`, ceiling: DEMO_DAILY_CEILING_UQOR };
    case "chair":
      return { name, key: `${total}:chair:${account()}`, ceiling: PER_CHAIR_DAILY_UQOR };
    case "posts":
      return { name, key: posts, ceiling: TOTAL_DAILY_POST_BYTES, unit: "bytes" };
    case "chair_posts":
      return { name, key: `${posts}:chair:${account()}`, ceiling: PER_CHAIR_DAILY_POST_BYTES, unit: "bytes" };
  }
}

/** The suffix a ledger's amounts carry in log lines, so bytes are never read as uqor. */
const unitOf = (ledgers: readonly Ledger[]): "Uqor" | "Bytes" => (ledgers[0]?.unit === "bytes" ? "Bytes" : "Uqor");

/**
 * The store has no decrement, so a ledger is two counters that only grow: what was booked under
 * the ledger's key, and what was settled away or given back under this one. A booking may count
 * twice when a lost reply is retried, which only overstates the spend; so the booked counter moves
 * by increment, and this one, where a doubled write would understate it, only by addOnce.
 */
const settledKey = (key: string): string => `${key}:settled`;

/** Every give-back takes this lock, so no other give-back writes a settled counter between its read and its write (addOnce). */
const SETTLE_LOCK = "relayer:settle";
/** A give-back is at most nine store calls; the lock ends on its own long after them if its holder dies. */
const SETTLE_LOCK_SECONDS = 10;
/** A give-back that waits longer than this for another leaves its amount booked, the side that overstates. */
const SETTLE_LOCK_WAIT_MS = 5_000;
/** Reservations already settled or given back. A Reservation belongs to the one request that booked it, so this is per process. */
const givenBack = new WeakSet<Reservation>();

/** The leak halt (threat model C25). No day in its name: it holds until an operator clears it. */
export const HALT_KEY = "relayer:halt";

/** The leak halt's key. A halt no longer belongs to a day, so `now` is ignored; it stays for older callers. */
export function haltKey(_now?: number): string {
  return HALT_KEY;
}

/** The day flag earlier releases wrote; still honoured on its own day, so a halt written before an upgrade is not lost by it. */
const dayHaltKey = (now: number): string => `relayer:halt:${utcDay(now)}`;

/** Whether the relayer is halted. A store error is thrown, so callers fail closed. */
export async function isHalted(store: SharedStore, now: number): Promise<boolean> {
  return (await store.get(HALT_KEY)) !== null || (await store.get(dayHaltKey(now))) !== null;
}

/** What clearHalt found under each key before removing it, null where a key held nothing. */
export interface ClearedHalt {
  halt: string | null;
  dayHalt: string | null;
  nonce: string | null;
}

/**
 * Lifts a leak halt, for an operator who has dealt with the relayer's key (scripts/clear-relayer-halt.ts):
 * removes the relayer's stored nonce first, so the next run adopts the chain's, then the halt flag
 * and the day flag earlier releases wrote for `now`'s day.
 *
 * @returns What each key held before it was removed.
 * @throws A store error as it came; whatever was already removed stays removed.
 */
export async function clearHalt(store: SharedStore, relayerEvm: string, now: number): Promise<ClearedHalt> {
  const nonce = nonceKey(relayerEvm);
  const cleared: ClearedHalt = { halt: await store.get(HALT_KEY), dayHalt: await store.get(dayHaltKey(now)), nonce: await store.get(nonce) };
  await store.delete(nonce);
  await store.delete(HALT_KEY);
  await store.delete(dayHaltKey(now));
  logEvent("relayer_halt_cleared", { halt: cleared.halt !== null, dayHalt: cleared.dayHalt !== null, nonce: cleared.nonce ?? "none" });
  return cleared;
}

function sentKey(openedHeight: bigint): string {
  return `relayer:window:${openedHeight}:sent`;
}

function sentTotal(raw: string | null): bigint {
  if (raw === null) return 0n;
  if (!/^\d{1,16}$/.test(raw)) throw new Error("The window send record holds an unexpected value.");
  return BigInt(raw);
}

/**
 * Records one send through the window opened at `openedHeight`, with its worst case (gas limit
 * times fee cap, the figure the ledger reserves), before the send (threat model C24). The record
 * gates the leak halt, so it moves only by compare-and-set from the value read: a store request
 * retried after a lost reply lands once, never twice, and so never hides a transaction of someone
 * else's. Run it under SEND_LOCK, as handleRelay does.
 *
 * @throws RangeError for a worst case that is not a positive safe integer or would overflow the
 *   record; an Error when the record could not be written (nothing should then be sent).
 */
export async function recordWindowSend(store: SharedStore, openedHeight: bigint, worst: bigint): Promise<void> {
  checkAmount(worst);
  const amount = worst * SENT_COUNT_BASE + 1n;
  if (amount > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("A send's worst case is too large to record.");
  const key = sentKey(openedHeight);
  for (let attempt = 0; attempt < 2; attempt++) {
    const held = await store.get(key);
    const next = sentTotal(held) + amount;
    if (next > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("The window send record would overflow.");
    if (await store.compareAndSet(key, held, next.toString(), SENT_KEY_LIFETIME_SECONDS)) return;
    // A retried write that did land reads back as this one.
    if ((await store.get(key)) === next.toString()) return;
  }
  throw new Error("The window send record moved while it was written.");
}

/** What we have recorded sending through the window opened at `openedHeight`: total worst-case value and count. */
export async function sentThrough(store: SharedStore, openedHeight: bigint): Promise<{ value: bigint; txs: bigint }> {
  const total = sentTotal(await store.get(sentKey(openedHeight)));
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

async function counter(store: SharedStore, key: string): Promise<bigint> {
  const raw = await store.get(key);
  if (raw === null) return 0n;
  if (!/^\d{1,15}$/.test(raw)) throw new Error("The spend ledger holds an unexpected value.");
  return BigInt(raw);
}

/** Booked and settled, read settled first: a settlement landing between the reads can only make the balance look larger. */
async function balance(store: SharedStore, ledger: Ledger): Promise<{ settled: bigint; spent: bigint }> {
  const settled = await counter(store, settledKey(ledger.key));
  const booked = await counter(store, ledger.key);
  if (settled > booked) throw new Error("The spend ledger shows more settled than booked.");
  return { settled, spent: booked - settled };
}

/** uqor booked on `ledger` and not settled away. Throws on a value it cannot read, so callers fail closed. */
export async function spentOn(store: SharedStore, ledger: Ledger): Promise<bigint> {
  return (await balance(store, ledger)).spent;
}

/** uqor the relayer has committed to spend today (UTC), on the total ledger. Throws on a value it cannot read, so callers fail closed. */
export async function spentToday(store: SharedStore, now: number): Promise<bigint> {
  return spentOn(store, ledgerFor("total", now));
}

function checkAmount(amount: bigint): void {
  if (amount <= 0n || amount > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("A spend is a positive whole number of uqor.");
}

/**
 * Counts `amount` as settled on each ledger (threat model C31), under SETTLE_LOCK and by addOnce, so
 * a write retried after a lost reply lands once and never makes a ledger show less than it holds.
 * A write that fails or cannot be confirmed, or a lock not had in time, leaves that much booked,
 * which only ever overstates the spend, and is never tried again. Never throws.
 */
async function giveBack(store: SharedStore, ledgers: readonly Ledger[], amount: bigint, what: string): Promise<void> {
  const unsettled = (ledger: Ledger) => logEvent("relayer_spend_unsettled", { what, ledger: ledger.name, [`amount${unitOf([ledger])}`]: Number(amount) });
  let reached = 0;
  try {
    await store.withLock(
      SETTLE_LOCK,
      SETTLE_LOCK_SECONDS,
      async () => {
        for (const ledger of ledgers) {
          reached += 1;
          if (!(await addOnce(store, settledKey(ledger.key), amount, SPEND_KEY_LIFETIME_SECONDS).catch(() => false))) unsettled(ledger);
        }
      },
      { waitMs: SETTLE_LOCK_WAIT_MS },
    );
  } catch {
    for (const ledger of ledgers.slice(reached)) unsettled(ledger);
  }
}

async function book(store: SharedStore, ledgers: readonly Ledger[], amount: bigint, what: string, headroom: bigint): Promise<{ reservation: Reservation; after: bigint }> {
  checkAmount(amount);
  const unit = unitOf(ledgers);
  const taken: Ledger[] = [];
  let after = 0n;
  try {
    for (const ledger of ledgers) {
      const { settled, spent } = await balance(store, ledger);
      if (spent + amount + headroom > ledger.ceiling) {
        logEvent("relayer_spend_refused", { what, ledger: ledger.name, reason: "daily_ceiling", [`spent${unit}`]: Number(spent), [`asked${unit}`]: Number(amount) });
        throw new DailyCeilingReached(ledger.name);
      }
      const booked = BigInt(await store.incrWindow(ledger.key, SPEND_KEY_LIFETIME_SECONDS, Number(amount)));
      taken.push(ledger);
      after = booked - settled;
      if (after > ledger.ceiling) {
        logEvent("relayer_spend_refused", { what, ledger: ledger.name, reason: "daily_ceiling_race", [`total${unit}`]: Number(after) });
        throw new DailyCeilingReached(ledger.name);
      }
    }
  } catch (error) {
    await giveBack(store, taken, amount, what);
    throw error;
  }
  logEvent("relayer_spend_recorded", { what, ledgers: ledgers.map((l) => l.name).join(","), [`amount${unit}`]: Number(amount), [`total${unit}`]: Number(after) });
  return { reservation: { amount, ledgers, what }, after };
}

/**
 * Books `amount` on every ledger in `ledgers`, in order, before anything is spent (threat model
 * C24, C31, C41, C44): uqor, or bytes for the post ledgers, one unit per call. The amount is the
 * worst case the spend can cost, never the expected cost.
 *
 * @param headroom What must still fit under each ceiling after this spend, without being booked.
 * @returns The reservation, to settle with settleSpend once the real cost is known or to give back
 *   with releaseSpend when nothing was spent.
 * @throws DailyCeilingReached naming the first ledger that would pass its ceiling, after giving
 *   back what the earlier ledgers took, so a refused spend leaves nothing booked. Two writers that
 *   race past the read are each checked again after their own increment, and one that crosses is
 *   refused the same way.
 */
export async function reserveOn(store: SharedStore, ledgers: readonly Ledger[], amount: bigint, what: string, headroom = 0n): Promise<Reservation> {
  return (await book(store, ledgers, amount, what, headroom)).reservation;
}

/**
 * Books `amount` uqor on today's total ledger alone, before anything is spent (threat model C24, C31).
 *
 * @param headroom uqor that must still fit under the ceiling after this spend, without being
 *   booked. A window open asks for one worst-case transaction, so its fee is never paid for a
 *   window nothing could then use.
 * @returns The day's total after this spend.
 * @throws DailyCeilingReached when the total plus the headroom would pass RELAYER_DAILY_CEILING_UQOR;
 *   nothing stays booked.
 */
export async function reserveSpend(store: SharedStore, now: number, amount: bigint, what: string, headroom = 0n): Promise<bigint> {
  return (await book(store, [ledgerFor("total", now)], amount, what, headroom)).after;
}

/**
 * Settles a reservation down to `cost`, what the spend really cost, on every ledger it was booked
 * on, once (threat model C31): a reservation already settled or given back gives nothing back
 * again. A cost at or above the booked amount changes nothing: a booking is never raised afterwards.
 */
export async function settleSpend(store: SharedStore, reservation: Reservation, cost: bigint): Promise<void> {
  if (cost < 0n) throw new RangeError("A cost is never negative.");
  if (givenBack.has(reservation)) return;
  givenBack.add(reservation);
  const back = reservation.amount - cost;
  if (back <= 0n) return;
  await giveBack(store, reservation.ledgers, back, reservation.what);
  const unit = unitOf(reservation.ledgers);
  logEvent("relayer_spend_settled", { what: reservation.what, [`booked${unit}`]: Number(reservation.amount), [`cost${unit}`]: Number(cost) });
}

/** Gives a whole reservation back, for a spend that never happened, once, like settleSpend. */
export async function releaseSpend(store: SharedStore, reservation: Reservation): Promise<void> {
  await settleSpend(store, reservation, 0n);
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
  const left = RELAYER_DAILY_CEILING_UQOR - spent - WINDOW_OPEN_FEE_UQOR;
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

/** Where the relayer's next expected nonce lives, one per relayer account, so a new key never inherits an old count. */
export function nonceKey(relayerEvm: string): string {
  return `relayer:next-nonce:${bytesToHex(accountBytes(relayerEvm))}`;
}

async function storedNonce(store: SharedStore, key: string): Promise<bigint | undefined> {
  const raw = await store.get(key);
  if (raw === null) return undefined;
  if (!/^\d{1,15}$/.test(raw)) throw new Error("The stored nonce holds an unexpected value.");
  return BigInt(raw);
}

/**
 * The relayer's next nonce on chain, and the one we expect. A first run with nothing stored adopts
 * the chain's. A chain that cannot report a nonce, or cannot look up our own transactions, gives no
 * way to tell our use of the key from anyone else's, so nothing is checked against it.
 */
async function nonces(deps: WindowDeps, deadline: Deadline): Promise<{ chain: bigint; expected: bigint }> {
  if (deps.chain.nonce === undefined || deps.chain.txStatus === undefined) throw new WindowUnavailable("nonce_unavailable");
  const chain = await within(deadline, deps.chain.nonce(), "reading the relayer's nonce");
  if (typeof chain !== "bigint" || chain < 0n || chain > BigInt(Number.MAX_SAFE_INTEGER)) throw new WindowUnavailable("nonce_unavailable");
  const key = nonceKey(deps.relayer.evm);
  const expected = await storedNonce(deps.store, key);
  if (expected !== undefined) return { chain, expected };
  await deps.store.setIfAbsent(key, chain.toString(), DURABLE_SECONDS);
  const adopted = (await storedNonce(deps.store, key)) ?? chain;
  logEvent("relayer_nonce_adopted", { relayer: deps.relayer.qor1, nonce: adopted.toString() });
  return { chain, expected: adopted };
}

/**
 * Where a transaction the relayer signed is recorded, under the nonce it carries, before its
 * broadcast (threat model C24). A record is needed only until the next check finds its hash in a
 * block; one gone before that reads as missing, which halts, the safe direction.
 */
function signedKey(relayerEvm: string, nonce: bigint): string {
  return `relayer:sent:${bytesToHex(accountBytes(relayerEvm))}:${nonce}`;
}

const SIGNED_HASH = { evm: /^0x[0-9a-f]{64}$/, native: /^[0-9A-F]{64}$/ } as const;

type SignedRecord = Pick<SignedTx, "kind" | "hash">;

const encodeSigned = (signed: SignedRecord): string => JSON.stringify({ kind: signed.kind, hash: signed.hash });

/** A stored record read back as an input would be: anything but one of the two exact shapes we write is undefined. */
function decodeSigned(raw: string | null): SignedRecord | undefined {
  if (raw === null || raw.length > 128) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null) return undefined;
  const { kind, hash } = parsed as { kind?: unknown; hash?: unknown };
  if ((kind !== "evm" && kind !== "native") || typeof hash !== "string" || !SIGNED_HASH[kind].test(hash)) return undefined;
  return { kind, hash };
}

/** Lookups one check may make of a single transaction of ours: one at once, then one a poll while the wait lasts. */
const CONFIRM_LOOKUPS = Math.floor(NONCE_CONFIRM_WAIT_MS / NONCE_CONFIRM_POLL_MS) + 1;

/**
 * Looks one of our recorded transactions up until it is in a block, landed or reverted (either one
 * used its nonce), at most CONFIRM_LOOKUPS times and only while `wait` lasts. A lookup that fails
 * is thrown, so a failed read never reads as someone else's transaction.
 */
async function standing(deps: WindowDeps, wait: Deadline, ours: SignedRecord): Promise<TxStatus> {
  const lookup = deps.chain.txStatus;
  if (lookup === undefined) throw new WindowUnavailable("nonce_unavailable");
  let status: TxStatus = "unknown";
  for (let tries = 0; tries < CONFIRM_LOOKUPS; tries++) {
    status = await within(wait, lookup(ours.kind, ours.hash), "looking up the relayer's own transaction");
    if (status === "landed" || status === "reverted" || leftMs(wait) <= NONCE_CONFIRM_POLL_MS) return status;
    await (deps.sleep ?? pause)(NONCE_CONFIRM_POLL_MS);
  }
  return status;
}

/**
 * Whether every nonce from `from` up to `to` carries a transaction we recorded before its broadcast
 * and the chain holds in a block, landed or reverted. A nonce with no record, an unreadable record,
 * or a recorded hash the chain still does not know once the wait is over was used by someone else.
 */
async function oursSince(deps: WindowDeps, deadline: Deadline, from: bigint, to: bigint): Promise<"ours" | "pending" | { foreign: bigint }> {
  const wait = narrowed(deadline, NONCE_CONFIRM_WAIT_MS);
  for (let nonce = from; nonce < to; nonce++) {
    const ours = decodeSigned(await deps.store.get(signedKey(deps.relayer.evm, nonce)));
    if (ours === undefined) return { foreign: nonce };
    const status = await standing(deps, wait, ours);
    if (status === "unknown") return { foreign: nonce };
    if (status === "pending") return "pending";
  }
  return "ours";
}

/** Moves the stored nonce from `from` to `to` by compare-and-set from the value read, so a retried write lands once. */
async function moveNonce(deps: WindowDeps, from: bigint, to: bigint): Promise<void> {
  const key = nonceKey(deps.relayer.evm);
  if (await deps.store.compareAndSet(key, from.toString(), to.toString(), DURABLE_SECONDS)) return;
  if ((await deps.store.get(key)) === to.toString()) return;
  logEvent("relayer_nonce_moved", { relayer: deps.relayer.qor1, from: from.toString(), to: to.toString() });
  throw new WindowUnavailable("nonce_unavailable");
}

/**
 * Before any transaction we sign (threat model C24). The stored nonce S only ever moves to a chain
 * nonce C once every nonce from S up to C is a transaction we recorded before its broadcast and the
 * chain holds in a block, so S never runs ahead of what we know landed and every nonce the key used
 * is accounted for. A nonce in that span with no record of ours, or with a recorded hash the chain
 * does not know, means someone else signed with the relayer's key, even where no window counter
 * could see it: the relayer halts and closes its window. So does a span wider than NONCE_GAP_CAP,
 * which our own sends never leave. One of ours still waiting for a block refuses for now.
 *
 * @returns The chain's next nonce, the one our transaction is expected to take.
 */
async function checkNonce(deps: WindowDeps, deadline: Deadline, window: EvmWindow): Promise<bigint> {
  const { chain, expected } = await nonces(deps, deadline);
  if (chain === expected) return chain;
  const fields = { chainNonce: chain.toString(), expectedNonce: expected.toString() };
  if (chain < expected) {
    // Behind a nonce we saw land: a lagging node. Nothing is signed against a count we know is stale.
    logEvent("relayer_nonce_behind", { relayer: deps.relayer.qor1, ...fields });
    throw new WindowUnavailable("nonce_unavailable");
  }
  if (chain - expected > NONCE_GAP_CAP) return haltAndClose(deps, deadline, window, { ...fields, foreignNonce: "beyond_gap_cap" });
  const found = await oursSince(deps, deadline, expected, chain);
  if (found === "pending") {
    logEvent("relayer_nonce_pending", { relayer: deps.relayer.qor1, ...fields });
    throw new WindowUnavailable("nonce_pending");
  }
  if (found !== "ours") return haltAndClose(deps, deadline, window, { ...fields, foreignNonce: found.foreign.toString() });
  await moveNonce(deps, expected, chain);
  return chain;
}

/** Records a signed transaction before its broadcast, and takes the record back for one certainly never sent. */
interface Recorder {
  /** Pass to the chain's send, open or close. */
  readonly beforeBroadcast: BeforeBroadcast;
  /** Puts back what the record held before, for a transaction certainly never broadcast. Never throws. */
  undo(): Promise<void>;
}

/**
 * The record a transaction we sign leaves under its nonce before the broadcast, written by
 * compare-and-set from the value read. A nonce whose record names another transaction of ours keeps
 * it while the chain holds that one or cannot say: a re-signed transaction replaces only one the
 * chain has never seen, so the record never drops a transaction that may still land. "strict" (a
 * send or an open) refuses to broadcast when the record cannot be written; "best_effort" (a close,
 * the safe direction) logs and goes ahead, and the next check then halts on the missing record.
 * The lookup of an earlier transaction ends by `deadline`; one that runs out throws OutOfTime, so
 * nothing is broadcast.
 */
function recorder(deps: WindowDeps, mode: "strict" | "best_effort", deadline: Deadline): Recorder {
  let written: { key: string; value: string; before: string | null } | undefined;
  const record = async (signed: SignedTx): Promise<void> => {
    if (!SIGNED_HASH[signed.kind]?.test(signed.hash) || signed.nonce < 0n) throw new Error("The signed transaction is not one the record can hold.");
    const key = signedKey(deps.relayer.evm, signed.nonce);
    const value = encodeSigned(signed);
    const before = await deps.store.get(key);
    if (before === value) return;
    if (before !== null) {
      const earlier = decodeSigned(before);
      const lookup = deps.chain.txStatus;
      if (earlier === undefined || lookup === undefined || (await within(deadline, lookup(earlier.kind, earlier.hash), "looking up an earlier send at this nonce")) !== "unknown") {
        throw new Error("The nonce is spent, or may yet be, by an earlier transaction of ours.");
      }
    }
    if (!(await deps.store.compareAndSet(key, before, value, SENT_KEY_LIFETIME_SECONDS)) && (await deps.store.get(key)) !== value) {
      throw new Error("The send record moved while it was written.");
    }
    written = { key, value, before };
  };
  const unrecorded = (signed: SignedTx) => logEvent("relayer_send_unrecorded", { relayer: deps.relayer.qor1, nonce: signed.nonce.toString(), kind: signed.kind });
  return {
    beforeBroadcast: mode === "strict" ? record : (signed) => record(signed).catch(() => unrecorded(signed)),
    undo: async () => {
      if (written === undefined) return;
      const { key, value, before } = written;
      written = undefined;
      const back = before === null ? deps.store.delete(key) : deps.store.compareAndSet(key, value, before, SENT_KEY_LIFETIME_SECONDS);
      await back.catch(() => logEvent("relayer_send_record_kept", { relayer: deps.relayer.qor1 }));
    },
  };
}

/**
 * Whether a failed send, open or close certainly sent nothing: it ran out of time first, its record
 * could not be written, or the node refused it before any block. No nonce and no fee were used.
 */
const nothingSent = (error: unknown): boolean => error instanceof OutOfTime || error instanceof RefusedBeforeInclusion || error instanceof NotBroadcast;

/** What an EVM send carries from guardSend to the chain. */
export interface SendGuard extends Recorder {
  /** The chain's next nonce, checked: the one the send is expected to take. */
  readonly nonce: bigint;
}

/**
 * Checks the relayer's nonce right before an EVM send (threat model C24) and gives the send its
 * record. Run it under SEND_LOCK, as handleRelay does, because a send and a window open or close
 * move the same counter.
 *
 * @returns The checked nonce, and the hook to pass as the send's beforeBroadcast, which records the
 *   signed transaction under its nonce and refuses the broadcast if it cannot, or if looking up an
 *   earlier transaction of ours at that nonce outruns the deadline (OutOfTime); call undo when the
 *   send threw NotBroadcast.
 * @throws RelayerHalted after halting the relayer and closing `window` when a nonce between the
 *   stored one and the chain's is not a transaction of ours in a block;
 *   WindowUnavailable("nonce_pending") while one of ours still waits for a block after
 *   NONCE_CONFIRM_WAIT_MS; WindowUnavailable("nonce_unavailable") when the chain gives no nonce or
 *   no lookup, or its nonce is behind the stored one; OutOfTime when a read outruns the deadline;
 *   any store or read error as it came.
 */
export async function guardSend(deps: WindowDeps, window: EvmWindow): Promise<SendGuard> {
  const deadline = deps.deadline ?? startDeadline(RELAY_DEADLINE_MS);
  const nonce = await checkNonce(deps, deadline, window);
  return { nonce, ...recorder(deps, "strict", deadline) };
}

/**
 * Closes the relayer's window with MsgCloseEVMWindow, logs one line, and refuses. The close fee is
 * counted but never refused: closing a window we did not ask for must not wait on the budget. A
 * close that fails is retried by the next read, which finds the same window. A close that is not
 * itself part of a halt checks the nonce first, and halts when a nonce the chain used is not ours.
 * Every close is recorded under its nonce before its broadcast, but neither a nonce that cannot be
 * checked nor a record that cannot be written stops it, because closing is the safe direction.
 */
async function closeAndRefuse(deps: WindowDeps, deadline: Deadline, reason: WindowRefusal, window: EvmWindow, extra: Record<string, string | boolean> = {}): Promise<never> {
  const halting = reason === "suspected_key_leak" || reason === "halted_window";
  if (!halting) {
    try {
      await checkNonce(deps, deadline, window);
    } catch (error) {
      if (error instanceof RelayerHalted) throw error;
      logEvent("relayer_nonce_unchecked", { reason, relayer: deps.relayer.qor1 });
    }
  }
  const ledger = await recordSpend(deps.store, deps.now, WINDOW_CLOSE_FEE_UQOR);
  const fields = { reason, relayer: deps.relayer.qor1, ledgerUqor: ledger ?? -1, ...extra };
  const record = recorder(deps, "best_effort", deadline);
  try {
    const { hash } = await deps.chain.closeWindow(deadline, record.beforeBroadcast);
    logEvent("relayer_window_closed", { ...fields, hash });
  } catch (error) {
    if (nothingSent(error)) await record.undo();
    logEvent("relayer_window_close_failed", fields);
  }
  throw halting ? new RelayerHalted() : new WindowUnavailable(reason);
}

/**
 * Someone else used the relayer's key: its window shows spending we did not record, or its nonce
 * moved past ours. Halts first, with no expiry (threat model C25), then closes. If the flag cannot
 * be written the close still happens and the line says so.
 */
async function haltAndClose(deps: WindowDeps, deadline: Deadline, window: EvmWindow, extra: Record<string, string> = {}): Promise<never> {
  const halted = await deps.store.setIfAbsent(HALT_KEY, "suspected_key_leak", DURABLE_SECONDS).then(
    () => true,
    () => false,
  );
  const used = usedByChain(window);
  const ours = await sentThrough(deps.store, window.openedHeight).catch(() => ({ value: -1n, txs: -1n }));
  return closeAndRefuse(deps, deadline, "suspected_key_leak", window, {
    window: window.openedHeight.toString(),
    chainUsedUqor: used.value.toString(),
    chainUsedTxs: used.txs.toString(),
    recordedUqor: ours.value.toString(),
    recordedTxs: ours.txs.toString(),
    halted,
    ...extra,
  });
}

/**
 * Keeps the relayer's EVM window open, narrow, inside the day's budget and big enough for the next
 * transaction (threat model C24, C25, C31), under the shared lock "relayer:window" so two server
 * instances never both open one. Call it under SEND_LOCK, as handleRelay does: an open or a close
 * moves the same nonce an EVM send uses.
 *
 * Every read is checked first. While halted nothing opens, and a live window is closed, so a close
 * that failed earlier is tried again. A window of any shape the relayer could not have asked for
 * (isOurShape) is closed at once and the call refuses. A window that shows more value or
 * transactions used than every send we recorded through it (spentOutsideUs) means someone else
 * holds the key: the relayer is halted, with no expiry, and the window closed. A usable window
 * (renewalReason) is kept.
 * Otherwise, if no more than OPEN_CUTOFF_MS of the relay's time has gone, both before and after
 * the nonce check, it checks the relayer's nonce against the one stored (a nonce the chain used
 * that is not a transaction of ours in a block halts and closes; see guardSend), books the open
 * fee on the day's total (refusing unless one worst-case transaction still fits after it), and
 * opens the one window windowRequest describes with max_value the smaller of a full window and
 * what is left of the day, recording the open under its nonce before its broadcast (an open whose
 * record cannot be written is never sent). An open the node refused before any block, one that ran
 * out of time before its broadcast, or one never sent gives the fee and the record back instead.
 * The stored nonce moves past the open only when a later check finds it in a block. It then reads
 * the window back, closes and refuses if the chain stored anything else, and pauses
 * WAIT_AFTER_WINDOW_MS before any EVM transaction may follow. Every close it makes is checked and
 * recorded the same way, but never stopped by either.
 *
 * @throws RelayerHalted when halted or on a suspected leak; DailyCeilingReached (renewal stops
 *   until the next UTC day); WindowUnavailable when the open fails, a window was closed, the chain
 *   gives no nonce or no lookup, or one of our own transactions still waits for a block; OutOfTime
 *   when it is too late to open or a read outran the deadline; LockBusy when another holder keeps
 *   the lock past WINDOW_LOCK_WAIT_MS.
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
        if (current.found && current.live) return closeAndRefuse(deps, deadline, "halted_window", current);
        throw new RelayerHalted();
      }
      if (current.found && !isOurShape(current)) return closeAndRefuse(deps, deadline, "unexpected_window", current);
      if (current.found && (await spentOutsideUs(deps.store, current))) return haltAndClose(deps, deadline, current);
      const reason = renewalReason(current, valueFor(await spentToday(deps.store, deps.now)));
      if (reason === undefined) return { opened: false, window: current };

      if (elapsedMs(deadline) > OPEN_CUTOFF_MS) throw new OutOfTime("opening a window");
      await checkNonce(deps, deadline, current);
      // The check may have waited for one of our own transactions to reach a block.
      if (elapsedMs(deadline) > OPEN_CUTOFF_MS) throw new OutOfTime("opening a window");
      const { reservation, after: total } = await book(deps.store, [ledgerFor("total", deps.now)], WINDOW_OPEN_FEE_UQOR, "window", WORST_TX_COST_UQOR);
      const room = RELAYER_DAILY_CEILING_UQOR - total;
      const request = windowRequest(room < WINDOW.maxValue ? room : WINDOW.maxValue);
      const record = recorder(deps, "strict", deadline);
      let hash: string;
      try {
        ({ hash } = await deps.chain.openWindow(request, narrowed(deadline, NATIVE_TX_BUDGET_MS), record.beforeBroadcast));
      } catch (error) {
        if (nothingSent(error)) {
          await releaseSpend(deps.store, reservation);
          await record.undo();
        }
        logEvent("relayer_window_refused", { reason: "open_failed", because: reason });
        throw new WindowUnavailable("open_failed");
      }
      const opened = await within(deadline, deps.chain.readWindow(), "reading the window back").catch(() => undefined);
      if (opened === undefined || !matchesRequest(opened, request)) return closeAndRefuse(deps, deadline, "readback_mismatch", opened ?? current, { opened: hash });
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
