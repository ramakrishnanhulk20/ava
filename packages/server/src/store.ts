import { randomUUID } from "node:crypto";
import { Redis } from "@upstash/redis";
import { logEvent } from "./log.ts";

/**
 * The shared, durable state every once-only, rate, budget and nonce decision lives in (threat model
 * C31). Serverless instances share no memory and a restart wipes it, so nothing security-relevant
 * may be decided from process memory.
 */
export interface SharedStore {
  /**
   * Adds `amount` (1 by default) to the counter at `key` and returns the new total. The counter
   * starts its life of `windowSeconds` on the first increment and is never extended, so every
   * key is a fixed window that ends on its own.
   */
  incrWindow(key: string, windowSeconds: number, amount?: number): Promise<number>;
  /** Writes `value` with a lifetime of `ttlSeconds` only if `key` holds nothing. True when it wrote. */
  setIfAbsent(key: string, value: string, ttlSeconds: number): Promise<boolean>;
  get(key: string): Promise<string | null>;
  /**
   * Removes `key`. True only when it held something, so when several callers delete one key at
   * once exactly one of them sees true. That is what makes a stored value single use.
   */
  delete(key: string): Promise<boolean>;
  /**
   * Runs `fn` while holding the lock `key`. Fails fast with LockBusy when another holder has it,
   * unless `options.waitMs` is set: then it tries again after a random pause of 50 to 200 ms until
   * the lock is free or `waitMs` has passed, and only then throws LockBusy.
   * The lock ends after `ttlSeconds` even if `fn` is still running, so `ttlSeconds` must exceed the
   * longest `fn` can take. The release deletes the lock only if it is still this holder's.
   */
  withLock<T>(key: string, ttlSeconds: number, fn: () => Promise<T>, options?: LockOptions): Promise<T>;
}

export interface LockOptions {
  /** How long to keep trying for a held lock, in milliseconds, at most LOCK_MAX_WAIT_MS. 0, the default, does not wait. */
  waitMs?: number;
}

/** Another holder has the lock. Nothing ran. */
export class LockBusy extends Error {
  constructor() {
    super("The lock is held by someone else.");
    this.name = "LockBusy";
  }
}

/** The store answered with something that is not the reply the command defines. */
export class StoreReplyError extends Error {
  constructor(command: string) {
    super(`The shared store gave an unexpected reply to ${command}.`);
    this.name = "StoreReplyError";
  }
}

const MAX_KEY_LENGTH = 256;
const LOCK_PREFIX = "lock:";
const UPSTASH_TIMEOUT_MS = 3_000;

function checkKey(key: string): void {
  if (typeof key !== "string" || key.length === 0 || key.length > MAX_KEY_LENGTH) {
    throw new TypeError(`A store key is a string of 1 to ${MAX_KEY_LENGTH} characters.`);
  }
}

function checkCount(value: number, what: string): void {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${what} must be a whole number of at least 1.`);
}

export const LOCK_MAX_WAIT_MS = 20_000;
const LOCK_RETRY_MIN_MS = 50;
const LOCK_RETRY_JITTER_MS = 150;

function waitOf(options: LockOptions | undefined): number {
  const waitMs = options?.waitMs ?? 0;
  if (!Number.isSafeInteger(waitMs) || waitMs < 0 || waitMs > LOCK_MAX_WAIT_MS) {
    throw new TypeError(`waitMs must be a whole number of milliseconds from 0 to ${LOCK_MAX_WAIT_MS}.`);
  }
  return waitMs;
}

/**
 * Calls `tryAcquire` until it takes the lock or `waitMs` has passed. The random pause keeps waiters
 * on several instances from retrying in step. Time is measured on the process's monotonic clock.
 */
async function acquire(tryAcquire: () => Promise<boolean>, waitMs: number): Promise<void> {
  const deadline = performance.now() + waitMs;
  for (;;) {
    if (await tryAcquire()) return;
    const left = deadline - performance.now();
    if (left <= 0) throw new LockBusy();
    const pause = Math.min(left, LOCK_RETRY_MIN_MS + Math.random() * LOCK_RETRY_JITTER_MS);
    await new Promise((resolve) => setTimeout(resolve, pause));
  }
}

// Compare-and-delete in one step, so a holder whose lock already expired cannot delete the next holder's lock.
const RELEASE_SCRIPT = `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end`;

/** SharedStore on Upstash Redis over its REST API. */
export class UpstashStore implements SharedStore {
  readonly #redis: Redis;

  /** Wraps a client. Use `UpstashStore.connect` in the app; tests pass a client with a stub requester. */
  constructor(redis: Redis) {
    this.#redis = redis;
  }

  /**
   * A store on the database at `url`. Replies come back raw, never JSON-decoded, so `get` returns
   * the exact string that was written. Each request has its own timeout signal created per call:
   * the client turns an abort on a shared signal into an empty success, which would fail open.
   */
  static connect(settings: { url: string; token: string }): UpstashStore {
    return new UpstashStore(
      new Redis({
        url: settings.url,
        token: settings.token,
        automaticDeserialization: false,
        enableAutoPipelining: false,
        enableTelemetry: false,
        retry: { retries: 2, backoff: (attempt) => 100 * (attempt + 1) },
        signal: () => AbortSignal.timeout(UPSTASH_TIMEOUT_MS),
      }),
    );
  }

  async incrWindow(key: string, windowSeconds: number, amount = 1): Promise<number> {
    checkKey(key);
    checkCount(windowSeconds, "windowSeconds");
    checkCount(amount, "amount");
    // One MULTI transaction: the increment and the expiry land together. EXPIRE NX sets the
    // lifetime only when the key has none, so later increments never stretch the window.
    const [total] = await this.#redis.multi().incrby(key, amount).expire(key, windowSeconds, "NX").exec();
    if (typeof total !== "number" || !Number.isSafeInteger(total)) throw new StoreReplyError("INCRBY");
    return total;
  }

  async setIfAbsent(key: string, value: string, ttlSeconds: number): Promise<boolean> {
    checkKey(key);
    checkCount(ttlSeconds, "ttlSeconds");
    if (typeof value !== "string") throw new TypeError("A stored value is a string.");
    const reply = await this.#redis.set(key, value, { nx: true, ex: ttlSeconds });
    if (reply === "OK") return true;
    if (reply === null) return false;
    throw new StoreReplyError("SET NX");
  }

  async get(key: string): Promise<string | null> {
    checkKey(key);
    const reply: unknown = await this.#redis.get(key);
    if (reply === null || typeof reply === "string") return reply;
    throw new StoreReplyError("GET");
  }

  async delete(key: string): Promise<boolean> {
    checkKey(key);
    const reply: unknown = await this.#redis.del(key);
    if (reply === 1) return true;
    if (reply === 0) return false;
    throw new StoreReplyError("DEL");
  }

  async withLock<T>(key: string, ttlSeconds: number, fn: () => Promise<T>, options?: LockOptions): Promise<T> {
    const lockKey = LOCK_PREFIX + key;
    checkKey(lockKey);
    checkCount(ttlSeconds, "ttlSeconds");
    const waitMs = waitOf(options);
    const token = randomUUID();
    await acquire(async () => {
      const reply = await this.#redis.set(lockKey, token, { nx: true, ex: ttlSeconds });
      if (reply === null) return false;
      if (reply !== "OK") throw new StoreReplyError("SET NX");
      return true;
    }, waitMs);
    try {
      return await fn();
    } finally {
      // A failed release is not the caller's failure: fn already ran, and the lock ends at its TTL.
      await this.#redis.eval(RELEASE_SCRIPT, [lockKey], [token]).catch(() => logEvent("lock_release_failed"));
    }
  }
}

interface MemoryEntry {
  value: string;
  expiresAt: number;
}

/**
 * SharedStore in process memory, for tests only. It refuses to exist when NODE_ENV is
 * "production", because in production it would hold rate and once-only state in exactly the place
 * C31 forbids.
 */
export class MemoryStore implements SharedStore {
  readonly #entries = new Map<string, MemoryEntry>();
  readonly #now: () => number;

  /** @param options.now The clock in milliseconds, so tests can move time. Defaults to Date.now. */
  constructor(options: { now?: () => number } = {}) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("MemoryStore is for tests only and cannot be used when NODE_ENV is production.");
    }
    this.#now = options.now ?? Date.now;
  }

  #live(key: string): MemoryEntry | undefined {
    const entry = this.#entries.get(key);
    if (entry !== undefined && entry.expiresAt <= this.#now()) {
      this.#entries.delete(key);
      return undefined;
    }
    return entry;
  }

  async incrWindow(key: string, windowSeconds: number, amount = 1): Promise<number> {
    checkKey(key);
    checkCount(windowSeconds, "windowSeconds");
    checkCount(amount, "amount");
    const entry = this.#live(key);
    const total = (entry === undefined ? 0 : Number(entry.value)) + amount;
    const expiresAt = entry?.expiresAt ?? this.#now() + windowSeconds * 1000;
    this.#entries.set(key, { value: String(total), expiresAt });
    return total;
  }

  async setIfAbsent(key: string, value: string, ttlSeconds: number): Promise<boolean> {
    checkKey(key);
    checkCount(ttlSeconds, "ttlSeconds");
    if (typeof value !== "string") throw new TypeError("A stored value is a string.");
    if (this.#live(key) !== undefined) return false;
    this.#entries.set(key, { value, expiresAt: this.#now() + ttlSeconds * 1000 });
    return true;
  }

  async get(key: string): Promise<string | null> {
    checkKey(key);
    return this.#live(key)?.value ?? null;
  }

  async delete(key: string): Promise<boolean> {
    checkKey(key);
    const held = this.#live(key) !== undefined;
    this.#entries.delete(key);
    return held;
  }

  async withLock<T>(key: string, ttlSeconds: number, fn: () => Promise<T>, options?: LockOptions): Promise<T> {
    const lockKey = LOCK_PREFIX + key;
    const waitMs = waitOf(options);
    const token = randomUUID();
    await acquire(() => this.setIfAbsent(lockKey, token, ttlSeconds), waitMs);
    try {
      return await fn();
    } finally {
      if (this.#live(lockKey)?.value === token) this.#entries.delete(lockKey);
    }
  }
}
