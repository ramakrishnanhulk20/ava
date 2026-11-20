import type { SharedStore } from "../src/store.ts";

/** A store whose every call fails, to prove the callers fail closed. */
export function failingStore(): SharedStore {
  const fail = async (): Promise<never> => {
    throw new Error("store is down");
  };
  return { incrWindow: fail, setIfAbsent: fail, get: fail, compareAndSet: fail, delete: fail, withLock: fail };
}

export type RetriedWrite = "setIfAbsent" | "compareAndSet" | "delete" | "incrWindow";

/**
 * A store that applies every write `retried` names twice and answers what the second one answered:
 * what the Upstash client does when it retries a request whose reply was lost. A once-only write
 * that did land then answers false, and an increment counts twice.
 */
export function retriedWrites(store: SharedStore, retried: (write: RetriedWrite, key: string) => boolean): SharedStore {
  return {
    get: (key) => store.get(key),
    incrWindow: async (key, windowSeconds, amount) => {
      if (retried("incrWindow", key)) await store.incrWindow(key, windowSeconds, amount);
      return store.incrWindow(key, windowSeconds, amount);
    },
    withLock: (key, ttl, fn, options) => store.withLock(key, ttl, fn, options),
    setIfAbsent: async (key, value, ttl) => {
      if (retried("setIfAbsent", key)) await store.setIfAbsent(key, value, ttl);
      return store.setIfAbsent(key, value, ttl);
    },
    compareAndSet: async (key, expected, next, ttl) => {
      if (retried("compareAndSet", key)) await store.compareAndSet(key, expected, next, ttl);
      return store.compareAndSet(key, expected, next, ttl);
    },
    delete: async (key) => {
      if (retried("delete", key)) await store.delete(key);
      return store.delete(key);
    },
  };
}

/**
 * A request body that sends one byte and then never ends. `waiting()` turns true once a reader is
 * blocked on it, which is when a handler's read deadline is already running.
 */
export function stalledBody() {
  let pulls = 0;
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        pulls += 1;
        if (pulls === 1) controller.enqueue(new Uint8Array([1]));
        else return new Promise<void>(() => undefined);
      },
    },
    { highWaterMark: 0 },
  );
  return { stream, waiting: (): boolean => pulls >= 2 };
}

/** What a fetch from our own app carries: the custom header, and the origin the browser reports. */
export const APP_HEADERS: Readonly<Record<string, string>> = { "x-ava": "1", "sec-fetch-site": "same-origin" };

/**
 * Header sets our app never sends and a cross-site page can: no x-ava (what a beacon, an image, a
 * form or a no-cors fetch carries), or x-ava with a Sec-Fetch-Site other than same-origin.
 */
export const CROSS_SITE_HEADERS: readonly Record<string, string>[] = [
  {},
  { "sec-fetch-site": "cross-site" },
  { "x-ava": "1", "sec-fetch-site": "cross-site" },
  { "x-ava": "1", "sec-fetch-site": "same-site" },
  { "x-ava": "1", "sec-fetch-site": "none" },
  { "x-ava": "true", "sec-fetch-site": "same-origin" },
];
