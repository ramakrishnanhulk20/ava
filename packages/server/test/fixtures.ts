import type { SharedStore } from "../src/store.ts";

/** A store whose every call fails, to prove the callers fail closed. */
export function failingStore(): SharedStore {
  const fail = async (): Promise<never> => {
    throw new Error("store is down");
  };
  return { incrWindow: fail, setIfAbsent: fail, get: fail, delete: fail, withLock: fail };
}
