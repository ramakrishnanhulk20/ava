// Not covered here: a real Upstash database. UpstashStore is checked against a stub requester that
// records the exact commands it sends; whether Upstash runs them atomically is Upstash's promise,
// checked in the live runs. Lock expiry while fn is still running is a stated limit, not tested.
import { Redis, type Requester } from "@upstash/redis";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LockBusy, MemoryStore, StoreReplyError, UpstashStore, claimOnce } from "../src/store.ts";
import { retriedWrites } from "./fixtures.ts";

function clock(start = 1_000_000) {
  let now = start;
  return { now: () => now, advance: (ms: number) => (now += ms) };
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("MemoryStore", () => {
  it("counts in a fixed window that later increments never stretch", async () => {
    const time = clock();
    const store = new MemoryStore({ now: time.now });
    expect(await store.incrWindow("k", 60)).toBe(1);
    expect(await store.incrWindow("k", 60, 5)).toBe(6);
    time.advance(59_999);
    expect(await store.incrWindow("k", 60)).toBe(7);
    time.advance(1);
    expect(await store.incrWindow("k", 60)).toBe(1);
  });

  it("writes once with setIfAbsent and forgets after the lifetime", async () => {
    const time = clock();
    const store = new MemoryStore({ now: time.now });
    expect(await store.setIfAbsent("once", "a", 10)).toBe(true);
    expect(await store.setIfAbsent("once", "b", 10)).toBe(false);
    expect(await store.get("once")).toBe("a");
    time.advance(10_000);
    expect(await store.get("once")).toBeNull();
  });

  it("deletes a key once: of two racing deletes only one reports a removal", async () => {
    const time = clock();
    const store = new MemoryStore({ now: time.now });
    await store.setIfAbsent("challenge", "c", 10);
    expect(await Promise.all([store.delete("challenge"), store.delete("challenge")])).toEqual([true, false]);
    expect(await store.get("challenge")).toBeNull();
    await store.setIfAbsent("expired", "e", 1);
    time.advance(1_000);
    expect(await store.delete("expired")).toBe(false);
    await expect(store.delete("")).rejects.toBeInstanceOf(TypeError);
  });

  it("compares and sets: from absent, from the matching value, never from another value, and with a fresh lifetime", async () => {
    const time = clock();
    const store = new MemoryStore({ now: time.now });
    expect(await store.compareAndSet("cursor", null, "10", 60)).toBe(true);
    expect(await store.compareAndSet("cursor", null, "11", 60)).toBe(false);
    expect(await store.compareAndSet("cursor", "10", "20", 60)).toBe(true);
    expect(await store.compareAndSet("cursor", "10", "30", 60)).toBe(false);
    expect(await store.get("cursor")).toBe("20");

    time.advance(59_999);
    expect(await store.compareAndSet("cursor", "20", "21", 60)).toBe(true);
    time.advance(59_999);
    expect(await store.get("cursor")).toBe("21");
    time.advance(1);
    expect(await store.get("cursor")).toBeNull();
    expect(await store.compareAndSet("cursor", "21", "22", 60)).toBe(false);
    expect(await store.compareAndSet("cursor", null, "", 60)).toBe(true);
    expect(await store.compareAndSet("cursor", null, "x", 60)).toBe(false);
    expect(await store.compareAndSet("cursor", "", "x", 60)).toBe(true);

    await expect(store.compareAndSet("", null, "a", 60)).rejects.toBeInstanceOf(TypeError);
    await expect(store.compareAndSet("k", null, "a", 0)).rejects.toBeInstanceOf(TypeError);
    await expect(store.compareAndSet("k", 1 as never, "a", 60)).rejects.toBeInstanceOf(TypeError);
  });

  it("refuses a second holder, releases after fn even when it throws", async () => {
    const store = new MemoryStore();
    const second = vi.fn(async () => "ran");
    await store.withLock("queue", 30, async () => {
      await expect(store.withLock("queue", 30, second)).rejects.toBeInstanceOf(LockBusy);
    });
    expect(second).not.toHaveBeenCalled();
    await expect(store.withLock("queue", 30, async () => Promise.reject(new Error("boom")))).rejects.toThrow("boom");
    expect(await store.withLock("queue", 30, second)).toBe("ran");
  });

  it("never deletes a lock that expired and was taken by the next holder", async () => {
    const time = clock();
    const store = new MemoryStore({ now: time.now });
    await store.withLock("queue", 1, async () => {
      time.advance(1_000);
      expect(await store.setIfAbsent("lock:queue", "next-holder", 30)).toBe(true);
    });
    expect(await store.get("lock:queue")).toBe("next-holder");
  });

  it("refuses bad arguments", async () => {
    const store = new MemoryStore();
    await expect(store.incrWindow("", 60)).rejects.toBeInstanceOf(TypeError);
    await expect(store.incrWindow("k", 0)).rejects.toBeInstanceOf(TypeError);
    await expect(store.incrWindow("k", 60, 1.5)).rejects.toBeInstanceOf(TypeError);
    await expect(store.setIfAbsent("k", "v", -1)).rejects.toBeInstanceOf(TypeError);
  });

  it("refuses to construct when NODE_ENV is production", () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(() => new MemoryStore()).toThrow(/tests only/);
  });
});

describe("claimOnce", () => {
  it("counts a write retried after its reply was lost as the caller's own, and never another caller's value", async () => {
    const store = new MemoryStore();
    const retried = retriedWrites(store, (write) => write === "setIfAbsent");
    expect(await retried.setIfAbsent("mark", "mine", 60)).toBe(false);
    expect(await store.get("mark")).toBe("mine");

    expect(await claimOnce(retried, "claimed", "a:1", 60)).toBe(true);
    expect(await claimOnce(retried, "claimed", "b:2", 60)).toBe(false);
    expect(await claimOnce(store, "claimed", "a:1", 60)).toBe(true);
    expect(await store.get("claimed")).toBe("a:1");
  });
});

function recordingUpstash(reply: (command: unknown[]) => unknown) {
  const sent: { path: string[] | undefined; body: unknown }[] = [];
  const requester = {
    request: async (req: { path?: string[]; body?: unknown }) => {
      sent.push({ path: req.path, body: req.body });
      if (req.path?.[0] === "multi-exec") return (req.body as unknown[][]).map((command) => ({ result: reply(command) }));
      return { result: reply(req.body as unknown[]) };
    },
  } as unknown as Requester;
  return { store: new UpstashStore(new Redis(requester)), sent };
}

describe("UpstashStore", () => {
  it("sends the increment and the expiry together in one MULTI transaction", async () => {
    const { store, sent } = recordingUpstash((command) => (command[0] === "incrby" ? 7 : 1));
    expect(await store.incrWindow("rate:k", 60, 3)).toBe(7);
    expect(sent).toEqual([
      {
        path: ["multi-exec"],
        body: [
          ["incrby", "rate:k", 3],
          ["expire", "rate:k", 60, "NX"],
        ],
      },
    ]);
  });

  it("writes once with SET NX EX", async () => {
    let reply: string | null = "OK";
    const { store, sent } = recordingUpstash(() => reply);
    expect(await store.setIfAbsent("once:a", "1", 86_400)).toBe(true);
    reply = null;
    expect(await store.setIfAbsent("once:a", "1", 86_400)).toBe(false);
    expect(sent[0]).toEqual({ path: undefined, body: ["set", "once:a", "1", "nx", "ex", 86_400] });
  });

  it("deletes with DEL and reports whether a key was removed", async () => {
    let reply: unknown = 1;
    const { store, sent } = recordingUpstash(() => reply);
    expect(await store.delete("demo:challenge:ab")).toBe(true);
    reply = 0;
    expect(await store.delete("demo:challenge:ab")).toBe(false);
    expect(sent[0]).toEqual({ path: undefined, body: ["del", "demo:challenge:ab"] });
    reply = "not a count";
    await expect(store.delete("demo:challenge:ab")).rejects.toBeInstanceOf(StoreReplyError);
  });

  it("locks with SET NX EX and releases with a compare-and-delete of its own token", async () => {
    const { store, sent } = recordingUpstash((command) => (command[0] === "set" ? "OK" : 1));
    expect(await store.withLock("queue", 30, async () => "done")).toBe("done");
    const [acquire, release] = sent.map((entry) => entry.body as unknown[]);
    expect(acquire?.slice(0, 3)).toEqual(["set", "lock:queue", acquire?.[2]]);
    expect(acquire?.slice(3)).toEqual(["nx", "ex", 30]);
    expect(release?.[0]).toBe("eval");
    expect(String(release?.[1])).toContain('redis.call("get", KEYS[1]) == ARGV[1]');
    expect(release?.slice(2)).toEqual([1, "lock:queue", acquire?.[2]]);
  });

  it("compares and sets in one EVAL that reads, compares and writes with its lifetime", async () => {
    let reply: unknown = 1;
    const { store, sent } = recordingUpstash(() => reply);
    expect(await store.compareAndSet("envsweep:next-block", "10", "20", 600)).toBe(true);
    expect(await store.compareAndSet("envsweep:next-block", null, "10", 600)).toBe(true);
    reply = 0;
    expect(await store.compareAndSet("envsweep:next-block", "10", "20", 600)).toBe(false);
    const [fromValue, fromAbsent] = sent.map((entry) => entry.body as unknown[]);
    expect(sent).toHaveLength(3);
    expect(fromValue?.[0]).toBe("eval");
    expect(String(fromValue?.[1])).toMatch(/redis\.call\("get", KEYS\[1\]\)[\s\S]*redis\.call\("set", KEYS\[1\], ARGV\[3\], "EX", ARGV\[4\]\)/);
    expect(fromValue?.slice(2)).toEqual([1, "envsweep:next-block", "value", "10", "20", "600"]);
    expect(fromAbsent?.slice(2)).toEqual([1, "envsweep:next-block", "absent", "", "10", "600"]);
    reply = "OK";
    await expect(store.compareAndSet("envsweep:next-block", "10", "20", 600)).rejects.toBeInstanceOf(StoreReplyError);
  });

  it("takes a lock whose SET NX landed but answered no, as a request retried after a lost reply does, runs fn once and releases it", async () => {
    const held = new Map<string, string>();
    const { store } = recordingUpstash((command) => {
      const [name, key, value] = command.map(String) as [string, string, string];
      if (name === "set") {
        if (!held.has(key)) held.set(key, value);
        return null;
      }
      if (name === "get") return held.get(key) ?? null;
      const [, , , releaseKey, token] = command.map(String);
      if (name === "eval" && releaseKey !== undefined && held.get(releaseKey) === token) return Number(held.delete(releaseKey));
      return 0;
    });
    const fn = vi.fn(async () => "ran");
    expect(await store.withLock("queue", 30, fn)).toBe("ran");
    expect(fn).toHaveBeenCalledTimes(1);
    expect(held.has("lock:queue")).toBe(false);

    held.set("lock:queue", "another-holder");
    await expect(store.withLock("queue", 30, fn)).rejects.toBeInstanceOf(LockBusy);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(held.get("lock:queue")).toBe("another-holder");
  });

  it("does not run fn when the lock is held, and refuses a malformed reply", async () => {
    const busy = recordingUpstash(() => null);
    const fn = vi.fn(async () => "ran");
    await expect(busy.store.withLock("queue", 30, fn)).rejects.toBeInstanceOf(LockBusy);
    expect(fn).not.toHaveBeenCalled();
    const odd = recordingUpstash(() => "not a number");
    await expect(odd.store.incrWindow("rate:k", 60)).rejects.toBeInstanceOf(StoreReplyError);
  });
});
