// Not covered here: a real chain or a real Upstash database. The window keeper runs against a stub
// chain that records every open and close, on a test clock, and the bounded lock wait against
// MemoryStore and a stub Upstash requester. That the chain stores the window it was asked for, and
// what it reports as its blocks, is checked live by the read-back in ensureWindow and by
// scripts/live-relay-check.ts.
import { evmWindowCost, type EvmWindow } from "@qorechain/evm";
import { Redis, type Requester } from "@upstash/redis";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OutOfTime, startDeadline } from "../src/chain/deadline.ts";
import type { WindowChain, WindowRequest } from "../src/chain/types.ts";
import { DAILY_SPEND_CEILING_UQOR, REGISTRY_ADDRESS, WINDOW_CLOSE_FEE_UQOR, WINDOW_OPEN_FEE_UQOR } from "../src/config.ts";
import { LOCK_MAX_WAIT_MS, LockBusy, MemoryStore, UpstashStore } from "../src/store.ts";
import { DailyCeilingReached, RelayerHalted, WindowUnavailable, ensureWindow, haltKey, recordWindowSend, spendKey, spentToday } from "../src/window.ts";

beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("withLock bounded wait", () => {
  it("still fails at once by default, and waits for a held lock when waitMs is set", async () => {
    const store = new MemoryStore();
    let release: () => void = () => undefined;
    const holder = store.withLock("queue", 30, () => new Promise<void>((resolve) => (release = resolve)));
    await expect(store.withLock("queue", 30, async () => "ran")).rejects.toBeInstanceOf(LockBusy);
    const waiter = store.withLock("queue", 30, async () => "ran after", { waitMs: 5_000 });
    setTimeout(() => release(), 300);
    await holder;
    expect(await waiter).toBe("ran after");
  });

  it("throws LockBusy once waitMs passes, without running fn, and refuses a wait over 20 s", async () => {
    const store = new MemoryStore();
    const fn = vi.fn(async () => "ran");
    await store.withLock("queue", 30, async () => {
      const started = performance.now();
      await expect(store.withLock("queue", 30, fn, { waitMs: 400 })).rejects.toBeInstanceOf(LockBusy);
      expect(performance.now() - started).toBeGreaterThanOrEqual(390);
    });
    expect(fn).not.toHaveBeenCalled();
    expect(LOCK_MAX_WAIT_MS).toBe(20_000);
    await expect(store.withLock("queue", 30, fn, { waitMs: -1 })).rejects.toBeInstanceOf(TypeError);
    await expect(store.withLock("queue", 30, fn, { waitMs: 20_001 })).rejects.toBeInstanceOf(TypeError);
  });

  it("retries SET NX on Upstash until the lock is free", async () => {
    const sets: unknown[][] = [];
    let busy = 2;
    const requester = {
      request: async (req: { body?: unknown }) => {
        const command = req.body as unknown[];
        if (command[0] === "set") {
          sets.push(command);
          return { result: busy-- > 0 ? null : "OK" };
        }
        return { result: 1 };
      },
    } as unknown as Requester;
    const store = new UpstashStore(new Redis(requester));
    expect(await store.withLock("queue", 30, async () => "done", { waitMs: 5_000 })).toBe("done");
    expect(sets).toHaveLength(3);
    expect(new Set(sets.map((command) => command[2])).size).toBe(1);
  });
});

const NOW = Date.parse("2026-11-17T12:00:00Z");
const RELAYER = { qor1: "qor13gmaduk6r79q0utnt3tgcfs3ypwe86tn8292fq", evm: "0x8A37d6f2DA1F8a07f1735c568C2611205d93e973" } as const;
const OTHER = "0x624b5c35e3665eb9ade6d75bbbca1218a09e00d1";
const WORST_TX = evmWindowCost({ gas: 650_000n, maxFeePerGas: 250_000_000_000n });
const FULL = 40n * WORST_TX;

function windowOf(over: Partial<EvmWindow> = {}): EvmWindow {
  return {
    found: true,
    live: true,
    openedHeight: 1_000n,
    expiryHeight: 13_000n,
    maxTxs: 40n,
    usedTxs: 0n,
    maxValue: FULL,
    usedValue: 0n,
    remainingBlocks: 12_000n,
    remainingTxs: 40n,
    remainingValue: FULL,
    nativeOnly: false,
    allowedTargets: [REGISTRY_ADDRESS.toLowerCase()],
    ...over,
  };
}

const NONE = windowOf({ found: false, live: false, openedHeight: 0n, expiryHeight: 0n, maxTxs: 0n, maxValue: 0n, remainingBlocks: 0n, remainingTxs: 0n, remainingValue: 0n, allowedTargets: [] });

function asOpened(request: WindowRequest): EvmWindow {
  return windowOf({
    maxTxs: BigInt(request.maxTxs),
    maxValue: request.maxValue,
    remainingTxs: BigInt(request.maxTxs),
    remainingValue: request.maxValue,
    remainingBlocks: BigInt(request.blocks),
    expiryHeight: 1_000n + BigInt(request.blocks),
    allowedTargets: request.allowedTargets.map((t) => t.toLowerCase()),
  });
}

/** A chain whose window the stub replaces on every open and removes on every close, as the chain does; `stored` overrides what an open keeps. */
function stubChain(initial: EvmWindow, stored?: (request: WindowRequest) => EvmWindow) {
  let current = initial;
  const opens: WindowRequest[] = [];
  let closes = 0;
  const chain: WindowChain = {
    readWindow: async () => current,
    openWindow: async (request) => {
      opens.push(request);
      await new Promise((resolve) => setTimeout(resolve, 20));
      current = stored?.(request) ?? asOpened(request);
      return { hash: "AB".repeat(32) };
    },
    closeWindow: async () => {
      closes += 1;
      current = NONE;
      return { hash: "CD".repeat(32) };
    },
  };
  return { chain, opens, closes: () => closes };
}

function deps(chain: WindowChain, store = new MemoryStore()) {
  const sleep = vi.fn(async () => undefined);
  return { store, now: NOW, relayer: RELAYER, chain, sleep };
}

/** Records `n` of our own worst-case sends through the window opened at `openedHeight`, as the relay does. */
async function ourSends(store: MemoryStore, n: number, openedHeight = 1_000n): Promise<MemoryStore> {
  for (let i = 0; i < n; i++) await recordWindowSend(store, openedHeight, WORST_TX);
  return store;
}

async function spentAlready(uqor: bigint): Promise<MemoryStore> {
  const store = new MemoryStore();
  if (uqor > 0n) await store.incrWindow(spendKey(NOW), 172_800, Number(uqor));
  return store;
}

describe("ensureWindow: opening and renewing", () => {
  it("opens a window scoped to the registry alone when there is none, sized for 40 worst-case transactions", async () => {
    const { chain, opens } = stubChain(NONE);
    const d = deps(chain);
    const state = await ensureWindow(d);
    expect(state.opened).toBe(true);
    expect(opens).toEqual([{ blocks: 12_000, maxTxs: 40, maxValue: FULL, allowedTargets: [REGISTRY_ADDRESS] }]);
    expect(FULL).toBe(6_500_000n);
    expect(Object.keys(opens[0] ?? {})).not.toContain("nativeOnly");
    expect(d.sleep).toHaveBeenCalledWith(10_000);
    expect(await spentToday(d.store, NOW)).toBe(WINDOW_OPEN_FEE_UQOR);
  });

  it("renews below each threshold and keeps a window that is exactly at them", async () => {
    for (const low of [{ remainingTxs: 2n }, { remainingBlocks: 599n }, { remainingValue: 3n * WORST_TX - 1n }, { live: false }]) {
      const { chain, opens } = stubChain(windowOf(low));
      expect((await ensureWindow(deps(chain, await ourSends(new MemoryStore(), 38)))).opened).toBe(true);
      expect(opens).toHaveLength(1);
    }
    const { chain, opens } = stubChain(windowOf({ remainingTxs: 3n, remainingBlocks: 600n, remainingValue: 3n * WORST_TX }));
    const d = deps(chain, await ourSends(new MemoryStore(), 37));
    expect((await ensureWindow(d)).opened).toBe(false);
    expect(opens).toHaveLength(0);
    expect(d.sleep).not.toHaveBeenCalled();
  });

  it("with 0.5 QOR left today gives the window at most 0.5 QOR minus the open fee, and does not renew it for value", async () => {
    const store = await spentAlready(DAILY_SPEND_CEILING_UQOR - 500_000n);
    const { chain, opens } = stubChain(NONE);
    await ensureWindow(deps(chain, store));
    expect(opens.map((o) => o.maxValue)).toEqual([500_000n - WINDOW_OPEN_FEE_UQOR]);
    expect((await ensureWindow(deps(chain, store))).opened).toBe(false);
    expect(opens).toHaveLength(1);
  });

  it("opens only when the open fee and one worst-case transaction still fit, and stops renewing below that", async () => {
    const room = WINDOW_OPEN_FEE_UQOR + WORST_TX;
    const refused = stubChain(NONE);
    await expect(ensureWindow(deps(refused.chain, await spentAlready(DAILY_SPEND_CEILING_UQOR - room + 1n)))).rejects.toBeInstanceOf(DailyCeilingReached);
    expect(refused.opens).toHaveLength(0);

    const exhausted = stubChain(windowOf({ maxValue: WORST_TX, remainingValue: WORST_TX - 1n, remainingTxs: 39n }));
    const low = await ourSends(await spentAlready(DAILY_SPEND_CEILING_UQOR - WORST_TX + 1n), 1);
    await expect(ensureWindow(deps(exhausted.chain, low))).rejects.toBeInstanceOf(DailyCeilingReached);
    expect(exhausted.opens).toHaveLength(0);

    const fits = stubChain(NONE);
    const store = await spentAlready(DAILY_SPEND_CEILING_UQOR - room);
    expect((await ensureWindow(deps(fits.chain, store))).opened).toBe(true);
    expect(fits.opens.map((o) => o.maxValue)).toEqual([WORST_TX]);
  });

  it("does not start a renewal once 20 s of the relay's time have gone", async () => {
    let clock = 0;
    const { chain, opens } = stubChain(NONE);
    const d = { ...deps(chain), deadline: startDeadline(55_000, () => clock) };
    clock = 20_001;
    await expect(ensureWindow(d)).rejects.toBeInstanceOf(OutOfTime);
    expect(opens).toHaveLength(0);
    expect(await spentToday(d.store, NOW)).toBe(0n);
  });

  it("opens once when two callers find the window low at the same time", async () => {
    const { chain, opens } = stubChain(NONE);
    const store = new MemoryStore();
    const [a, b] = await Promise.all([ensureWindow(deps(chain, store)), ensureWindow(deps(chain, store))]);
    expect(opens).toHaveLength(1);
    expect([a.opened, b.opened].sort()).toEqual([false, true]);
  });
});

describe("ensureWindow: spending by anyone else", () => {
  it("never trips on our own recorded sends, and an expired window is judged by the chain's used counters only", async () => {
    const used = windowOf({ remainingTxs: 35n, usedTxs: 5n, remainingValue: FULL - 5n * WORST_TX, usedValue: 5n * WORST_TX });
    const ours = stubChain(used);
    expect((await ensureWindow(deps(ours.chain, await ourSends(new MemoryStore(), 5)))).opened).toBe(false);
    expect(ours.closes()).toBe(0);

    const expired = stubChain(windowOf({ live: false, remainingBlocks: 0n, remainingTxs: 0n, remainingValue: 0n, usedTxs: 2n, usedValue: 2n * WORST_TX }));
    expect((await ensureWindow(deps(expired.chain, await ourSends(new MemoryStore(), 2)))).opened).toBe(true);
    expect(expired.closes()).toBe(0);
  });

  it("halts the day and closes the window when the chain shows one more transaction or 1 uqor more than we sent", async () => {
    for (const extra of [{ remainingTxs: 34n }, { remainingValue: FULL - 5n * WORST_TX - 1n }, { usedTxs: 6n }, { remainingBlocks: 0n, live: false, usedValue: 5n * WORST_TX + 1n, usedTxs: 5n }]) {
      const store = await ourSends(new MemoryStore(), 5);
      const { chain, opens, closes } = stubChain(windowOf({ remainingTxs: 35n, usedTxs: 5n, remainingValue: FULL - 5n * WORST_TX, usedValue: 5n * WORST_TX, ...extra }));
      await expect(ensureWindow(deps(chain, store))).rejects.toBeInstanceOf(RelayerHalted);
      expect(closes()).toBe(1);
      expect(opens).toHaveLength(0);
      expect(await store.get(haltKey(NOW))).toBe("suspected_key_leak");
    }
  });

  it("on a halted day opens nothing, and still closes a live window it finds", async () => {
    const store = new MemoryStore();
    await store.setIfAbsent(haltKey(NOW), "suspected_key_leak", 172_800);
    const none = stubChain(NONE);
    await expect(ensureWindow(deps(none.chain, store))).rejects.toBeInstanceOf(RelayerHalted);
    expect(none.opens).toHaveLength(0);
    const live = stubChain(windowOf());
    await expect(ensureWindow(deps(live.chain, store))).rejects.toBeInstanceOf(RelayerHalted);
    expect(live.closes()).toBe(1);
  });
});

describe("ensureWindow: any window it did not ask for is closed", () => {
  it("closes a found window of any other shape on every read, refuses, and opens nothing", async () => {
    const kinds: Partial<EvmWindow>[] = [
      { allowedTargets: [] },
      { nativeOnly: true },
      { allowedTargets: [REGISTRY_ADDRESS, OTHER] },
      { allowedTargets: [OTHER] },
      { allowedTargets: ["0xNOTANADDRESS"] },
      { maxTxs: 41n },
      { maxValue: FULL + 1n },
      { expiryHeight: 1_000n + 17_280n },
      { allowedTargets: [], live: false },
    ];
    for (const kind of kinds) {
      const { chain, opens, closes } = stubChain(windowOf(kind));
      await expect(ensureWindow(deps(chain))).rejects.toEqual(new WindowUnavailable("unexpected_window"));
      expect(closes()).toBe(1);
      expect(opens).toHaveLength(0);
    }
  });

  it("closes a window whose read-back is not the scope, size and blocks it asked for, and never pauses as if it were open", async () => {
    const kinds: ((r: WindowRequest) => EvmWindow)[] = [
      (r) => ({ ...asOpened(r), allowedTargets: [] }),
      (r) => ({ ...asOpened(r), nativeOnly: true }),
      (r) => ({ ...asOpened(r), allowedTargets: [REGISTRY_ADDRESS, OTHER] }),
      (r) => ({ ...asOpened(r), maxTxs: 39n }),
      (r) => ({ ...asOpened(r), maxValue: r.maxValue - 1n }),
      (r) => ({ ...asOpened(r), expiryHeight: 1_000n + 11_999n }),
      () => NONE,
    ];
    for (const kind of kinds) {
      const { chain, opens, closes } = stubChain(NONE, kind);
      const d = deps(chain);
      await expect(ensureWindow(d)).rejects.toEqual(new WindowUnavailable("readback_mismatch"));
      expect(opens).toHaveLength(1);
      expect(closes()).toBe(1);
      expect(d.sleep).not.toHaveBeenCalled();
    }
  });

  it("closes even when the day's ceiling is reached, and counts the close fee", async () => {
    const store = await spentAlready(DAILY_SPEND_CEILING_UQOR);
    const { chain, closes } = stubChain(windowOf({ allowedTargets: [] }));
    await expect(ensureWindow(deps(chain, store))).rejects.toBeInstanceOf(WindowUnavailable);
    expect(closes()).toBe(1);
    expect(await spentToday(store, NOW)).toBe(DAILY_SPEND_CEILING_UQOR + WINDOW_CLOSE_FEE_UQOR);
  });
});
