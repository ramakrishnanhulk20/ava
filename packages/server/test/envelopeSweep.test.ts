// Not covered here: the live EVM JSON-RPC. The EnvelopeGranted logs come from a stub, and
// liveEnvelopeLogs is checked against a stub client, so whether eth_getLogs on the public node
// really returns every event of a 10,000-block page, and decodes cipherSize as viem does here, is
// for a live run. The blob store is MemoryBlobBackend and the shared store is MemoryStore.
// Posted-document marks and the scan point are covered in test/docupload.test.ts, next to the
// sweep that reads them.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Hex, PublicClient } from "viem";
import { MemoryBlobBackend } from "../src/blob.ts";
import { REGISTRY_ADDRESS, REGISTRY_DEPLOY_BLOCK } from "../src/config.ts";
import { ENVELOPE_LOG_PAGE_BLOCKS, liveEnvelopeLogs, referencedKey, sweepUnreferencedEnvelopes, type EnvelopeLogs } from "../src/envelopeSweep.ts";
import { MemoryStore, type SharedStore } from "../src/store.ts";
import { failingStore } from "./fixtures.ts";

const ORIGIN = "https://store123.public.blob.vercel-storage.com";
const NOW = Date.UTC(2026, 10, 19, 12, 0, 0);
const MINUTE = 60_000;
const DEPLOY = REGISTRY_DEPLOY_BLOCK;
const PAGE = BigInt(ENVELOPE_LOG_PAGE_BLOCKS);

const hexFor = (label: string): string => createHash("sha256").update(label).digest("hex");
const CURSOR_KEY = `envsweep:next-mark-block:${REGISTRY_ADDRESS.toLowerCase()}`;

/** EnvelopeGranted events at the blocks given, and a record of every range read. */
function stubLogs(events: { block: bigint; hex: string }[], latest: () => bigint) {
  const reads: [bigint, bigint][] = [];
  const logs: EnvelopeLogs = {
    latestBlock: async () => latest(),
    envelopeHashes: async (fromBlock, toBlock) => {
      reads.push([fromBlock, toBlock]);
      return events.filter((e) => e.block >= fromBlock && e.block <= toBlock).map((e) => `0x${e.hex}` as Hex);
    },
  };
  return { logs, reads };
}

function blobsAged(entries: [string, number][]): MemoryBlobBackend {
  const blobs = new MemoryBlobBackend(ORIGIN);
  for (const [pathname, ageMinutes] of entries) {
    blobs.blobs.set(pathname, new Uint8Array([1]));
    blobs.uploadedAt.set(pathname, NOW - ageMinutes * MINUTE);
  }
  return blobs;
}

/**
 * A store that, once armed, applies the next write to the cursor twice and answers with the second
 * reply: what a client retry after a lost reply does.
 */
function retryingStore(inner: MemoryStore) {
  let armed = false;
  const twice = async <T>(key: string, write: () => Promise<T>): Promise<T> => {
    if (key === CURSOR_KEY && armed) {
      armed = false;
      await write();
    }
    return write();
  };
  const store: SharedStore = {
    incrWindow: (key, windowSeconds, amount) => twice(key, () => inner.incrWindow(key, windowSeconds, amount)),
    compareAndSet: (key, expected, next, ttlSeconds) => twice(key, () => inner.compareAndSet(key, expected, next, ttlSeconds)),
    setIfAbsent: (key, value, ttlSeconds) => inner.setIfAbsent(key, value, ttlSeconds),
    get: (key) => inner.get(key),
    delete: (key) => inner.delete(key),
    withLock: (key, ttlSeconds, fn, options) => inner.withLock(key, ttlSeconds, fn, options),
  };
  return {
    store,
    retryNextCursorWrite: (): void => {
      armed = true;
    },
  };
}

function upload(blobs: MemoryBlobBackend, hex: string, at: number): void {
  blobs.blobs.set(`envelope/${hex}`, new Uint8Array([1]));
  blobs.uploadedAt.set(`envelope/${hex}`, at);
}

beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("sweepUnreferencedEnvelopes", () => {
  it("starts at the block the registry was deployed in, as recorded at deploy", () => {
    const deployed = JSON.parse(readFileSync(new URL("../../contracts/deployments/testnet.json", import.meta.url), "utf8")) as { BoardRegistry: { blockNumber: string } };
    expect(REGISTRY_DEPLOY_BLOCK).toBe(BigInt(deployed.BoardRegistry.blockNumber));
  });

  it("marks every envelope the registry's logs name, in 10,000-block pages from its cursor, and deletes only envelopes over two hours old with no mark", async () => {
    const [early, late, orphan, young] = ["early", "late", "orphan", "young"].map(hexFor) as [string, string, string, string];
    const store = new MemoryStore({ now: () => NOW });
    const blobs = blobsAged([
      [`envelope/${early}`, 600],
      [`envelope/${late}`, 180],
      [`envelope/${orphan}`, 121],
      [`envelope/${young}`, 119],
      ["envelope/not-a-hash", 600],
      [`document/${orphan}`, 600],
    ]);
    let latest = DEPLOY + 25_000n;
    const { logs, reads } = stubLogs(
      [
        { block: DEPLOY + 5n, hex: early },
        { block: DEPLOY + 15_000n, hex: late },
      ],
      () => latest,
    );

    expect(await sweepUnreferencedEnvelopes({ blobs, store, now: NOW, logs })).toEqual({ referenced: 2, deleted: 2, caughtUp: true });
    expect(reads).toEqual([
      [DEPLOY, DEPLOY + PAGE - 1n],
      [DEPLOY + PAGE, DEPLOY + 2n * PAGE - 1n],
      [DEPLOY + 2n * PAGE, DEPLOY + 25_000n],
    ]);
    expect([...blobs.blobs.keys()].sort()).toEqual([`document/${orphan}`, `envelope/${early}`, `envelope/${late}`, `envelope/${young}`].sort());
    expect(await store.get(referencedKey(late))).not.toBeNull();

    latest += 5n;
    reads.length = 0;
    expect(await sweepUnreferencedEnvelopes({ blobs, store, now: NOW, logs })).toEqual({ referenced: 0, deleted: 0, caughtUp: true });
    expect(reads).toEqual([[DEPLOY + 25_001n, DEPLOY + 25_005n]]);
  });

  it("deletes nothing when a log read fails, a log is malformed, one run cannot reach the latest block, or the store is down", async () => {
    const orphan = `envelope/${hexFor("orphan")}`;
    const store = new MemoryStore({ now: () => NOW });
    const blobs = blobsAged([[orphan, 600]]);

    let calls = 0;
    const broken: EnvelopeLogs = {
      latestBlock: async () => DEPLOY + 25_000n,
      envelopeHashes: async () => {
        calls += 1;
        if (calls === 2) throw new Error("the node is down");
        return [];
      },
    };
    await expect(sweepUnreferencedEnvelopes({ blobs, store, now: NOW, logs: broken })).rejects.toThrow();
    const malformed: EnvelopeLogs = { latestBlock: async () => DEPLOY + 25_000n, envelopeHashes: async () => ["0x1234"] };
    await expect(sweepUnreferencedEnvelopes({ blobs, store, now: NOW, logs: malformed })).rejects.toThrow();
    expect(blobs.blobs.has(orphan)).toBe(true);

    // The failed run kept the page it finished, so the next run starts after it.
    const far = stubLogs([], () => DEPLOY + 1_000n * PAGE);
    expect(await sweepUnreferencedEnvelopes({ blobs, store, now: NOW, logs: far.logs })).toMatchObject({ deleted: 0, caughtUp: false });
    expect(far.reads[0]).toEqual([DEPLOY + PAGE, DEPLOY + 2n * PAGE - 1n]);
    expect(blobs.blobs.has(orphan)).toBe(true);

    await expect(sweepUnreferencedEnvelopes({ blobs, store: failingStore(), now: NOW, logs: far.logs })).rejects.toThrow();
    expect(blobs.blobs.has(orphan)).toBe(true);
  });

  it("never moves the cursor past an unread block when a run outlives its lock and another overlaps it", async () => {
    let clock = NOW;
    const store = new MemoryStore({ now: () => clock });
    const blobs = new MemoryBlobBackend(ORIGIN, { now: () => clock });
    const events: { block: bigint; hex: string }[] = [];
    let latest = DEPLOY + 25_000n;
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => (release = resolve));
    let holding = false;
    const logs = (slow: boolean): EnvelopeLogs => ({
      latestBlock: async () => latest,
      envelopeHashes: async (fromBlock, toBlock) => {
        if (slow) {
          holding = true;
          await held;
        }
        return events.filter((e) => e.block >= fromBlock && e.block <= toBlock).map((e) => `0x${e.hex}` as Hex);
      },
    });
    const run = (slow = false) => sweepUnreferencedEnvelopes({ blobs, store, now: clock, logs: logs(slow) });

    await run();
    latest = DEPLOY + 40_000n;
    const first = run(true).catch((error: unknown) => error);
    while (!holding) await new Promise((resolve) => setTimeout(resolve, 5));
    clock += 301_000;
    expect(await run()).toMatchObject({ caughtUp: true });
    release();
    await first;
    expect(await store.get(CURSOR_KEY)).toBe(String(DEPLOY + 40_001n));

    const granted = hexFor("rotation envelope sealed to every member");
    upload(blobs, granted, clock);
    latest = DEPLOY + 45_000n;
    events.push({ block: DEPLOY + 45_000n, hex: granted });
    expect(await run()).toEqual({ referenced: 1, deleted: 0, caughtUp: true });
    latest = DEPLOY + 52_000n;
    clock += 2 * 3_600_000 + 60_000;
    expect(await run()).toMatchObject({ caughtUp: true });
    expect(blobs.blobs.has(`envelope/${granted}`)).toBe(true);
    expect(await store.get(referencedKey(granted))).not.toBeNull();
  });

  it("counts a cursor write the store applied twice, after a client retry, as one move", async () => {
    let clock = NOW;
    const inner = new MemoryStore({ now: () => clock });
    const { store, retryNextCursorWrite } = retryingStore(inner);
    const blobs = new MemoryBlobBackend(ORIGIN);
    const events: { block: bigint; hex: string }[] = [];
    let latest = DEPLOY + 25_000n;
    const { logs } = stubLogs(events, () => latest);
    const run = () => sweepUnreferencedEnvelopes({ blobs, store, now: clock, logs });

    await run();
    latest = DEPLOY + 32_000n;
    retryNextCursorWrite();
    expect(await run()).toEqual({ referenced: 0, deleted: 0, caughtUp: true });
    expect(await inner.get(CURSOR_KEY)).toBe(String(DEPLOY + 32_001n));

    const granted = hexFor("add-member envelope");
    upload(blobs, granted, clock);
    events.push({ block: DEPLOY + 33_000n, hex: granted });
    latest = DEPLOY + 40_000n;
    clock += 2 * 3_600_000 + 60_000;
    expect(await run()).toEqual({ referenced: 1, deleted: 0, caughtUp: true });
    expect(blobs.blobs.has(`envelope/${granted}`)).toBe(true);
  });

  it("starts from the deploy block when no cursor is stored, even when that first write is applied twice", async () => {
    const [granted, orphan] = ["first grant", "never granted"].map(hexFor) as [string, string];
    const inner = new MemoryStore({ now: () => NOW });
    const { store, retryNextCursorWrite } = retryingStore(inner);
    const blobs = new MemoryBlobBackend(ORIGIN);
    upload(blobs, granted, NOW - 3 * 3_600_000);
    upload(blobs, orphan, NOW - 3 * 3_600_000);
    const { logs, reads } = stubLogs([{ block: DEPLOY + 5n, hex: granted }], () => DEPLOY + 15_000n);

    expect(await inner.get(CURSOR_KEY)).toBeNull();
    retryNextCursorWrite();
    expect(await sweepUnreferencedEnvelopes({ blobs, store, now: NOW, logs })).toEqual({ referenced: 1, deleted: 1, caughtUp: true });
    expect(reads).toEqual([
      [DEPLOY, DEPLOY + PAGE - 1n],
      [DEPLOY + PAGE, DEPLOY + 15_000n],
    ]);
    expect(await inner.get(CURSOR_KEY)).toBe(String(DEPLOY + 15_001n));
    expect(blobs.blobs.has(`envelope/${granted}`)).toBe(true);
    expect(blobs.blobs.has(`envelope/${orphan}`)).toBe(false);
  });

  it("starts no log page once 240 s of its 300 s lock are used, and deletes nothing in that run", async () => {
    const orphan = hexFor("orphan");
    const store = new MemoryStore({ now: () => NOW });
    const blobs = new MemoryBlobBackend(ORIGIN);
    upload(blobs, orphan, NOW - 3 * 3_600_000);
    const { logs, reads } = stubLogs([], () => DEPLOY + 5n * PAGE);
    let elapsed = 0;
    const slow: EnvelopeLogs = {
      latestBlock: logs.latestBlock,
      envelopeHashes: async (fromBlock, toBlock) => {
        elapsed += 100_000;
        return logs.envelopeHashes(fromBlock, toBlock);
      },
    };

    expect(await sweepUnreferencedEnvelopes({ blobs, store, now: NOW, logs: slow, clock: () => elapsed })).toEqual({ referenced: 0, deleted: 0, caughtUp: false });
    expect(reads).toHaveLength(3);
    expect(blobs.blobs.has(`envelope/${orphan}`)).toBe(true);

    reads.length = 0;
    expect(await sweepUnreferencedEnvelopes({ blobs, store, now: NOW, logs, clock: () => 0 })).toEqual({ referenced: 0, deleted: 1, caughtUp: true });
    expect(reads[0]).toEqual([DEPLOY + 3n * PAGE, DEPLOY + 4n * PAGE - 1n]);
  });
});

describe("liveEnvelopeLogs", () => {
  it("reads the cipherHash and cipherSize of each DocumentPosted log of the registry, and refuses a log that is not one", async () => {
    const cipherHash = `0x${hexFor("posted document")}` as Hex;
    const good = { address: REGISTRY_ADDRESS, removed: false, args: { cipherHash, cipherSize: 1_000n } };
    let answer: unknown[] = [good];
    const getLogs = vi.fn(async () => answer);
    const logs = liveEnvelopeLogs({ getLogs } as unknown as PublicClient);
    expect(await logs.documentPosts?.(DEPLOY, DEPLOY + 9n)).toEqual([{ cipherHash, cipherSize: 1_000n }]);
    expect(getLogs).toHaveBeenCalledWith(expect.objectContaining({ address: REGISTRY_ADDRESS, event: expect.objectContaining({ name: "DocumentPosted" }), fromBlock: DEPLOY, toBlock: DEPLOY + 9n }));

    const lies = [
      { ...good, args: { cipherHash } },
      { ...good, args: { cipherSize: 1_000n } },
      { ...good, args: { cipherHash, cipherSize: 1_000 } },
      { ...good, removed: true },
      { ...good, address: "0x000000000000000000000000000000000000dEaD" },
    ];
    for (const log of lies) {
      answer = [good, log];
      await expect(logs.documentPosts?.(DEPLOY, DEPLOY + 9n)).rejects.toThrow("DocumentPosted");
    }
  });
});
