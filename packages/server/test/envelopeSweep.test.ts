// Not covered here: the live EVM JSON-RPC. The EnvelopeGranted logs come from a stub, so whether
// eth_getLogs on the public node really returns every event of a 10,000-block page is for a live run.
// The blob store is MemoryBlobBackend and the shared store is MemoryStore.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Hex } from "viem";
import { MemoryBlobBackend } from "../src/blob.ts";
import { REGISTRY_DEPLOY_BLOCK } from "../src/config.ts";
import { ENVELOPE_LOG_PAGE_BLOCKS, referencedKey, sweepUnreferencedEnvelopes, type EnvelopeLogs } from "../src/envelopeSweep.ts";
import { MemoryStore } from "../src/store.ts";
import { failingStore } from "./fixtures.ts";

const ORIGIN = "https://store123.public.blob.vercel-storage.com";
const NOW = Date.UTC(2026, 10, 19, 12, 0, 0);
const MINUTE = 60_000;
const DEPLOY = REGISTRY_DEPLOY_BLOCK;
const PAGE = BigInt(ENVELOPE_LOG_PAGE_BLOCKS);

const hexFor = (label: string): string => createHash("sha256").update(label).digest("hex");

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
});
