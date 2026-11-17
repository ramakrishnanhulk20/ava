import { sameAccount } from "@ava/core";
import { getAbiItem, type Hex, type PublicClient } from "viem";
import { boardRegistryAbi } from "./abi/boardRegistry.ts";
import type { BlobBackend } from "./blob.ts";
import { evmClient } from "./chain/evm.ts";
import { REGISTRY_ADDRESS, REGISTRY_DEPLOY_BLOCK } from "./config.ts";
import { logEvent } from "./log.ts";
import type { SharedStore } from "./store.ts";

/** The most blocks one eth_getLogs read covers. */
export const ENVELOPE_LOG_PAGE_BLOCKS = 10_000;
/**
 * One run reads at most 50 pages, 500,000 blocks (about eight days at 1.4 s a block). A run that
 * stops short of the latest block deletes nothing, because a later page may reference any blob.
 */
const MAX_LOG_PAGES = 50;
/** An envelope blob that no EnvelopeGranted event names this long after its upload is deleted. */
export const ENVELOPE_SWEEP_AGE_MS = 2 * 3_600_000;
/** The shared store gives every write a lifetime; ten years outlives the project. */
const KEEP_SECONDS = 315_360_000;
const CURSOR_KEY = "envsweep:next-block";
const LOCK = "envsweep";
/** One run, its log pages, marks, listing and deletes, ends well inside this. */
const LOCK_TTL_SECONDS = 300;
const PREFIX = "envelope/";
const HEX_NAME = /^envelope\/([0-9a-f]{64})$/;
const HASH = /^0x[0-9a-fA-F]{64}$/;
// The same bounds as the document sweep: pages of 100, at most 5,000 blobs a run, 20 lookups at a time.
const LIST_PAGE_SIZE = 100;
const LIST_MAX_PAGES = 50;
const PARALLEL = 20;
const STORE_TIMEOUT_MS = 10_000;

/** What the sweep reads from the chain. Every method throws when its read fails, so the sweep stops. */
export interface EnvelopeLogs {
  latestBlock(): Promise<bigint>;
  /** The envelopeHash of every EnvelopeGranted event REGISTRY_ADDRESS emitted from `fromBlock` to `toBlock`, both included. */
  envelopeHashes(fromBlock: bigint, toBlock: bigint): Promise<Hex[]>;
}

export interface EnvelopeSweepContext {
  blobs: BlobBackend;
  store: SharedStore;
  /** Milliseconds since the epoch, from the scheduler's clock. */
  now: number;
  logs: EnvelopeLogs;
}

export interface EnvelopeSweepOutcome {
  /** Distinct envelope hashes this run read from the logs and marked. */
  referenced: number;
  deleted: number;
  /** Whether the logs were read up to the latest block; nothing is deleted otherwise. */
  caughtUp: boolean;
}

/** The mark that an EnvelopeGranted event names this envelope, so its blob is kept. */
export const referencedKey = (hex: string): string => `referenced:${hex}`;

const ENVELOPE_GRANTED = getAbiItem({ abi: boardRegistryAbi, name: "EnvelopeGranted" });

/**
 * EnvelopeGranted logs of REGISTRY_ADDRESS, read from the public EVM JSON-RPC. Each log the node
 * returns is checked like an input: emitted by the registry, not removed, carrying a decoded hash.
 */
export function liveEnvelopeLogs(client: PublicClient = evmClient()): EnvelopeLogs {
  return {
    latestBlock: () => client.getBlockNumber(),
    envelopeHashes: async (fromBlock, toBlock) => {
      const logs = await client.getLogs({ address: REGISTRY_ADDRESS, event: ENVELOPE_GRANTED, fromBlock, toBlock, strict: false });
      return logs.map((log) => {
        const hash = log.args.envelopeHash;
        if (log.removed || !sameAccount(log.address, REGISTRY_ADDRESS) || typeof hash !== "string") throw new Error("A log is not an EnvelopeGranted event of the registry.");
        return hash;
      });
    },
  };
}

async function readCursor(store: SharedStore): Promise<bigint> {
  const raw = await store.get(CURSOR_KEY);
  if (raw === null) return 0n;
  if (!/^\d{1,16}$/.test(raw)) throw new Error("The envelope sweep cursor holds an unexpected value.");
  return BigInt(raw);
}

/** Reads the logs from the cursor to the latest block, page by page, marking every hash named. */
async function markReferenced(ctx: EnvelopeSweepContext): Promise<{ referenced: number; caughtUp: boolean }> {
  const latest = await ctx.logs.latestBlock();
  let stored = await readCursor(ctx.store);
  let next = stored > REGISTRY_DEPLOY_BLOCK ? stored : REGISTRY_DEPLOY_BLOCK;
  // A cursor past the chain's head means the chain is not the one it was read from: a testnet
  // reset, or a wrong node. Its events would never be read, so refuse rather than delete by them.
  if (next > latest + 1n) throw new Error("The envelope sweep cursor is past the latest block.");
  const seen = new Set<string>();
  for (let page = 0; page < MAX_LOG_PAGES && next <= latest; page++) {
    const last = next + BigInt(ENVELOPE_LOG_PAGE_BLOCKS) - 1n;
    const to = last < latest ? last : latest;
    const fresh: string[] = [];
    for (const hash of await ctx.logs.envelopeHashes(next, to)) {
      if (typeof hash !== "string" || !HASH.test(hash)) throw new Error("An EnvelopeGranted log carries no 32-byte envelope hash.");
      const hex = hash.slice(2).toLowerCase();
      if (!seen.has(hex)) fresh.push(hex);
      seen.add(hex);
    }
    for (let start = 0; start < fresh.length; start += PARALLEL) {
      await Promise.all(fresh.slice(start, start + PARALLEL).map((hex) => ctx.store.setIfAbsent(referencedKey(hex), to.toString(), KEEP_SECONDS)));
    }
    // A counter that only ever grows holds the cursor, so it can never move back. It moves only
    // after every mark of its page is written, so a run that fails reads that page again.
    const moved = BigInt(await ctx.store.incrWindow(CURSOR_KEY, KEEP_SECONDS, Number(to + 1n - stored)));
    if (moved !== to + 1n) throw new Error("The envelope sweep cursor moved under another writer.");
    stored = moved;
    next = to + 1n;
  }
  return { referenced: seen.size, caughtUp: next > latest };
}

/** Deletes envelope blobs older than ENVELOPE_SWEEP_AGE_MS with no "referenced:" mark. */
async function deleteUnreferenced(ctx: EnvelopeSweepContext): Promise<number> {
  let cursor: string | undefined;
  let deleted = 0;
  for (let page = 0; page < LIST_MAX_PAGES; page++) {
    const listed = await ctx.blobs.list(PREFIX, { limit: LIST_PAGE_SIZE, cursor, signal: AbortSignal.timeout(STORE_TIMEOUT_MS) });
    const old = listed.blobs.filter((blob) => blob.pathname.startsWith(PREFIX) && ctx.now - blob.uploadedAt > ENVELOPE_SWEEP_AGE_MS);
    const doomed: string[] = [];
    for (let start = 0; start < old.length; start += PARALLEL) {
      const batch = old.slice(start, start + PARALLEL);
      // A name that is not a 64-hex hash can never be referenced, so it goes too.
      const marks = await Promise.all(
        batch.map((blob) => {
          const hex = HEX_NAME.exec(blob.pathname)?.[1];
          return hex === undefined ? Promise.resolve(null) : ctx.store.get(referencedKey(hex));
        }),
      );
      batch.forEach((blob, i) => {
        if (marks[i] === null) doomed.push(blob.pathname);
      });
    }
    if (doomed.length > 0) {
      await ctx.blobs.delete(doomed, AbortSignal.timeout(STORE_TIMEOUT_MS));
      deleted += doomed.length;
      logEvent("envsweep_deleted", { count: doomed.length });
    }
    if (listed.cursor === undefined) break;
    cursor = listed.cursor;
  }
  return deleted;
}

/**
 * Keeps only the envelope blobs the registry references (threat model C28, C44). Reads the
 * EnvelopeGranted logs of REGISTRY_ADDRESS from a cursor kept in SharedStore, starting at the
 * registry's deploy block, in pages of at most 10,000 blocks, and marks each envelope hash
 * "referenced:<sha256>". Once the logs are read up to the latest block, it deletes every envelope
 * blob older than two hours with no mark. Meant for a schedule, one run at a time under the
 * "envsweep" lock.
 *
 * Covers envelopes uploaded and never used, and anything under `envelope/` not named by a hash.
 * Does not cover an envelope whose action lands more than two hours after its upload: it is
 * deleted first, so the app uploads an envelope only right before the chair signs.
 *
 * @returns How many hashes were marked and blobs deleted, and whether the logs were read to the
 *   latest block. A run that is not caught up after 50 pages deletes nothing.
 * @throws When a log read fails or returns a malformed hash, the cursor is past the latest block,
 *   the lock is held, or either store fails. Pages already marked stay marked.
 */
export async function sweepUnreferencedEnvelopes(ctx: EnvelopeSweepContext): Promise<EnvelopeSweepOutcome> {
  return ctx.store.withLock(LOCK, LOCK_TTL_SECONDS, async () => {
    const { referenced, caughtUp } = await markReferenced(ctx);
    if (!caughtUp) {
      logEvent("envsweep_behind", { referenced });
      return { referenced, deleted: 0, caughtUp };
    }
    return { referenced, deleted: await deleteUnreferenced(ctx), caughtUp };
  });
}
