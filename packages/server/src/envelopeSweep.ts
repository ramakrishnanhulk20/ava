import { MAX_CIPHER_SIZE, sameAccount } from "@ava/core";
import { getAbiItem, type Hex, type PublicClient } from "viem";
import { boardRegistryAbi } from "./abi/boardRegistry.ts";
import type { BlobBackend } from "./blob.ts";
import { evmClient } from "./chain/evm.ts";
import { REGISTRY_ADDRESS, REGISTRY_DEPLOY_BLOCK } from "./config.ts";
import { parsePostedScan, POSTED_SCAN_KEY, postedKey, postedMarkWith, SCANNED_REGISTRY } from "./docupload.ts";
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
// Named for the registry, as POSTED_SCAN_KEY is: a cursor read for another registry would skip
// this one's events up to it. Renamed with the marks ("envsweep:next-block:" before), so the first
// run under these names reads from the deploy block and rebuilds every mark before it deletes.
const CURSOR_KEY = `envsweep:next-mark-block:${SCANNED_REGISTRY}`;
const LOCK = "envsweep";
/** One run, its log pages, marks, listing and deletes, ends well inside this. */
const LOCK_TTL_SECONDS = 300;
/**
 * A run starts no new page, of logs or of deletes, once it has held its lock this long. The 60 s
 * left cover the page already started (one log read and its marks, or one listing and its deletes).
 */
const RUN_BUDGET_MS = (LOCK_TTL_SECONDS - 60) * 1000;
const PREFIX = "envelope/";
const HEX_NAME = /^envelope\/([0-9a-f]{64})$/;
const HASH = /^0x[0-9a-fA-F]{64}$/;
// The same bounds as the document sweep: pages of 100, at most 5,000 blobs a run, 20 lookups at a time.
const LIST_PAGE_SIZE = 100;
const LIST_MAX_PAGES = 50;
const PARALLEL = 20;
const STORE_TIMEOUT_MS = 10_000;
/** Tries at adding sizes to one posted mark before the run stops: each failed try means another writer moved it. */
const MARK_ATTEMPTS = 3;

/** One DocumentPosted event: the cipherHash and cipherSize its poster signed. */
export interface DocumentPost {
  cipherHash: Hex;
  cipherSize: bigint;
}

/** What the sweep reads from the chain. Every method throws when its read fails, so the sweep stops. */
export interface EnvelopeLogs {
  latestBlock(): Promise<bigint>;
  /** The envelopeHash of every EnvelopeGranted event REGISTRY_ADDRESS emitted from `fromBlock` to `toBlock`, both included. */
  envelopeHashes(fromBlock: bigint, toBlock: bigint): Promise<Hex[]>;
  /**
   * The cipherHash and cipherSize of every DocumentPosted event REGISTRY_ADDRESS emitted from
   * `fromBlock` to `toBlock`, both included. Logs without this or blockTime mark no document and
   * never move the posted-document scan point, so the document sweep deletes no document by them.
   */
  documentPosts?(fromBlock: bigint, toBlock: bigint): Promise<DocumentPost[]>;
  /** The timestamp of `block`, in milliseconds since the epoch. */
  blockTime?(block: bigint): Promise<number>;
}

export interface EnvelopeSweepContext {
  blobs: BlobBackend;
  store: SharedStore;
  /** Milliseconds since the epoch, from the scheduler's clock. */
  now: number;
  logs: EnvelopeLogs;
  /**
   * A running clock in milliseconds, read only to measure how long this run has held its lock. The
   * process's monotonic clock by default.
   */
  clock?: () => number;
}

export interface EnvelopeSweepOutcome {
  /** Distinct envelope hashes this run read from the logs and marked. */
  referenced: number;
  deleted: number;
  /** Whether the logs were read up to the latest block; nothing is deleted otherwise. */
  caughtUp: boolean;
}

/**
 * The mark that an EnvelopeGranted event of REGISTRY_ADDRESS names this envelope, so its blob is
 * kept. Named for the registry (SCANNED_REGISTRY), so a mark another registry's scan left keeps nothing.
 */
export const referencedKey = (hex: string): string => `referenced:${SCANNED_REGISTRY}:${hex}`;

const ENVELOPE_GRANTED = getAbiItem({ abi: boardRegistryAbi, name: "EnvelopeGranted" });
const DOCUMENT_POSTED = getAbiItem({ abi: boardRegistryAbi, name: "DocumentPosted" });

/**
 * EnvelopeGranted and DocumentPosted logs of REGISTRY_ADDRESS and block timestamps, read from the
 * public EVM JSON-RPC. Each log the node returns is checked like an input: emitted by the registry,
 * not removed, carrying a decoded hash and, for DocumentPosted, a decoded cipherSize; each block
 * must be the one asked for. sweepUnreferencedEnvelopes checks the hash and size values themselves.
 * @throws From documentPosts, for a log that is not a DocumentPosted event of the registry.
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
    documentPosts: async (fromBlock, toBlock) => {
      const logs = await client.getLogs({ address: REGISTRY_ADDRESS, event: DOCUMENT_POSTED, fromBlock, toBlock, strict: false });
      return logs.map((log) => {
        const { cipherHash, cipherSize } = log.args;
        if (log.removed || !sameAccount(log.address, REGISTRY_ADDRESS) || typeof cipherHash !== "string" || typeof cipherSize !== "bigint") {
          throw new Error("A log is not a DocumentPosted event of the registry.");
        }
        return { cipherHash, cipherSize };
      });
    },
    blockTime: async (block) => {
      const found = await client.getBlock({ blockNumber: block });
      if (found.number !== block) throw new Error("The node answered with another block.");
      return Number(found.timestamp) * 1000;
    },
  };
}

/** Both DocumentPosted reads, or undefined when these logs lack either. */
function documentLogs(logs: EnvelopeLogs): { posts: (fromBlock: bigint, toBlock: bigint) => Promise<DocumentPost[]>; time: (block: bigint) => Promise<number> } | undefined {
  const { documentPosts, blockTime } = logs;
  if (documentPosts === undefined || blockTime === undefined) return undefined;
  return { posts: documentPosts.bind(logs), time: blockTime.bind(logs) };
}

/** The hashes as 64 lowercase hex characters each. @throws Error for anything that is not a 32-byte hash. */
function hexesOf(hashes: readonly unknown[], event: string): string[] {
  return hashes.map((hash) => {
    if (typeof hash !== "string" || !HASH.test(hash)) throw new Error(`A ${event} log carries no 32-byte hash.`);
    return hash.slice(2).toLowerCase();
  });
}

/**
 * Each post's hash as 64 lowercase hex characters, with its size.
 * @throws Error for a hash that is not 32 bytes, or a size the registry never records (it accepts
 *   1 byte to MAX_CIPHER_SIZE only), so a node that answers with anything else stops the run.
 */
function postsOf(posts: readonly DocumentPost[]): { hex: string; size: bigint }[] {
  const hexes = hexesOf(posts.map((post) => post?.cipherHash), "DocumentPosted");
  return posts.map((post, i) => {
    const size = post.cipherSize;
    if (typeof size !== "bigint" || size < 1n || size > BigInt(MAX_CIPHER_SIZE)) throw new Error("A DocumentPosted log carries no cipherSize the registry records.");
    return { hex: hexes[i] ?? "", size };
  });
}

/**
 * Adds `sizes` to the posted mark of `hex` by compare-and-set from the value just read, so runs
 * that overlap both land their sizes and neither erases the other's. A write the store applied but
 * reported as failed already holds the sizes when read again, and leaves nothing to do.
 * @throws When the mark moved under other writers on every try.
 */
async function markPosted(store: SharedStore, hex: string, block: bigint, sizes: readonly bigint[]): Promise<void> {
  const key = postedKey(hex);
  for (let attempt = 0; attempt < MARK_ATTEMPTS; attempt++) {
    const held = await store.get(key);
    const next = postedMarkWith(held, block, sizes);
    if (next === undefined || (await store.compareAndSet(key, held, next, KEEP_SECONDS))) return;
  }
  throw new Error(`The posted mark of ${hex} kept moving under other writers.`);
}

/** The cursor exactly as stored (null when absent), and the block it names. */
async function readCursor(store: SharedStore): Promise<{ raw: string | null; block: bigint }> {
  const raw = await store.get(CURSOR_KEY);
  if (raw === null) return { raw, block: 0n };
  if (!/^\d{1,16}$/.test(raw)) throw new Error("The envelope sweep cursor holds an unexpected value.");
  return { raw, block: BigInt(raw) };
}

/**
 * Moves `key` from the exact value this run read to `to`, so neither the cursor nor the scan point
 * can pass a block no run has read, whoever else writes. When the store says no, the key is read
 * again: a write retried after a lost reply has already left exactly `to`; anything else means
 * another writer, and the run stops.
 */
async function moveFrom(store: SharedStore, key: string, from: string | null, to: string): Promise<string> {
  if (!(await store.compareAndSet(key, from, to, KEEP_SECONDS)) && (await store.get(key)) !== to) {
    throw new Error(`The envelope sweep's ${key} moved under another writer.`);
  }
  return to;
}

/**
 * Reads the logs from the cursor to the latest block, page by page, marking every envelope hash
 * named and, when the logs offer them, every document hash posted, and moving the posted-document
 * scan point after each page.
 */
async function markReferenced(ctx: EnvelopeSweepContext, outOfTime: () => boolean): Promise<{ referenced: number; caughtUp: boolean }> {
  const latest = await ctx.logs.latestBlock();
  const cursor = await readCursor(ctx.store);
  const docs = documentLogs(ctx.logs);
  let read = cursor.raw;
  let scanRead = docs === undefined ? null : await ctx.store.get(POSTED_SCAN_KEY);
  let next = cursor.block > REGISTRY_DEPLOY_BLOCK ? cursor.block : REGISTRY_DEPLOY_BLOCK;
  if (docs !== undefined) {
    // Posted marks cover the blocks up to the scan point and no further, so a cursor that a run
    // without DocumentPosted logs moved past it (or a wiped store) is read again from there.
    const scanned = parsePostedScan(scanRead);
    const resume = scanned === undefined ? REGISTRY_DEPLOY_BLOCK : scanned.block + 1n;
    if (resume < next) next = resume > REGISTRY_DEPLOY_BLOCK ? resume : REGISTRY_DEPLOY_BLOCK;
  }
  // A cursor past the chain's head means the chain is not the one it was read from: a testnet
  // reset, or a wrong node. Its events would never be read, so refuse rather than delete by them.
  if (next > latest + 1n) throw new Error("The envelope sweep cursor is past the latest block.");
  const seen = new Set<string>();
  // Each hash and size this run has marked, as `<hex>:<size>`, so a repeat costs no store call.
  const posted = new Set<string>();
  for (let page = 0; page < MAX_LOG_PAGES && next <= latest; page++) {
    if (outOfTime()) {
      logEvent("envsweep_out_of_time", { phase: "logs", page });
      break;
    }
    const last = next + BigInt(ENVELOPE_LOG_PAGE_BLOCKS) - 1n;
    const to = last < latest ? last : latest;
    const marks: string[] = [];
    for (const hex of hexesOf(await ctx.logs.envelopeHashes(next, to), "EnvelopeGranted")) {
      if (!seen.has(hex)) marks.push(referencedKey(hex));
      seen.add(hex);
    }
    const sizes = new Map<string, bigint[]>();
    for (const { hex, size } of docs === undefined ? [] : postsOf(await docs.posts(next, to))) {
      const pair = `${hex}:${size}`;
      if (posted.has(pair)) continue;
      posted.add(pair);
      sizes.set(hex, [...(sizes.get(hex) ?? []), size]);
    }
    for (let start = 0; start < marks.length; start += PARALLEL) {
      await Promise.all(marks.slice(start, start + PARALLEL).map((key) => ctx.store.setIfAbsent(key, to.toString(), KEEP_SECONDS)));
    }
    const named = [...sizes];
    for (let start = 0; start < named.length; start += PARALLEL) {
      await Promise.all(named.slice(start, start + PARALLEL).map(([hex, stated]) => markPosted(ctx.store, hex, to, stated)));
    }
    // Both move only after every mark of the page is written, so a run that fails reads that page
    // again. The scan point's time is never later than this run's start, whatever the node says.
    read = await moveFrom(ctx.store, CURSOR_KEY, read, (to + 1n).toString());
    if (docs !== undefined) {
      const time = Math.min(await docs.time(to), ctx.now);
      if (!Number.isSafeInteger(time) || time < 0) throw new Error("A block carries no usable timestamp.");
      scanRead = await moveFrom(ctx.store, POSTED_SCAN_KEY, scanRead, `${to}:${time}`);
    }
    next = to + 1n;
  }
  return { referenced: seen.size, caughtUp: next > latest };
}

/** Deletes envelope blobs older than ENVELOPE_SWEEP_AGE_MS with no referenced mark of this registry (referencedKey). */
async function deleteUnreferenced(ctx: EnvelopeSweepContext, outOfTime: () => boolean): Promise<number> {
  let cursor: string | undefined;
  let deleted = 0;
  for (let page = 0; page < LIST_MAX_PAGES; page++) {
    // What is left waits for the next run: only the deletes stop, never the marks they depend on.
    if (outOfTime()) {
      logEvent("envsweep_out_of_time", { phase: "delete", page });
      break;
    }
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
 * Keeps only the envelope blobs the registry references, and marks the documents it posts (threat
 * model C28, C31, C44). Reads the EnvelopeGranted logs of REGISTRY_ADDRESS from a cursor kept in
 * SharedStore under a key named for that registry, as the scan point's is, so a cursor left by a
 * scan of another registry is never resumed. It starts at the registry's deploy block, reads pages
 * of at most 10,000 blocks, and marks each envelope hash "referenced:<registry>:<sha256>". When the
 * logs offer DocumentPosted reads, it also marks each cipherHash "posted:<registry>:<sha256>" (both
 * named for REGISTRY_ADDRESS, so a mark another registry's scan left keeps nothing) with the page's last block
 * and every cipherSize posted for it (postedMarkWith in docupload.ts, by compare-and-set), and,
 * after each page, moves the scan point that sweepUnverified deletes by to that page's last block
 * and its time. Once the logs are read up to the latest block, it deletes every envelope blob older
 * than two hours with no mark. Meant for a schedule, one run at a time under the "envsweep" lock.
 *
 * The cursor and the scan point move only by compare-and-set from the value this run read, never
 * by an increment, so overlapping runs or a write the store applied twice can never move either
 * past a block no run read. A run starts from the scan point when the cursor is ahead of it, so
 * posted marks always cover every block from the deploy block up to the scan point. A run starts
 * no new page, of logs or of deletes, once it has held its 300 s lock for 240 s.
 *
 * Covers envelopes uploaded and never used, and anything under `envelope/` not named by a hash.
 * Does not cover an envelope whose action lands more than two hours after its upload: it is
 * deleted first, so the app uploads an envelope only right before the chair signs.
 *
 * @returns How many envelope hashes were marked and blobs deleted, and whether the logs were read
 *   to the latest block. A run that is not caught up (after 50 pages, or out of time) deletes
 *   nothing.
 * @throws When a log read fails or returns a malformed hash or block time, the cursor is past the
 *   latest block, the cursor or scan point moved under another writer, the lock is held, or either
 *   store fails. Pages already marked stay marked.
 */
export async function sweepUnreferencedEnvelopes(ctx: EnvelopeSweepContext): Promise<EnvelopeSweepOutcome> {
  return ctx.store.withLock(LOCK, LOCK_TTL_SECONDS, async () => {
    const clock = ctx.clock ?? (() => performance.now());
    const started = clock();
    const outOfTime = (): boolean => clock() - started >= RUN_BUDGET_MS;
    const { referenced, caughtUp } = await markReferenced(ctx, outOfTime);
    if (!caughtUp) {
      logEvent("envsweep_behind", { referenced });
      return { referenced, deleted: 0, caughtUp };
    }
    return { referenced, deleted: await deleteUnreferenced(ctx, outOfTime), caughtUp };
  });
}
