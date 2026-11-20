import { randomUUID } from "node:crypto";
import { MAX_CIPHER_SIZE, sameHash, sha256 } from "@ava/core";
import { generateClientTokenFromReadWriteToken, type GenerateClientTokenOptions } from "@vercel/blob/client";
import { z } from "zod";
import { sameUrl, secondsToUtcMidnight, type BlobBackend, type BlobInfo, type BlobPage } from "./blob.ts";
import { DOC_BYTES_PER_CLIENT_DAY, DOC_BYTES_PER_NET48_DAY, DOC_BYTES_TOTAL_DAY, REGISTRY_ADDRESS } from "./config.ts";
import { isHttpsOrigin, type ServerEnv } from "./env.ts";
import { BodyTimeout, declaredLength, json, readBody, refuse, refuseCrossSite, TooLarge, type HandlerContext } from "./http.ts";
import { logEvent } from "./log.ts";
import { clientKey, limit, spendBudget } from "./ratelimit.ts";
import { LockBusy, addOnce, claimOnce, type SharedStore } from "./store.ts";

// Board packs go from the browser straight to the blob store, because the hosting layer refuses
// request bodies above about 4.5 MB. The server never sees those bytes on the way in, so it names
// the upload in advance, lets exactly that name be written, then reads the stored bytes back and
// keeps them only if their SHA-256 is the name (threat model C28).

const PREFIX = "document/";

/** The largest document the registry records: 25 MiB. */
export const DOCUMENT_CAP = MAX_CIPHER_SIZE;
/** The only type a document may be stored as, so the store has no reason to serve it as anything that runs (C29). */
export const DOCUMENT_CONTENT_TYPE = "application/octet-stream";
/** An upload token lasts ten minutes: room for 25 MiB at about 0.4 Mbit/s. */
export const DOCUMENT_TOKEN_SECONDS = 600;
/**
 * @deprecated Nothing is written under "pending:" any more: nothing ever read the record. Kept only
 * so existing imports still compile.
 */
export const PENDING_SECONDS = 3600;
/**
 * The shared store gives every write a lifetime, so a "verified:" mark is written for ten years,
 * which outlives the project.
 */
export const VERIFIED_SECONDS = 315_360_000;
/** The whole verify (look up, read up to 25 MiB, hash) must finish within this. */
export const VERIFY_TIMEOUT_MS = 30_000;
/**
 * An unverified document older than this can no longer be verified: verify refuses it and leaves
 * it to the sweep. The gap to DOCUMENT_KEEP_MS is far longer than a verify can take, so the sweep
 * never deletes a blob a verify is about to approve.
 */
export const VERIFY_WINDOW_MS = 50 * 60_000;
/** Anything under `document/` not named by a 64-hex hash can never be posted, and is deleted once older than this. */
export const SWEEP_AGE_MS = 60 * 60_000;
/**
 * A document no registry DocumentPosted event names this long after its upload is deleted, verified
 * or not (threat model C28, C44). The app posts a document right after verifying it.
 */
export const DOCUMENT_KEEP_MS = 2 * 3_600_000;

/**
 * The registry every key the log scan writes is named for: its posted and referenced marks, its
 * cursor and its scan point (threat model C28, C44). A mark left by a scan of another registry then
 * keeps nothing here, and every keep decision is one this registry's logs made.
 */
export const SCANNED_REGISTRY = REGISTRY_ADDRESS.toLowerCase();

/** The mark that a DocumentPosted event of REGISTRY_ADDRESS names this document. The registry log scan (envelopeSweep.ts) writes it. */
export const postedKey = (hex: string): string => `posted:${SCANNED_REGISTRY}:${hex}`;
/**
 * The most distinct cipherSizes one posted mark records. Every honest post of a ciphertext states
 * its one true length, so a second size already means a poster lied. Past four the mark records
 * no sizes at all, so posts that lie can neither grow the mark nor get the honest copy deleted.
 */
export const POSTED_SIZES_MAX = 4;
/**
 * How far the registry log scan has marked DocumentPosted events, as `<block>:<ms>`: the last block
 * read and its timestamp. Every DocumentPosted at or before that block has its posted mark. The key
 * names REGISTRY_ADDRESS, so a scan point read for another registry is never taken as this one's:
 * it would cover blocks no scan of this registry read, and the sweep would delete their documents.
 * It took a new name when the marks did ("docsweep:scanned-through:" before), because the point an
 * older scan left covers marks written under the old names: a scan starts again from the deploy
 * block and rebuilds them, and until it passes a document's upload by two hours that document is kept.
 */
export const POSTED_SCAN_KEY = `docsweep:marked-through:${SCANNED_REGISTRY}`;

/**
 * The scan point a POSTED_SCAN_KEY value holds, or undefined when the store holds none.
 * @throws Error for any other value, so a damaged point never lets the sweep delete.
 */
export function parsePostedScan(raw: string | null): { block: bigint; time: number } | undefined {
  if (raw === null) return undefined;
  const parts = /^(\d{1,16}):(\d{1,16})$/.exec(raw);
  const time = Number(parts?.[2]);
  if (parts === null || !Number.isSafeInteger(time)) throw new Error("The posted-document scan point holds an unexpected value.");
  return { block: BigInt(parts[1] ?? ""), time };
}
/**
 * Per hour: token requests per IP and in total, plus the tokens one IP may be issued. Each token
 * can place up to 25 MiB, so 12 tokens bound one IP to 300 MiB an hour, all of it deleted by
 * verify or the sweep unless it hashes to its name. The total is 50 times the per-IP limit, so
 * only an attacker with 50 or more addresses can reach it (docs/security/runbook.md, Known limits).
 */
export const DOCUMENT_TOKEN_LIMITS = { perIp: 30, total: 1_500, windowSeconds: 3600, tokensPerIp: 12 } as const;
/**
 * Per hour: verify requests per IP and in total. Each one may read up to 25 MiB from the store,
 * but only a blob that is there and not yet verified. The total is 50 times the per-IP limit.
 */
export const DOCUMENT_VERIFY_LIMITS = { perIp: 30, total: 1_500, windowSeconds: 3600 } as const;

/**
 * The most bytes one sweep run reads back to hash posted documents that were never verified:
 * 200 MiB, eight full-size documents. At 2 MiB/s, a slow read from the store, 200 MiB takes 100 s
 * of the run's 240 s budget and leaves the rest for listing, mark lookups and deletes; a store
 * slower than that is cut off by the budget itself. Reads go one at a time, so a run holds at most
 * one 25 MiB document in memory.
 */
export const SWEEP_HASH_BYTES = 8 * DOCUMENT_CAP;

const SWEEP_LOCK = "docsweep:lock";
/** One run, its listing, lookups, hashing reads and deletes, ends well inside this. */
const SWEEP_LOCK_TTL_SECONDS = 300;
/**
 * A run starts no new page and no new hashing read once it has held its lock this long. The 60 s
 * left cover what is already started: one listing and one delete (10 s each) and one read (30 s).
 */
const SWEEP_RUN_BUDGET_MS = (SWEEP_LOCK_TTL_SECONDS - 60) * 1000;
const BODY_CAP = 256;
const STORE_TIMEOUT_MS = 10_000;
// A listing page and a delete batch of 100 stay well inside the store's request limits. Fifty pages
// bound one sweep to 5,000 documents; each page costs at most 100 posted and 100 verified mark
// lookups, 20 at a time, the hashing reads SWEEP_HASH_BYTES leaves room for, and one delete.
const SWEEP_PAGE_SIZE = 100;
const SWEEP_MAX_PAGES = 50;
const SWEEP_PARALLEL = 20;
/** Where the next run's listing starts: "start", or "after:" and the blob store's own cursor. */
const LISTING_CURSOR_KEY = "docsweep:cursor";
/**
 * Every run rewrites the cursor after each page, so it lapses only when no run has written it for a
 * day: the sweep stopped, or the blob store no longer takes it back. The next run then starts from
 * the first page, which is always safe: the cursor decides only where a run looks, never what it
 * deletes.
 */
const LISTING_CURSOR_SECONDS = 86_400;
const LISTING_START = "start";
// The store's cursor is opaque, so only its length is bounded; it goes back to the store untouched.
const LISTING_AFTER = /^after:([\s\S]{1,4096})$/;

const HEX = /^[0-9a-f]{64}$/;
const HashBody = z.strictObject({ sha256: z.string().regex(HEX) });
/** A token request: the document's name, and the exact size in bytes the token will let be written. */
const TokenBody = z.strictObject({ sha256: z.string().regex(HEX), size: z.number().int().min(1).max(DOCUMENT_CAP) });
/** A UTC day's document byte budgets live two days, so a request near midnight never finds its day's count gone. */
const DOC_BYTES_KEY_SECONDS = 2 * 86_400;
const HEX_NAME = /^document\/([0-9a-f]{64})$/;
// A legacy mark is the block alone; a mark with sizes adds them, ascending and without repeats.
const POSTED_MARK = /^(\d{1,16})(?::([0-9,]{1,80}))?$/;

export interface DocumentContext extends HandlerContext {
  blobs: BlobBackend;
  env: Pick<ServerEnv, "BLOB_ORIGIN" | "BLOB_READ_WRITE_TOKEN">;
  /** Replaces generateClientTokenFromReadWriteToken, so tests can see the exact options it is given. */
  buildToken?: (options: GenerateClientTokenOptions) => Promise<string>;
  /** Overrides DOCUMENT_TOKEN_LIMITS. */
  tokenLimits?: { perIp: number; total: number; windowSeconds: number; tokensPerIp: number };
  /** Overrides DOCUMENT_VERIFY_LIMITS. */
  verifyLimits?: { perIp: number; total: number; windowSeconds: number };
  /** Overrides VERIFY_TIMEOUT_MS. */
  timeoutMs?: number;
}

export interface SweepContext {
  blobs: BlobBackend;
  store: SharedStore;
  /** BLOB_ORIGIN from loadEnv: a posted document is read back from here, as verify reads it. */
  blobOrigin: string;
  /** Milliseconds since the epoch, from the scheduler's clock. */
  now: number;
  /**
   * A running clock in milliseconds, read only to measure how long this run has held its lock. The
   * process's monotonic clock by default.
   */
  clock?: () => number;
}

/** What one sweepUnverified call did. */
export type DocumentSweepOutcome =
  /** Another run holds the lock; this one read and deleted nothing. */
  | { done: "busy" }
  | {
      done: "swept";
      deleted: number;
      /** Posted documents with no verified mark left unhashed, by the byte bound or the time budget, for the next pass over their page. */
      deferred: number;
      /** The hashes of posted documents that could not be read back; none of them was deleted. */
      unreadable: string[];
      /** Whether the run stopped starting pages or hashing reads because its time budget was used. */
      outOfTime: boolean;
      /** Bookings given back for tokens whose upload never arrived (settleTokens). */
      returned: number;
    };

interface Target {
  hex: string;
  pathname: string;
  url: URL;
}

type Rejection = "blob_missing" | "too_large" | "empty" | "hash_mismatch";
type Checked = { size: number } | { rejected: Rejection };
type NamedBlob = BlobInfo & { hex: string };
type Unreadable = "unexpected_blob_url" | "read_failed" | "read_timeout";
/** What one sweep run has left of SWEEP_HASH_BYTES and of its time, and what it put off. */
interface HashRun {
  left: number;
  stopped: boolean;
  deferred: number;
  outOfTime: () => boolean;
  timedOut: boolean;
}

const verifiedKey = (hex: string): string => `verified:${hex}`;
const retry = (seconds: number): Record<string, string> => ({ "retry-after": String(seconds) });

/**
 * A document size as the marks state it: a whole number of bytes from 1 to MAX_CIPHER_SIZE, in
 * decimal with no sign, space or leading zero. Verified sizes and posted sizes both go through this
 * one parser, so the two are always compared as the same kind of number.
 */
function sizeOf(text: string): bigint | undefined {
  if (!/^[1-9][0-9]{0,15}$/.test(text)) return undefined;
  const size = BigInt(text);
  return size <= BigInt(MAX_CIPHER_SIZE) ? size : undefined;
}

/**
 * What `verified:<hex>` holds: null when nothing, otherwise the size it states, which is undefined
 * when it states none. Every read of a verified mark goes through here.
 */
async function readVerified(store: SharedStore, hex: string): Promise<{ size: bigint | undefined } | null> {
  const raw = await store.get(verifiedKey(hex));
  return raw === null ? null : { size: sizeOf(raw) };
}

/**
 * The size in bytes of the document named `sha256Hex` as this server last read and hashed it: the
 * size in its "verified:<sha256>" mark, which handleDocumentVerify or sweepUnverified writes only
 * after the stored bytes hashed to the name (threat model C28, C30, C44). A post that states another
 * cipherSize is not for the bytes the store holds.
 * @param sha256Hex The document's SHA-256 as 64 lowercase hex characters with no 0x. Anything else
 *   is answered undefined without a lookup.
 * @returns The size, or undefined when there is no mark or the mark is not a positive decimal no
 *   larger than MAX_CIPHER_SIZE.
 * @throws When the shared store fails.
 */
export async function verifiedSize(store: SharedStore, sha256Hex: string): Promise<bigint | undefined> {
  if (typeof sha256Hex !== "string" || !HEX.test(sha256Hex)) return undefined;
  return (await readVerified(store, sha256Hex))?.size;
}

/** The block and the sizes a posted mark holds; sizes is undefined for a mark that records none. Undefined for a mark in no form this file writes. */
function readPosted(raw: string): { block: string; sizes: bigint[] | undefined } | undefined {
  const parts = POSTED_MARK.exec(raw);
  if (parts === null) return undefined;
  const block = parts[1] ?? "";
  if (parts[2] === undefined) return { block, sizes: undefined };
  const sizes: bigint[] = [];
  for (const text of parts[2].split(",")) {
    const size = sizeOf(text);
    const last = sizes.at(-1);
    if (size === undefined || (last !== undefined && size <= last)) return undefined;
    sizes.push(size);
  }
  return sizes.length > POSTED_SIZES_MAX ? undefined : { block, sizes };
}

/**
 * The cipherSizes that the DocumentPosted events naming a document state, from its posted mark (the
 * value under postedKey). This is the one parser of that mark (threat model C44).
 * @returns The sizes, ascending, or undefined when the mark records none: one written before marks
 *   held sizes, one whose posts stated more than POSTED_SIZES_MAX sizes, or a value in no form this
 *   package writes. sweepUnverified never deletes a document for its size on such a mark.
 */
export function postedSizes(raw: string): readonly bigint[] | undefined {
  return readPosted(raw)?.sizes;
}

/**
 * The posted mark to write once the DocumentPosted events of a scan page that ends at `block` name a
 * document with `sizes`, given the mark the store holds now (`held`, null for none). A new mark is
 * `<block>:<sizes>`; a held mark keeps its block and gains the new sizes, and past POSTED_SIZES_MAX
 * sizes it becomes `<block>` alone, which records none.
 * @returns The value to write, or undefined when there is nothing to change: no sizes were given,
 *   the held mark has them all, or it records no sizes or is in no form this package writes. Such a
 *   mark is never rewritten.
 * @throws TypeError for a block that is not a whole number of at most 16 digits, or a size that is
 *   not a whole number from 1 to MAX_CIPHER_SIZE.
 */
export function postedMarkWith(held: string | null, block: bigint, sizes: Iterable<bigint>): string | undefined {
  if (typeof block !== "bigint" || block < 0n || block.toString().length > 16) throw new TypeError("A posted mark's block is a whole number of at most 16 digits.");
  const adding = [...sizes];
  for (const size of adding) {
    if (typeof size !== "bigint" || sizeOf(size.toString()) === undefined) throw new TypeError(`A posted size is a whole number from 1 to ${MAX_CIPHER_SIZE}.`);
  }
  const mark = held === null ? { block: block.toString(), sizes: [] } : readPosted(held);
  if (adding.length === 0 || mark?.sizes === undefined) return undefined;
  const all = [...new Set([...mark.sizes, ...adding])].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (held !== null && all.length === mark.sizes.length) return undefined;
  return all.length > POSTED_SIZES_MAX ? mark.block : `${mark.block}:${all.join(",")}`;
}

/** A JSON body of at most BODY_CAP bytes, ending within 20 seconds, as parsed; or the refusal to send. */
async function readJson(request: Request): Promise<{ value: unknown } | Response> {
  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") return refuse(415, "json_only");
  const stated = declaredLength(request);
  if (stated !== undefined && stated > BODY_CAP) return refuse(413, "body_too_large");
  if (request.body === null) return refuse(400, "bad_body");
  try {
    return { value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBody(request.body, BODY_CAP))) };
  } catch (error) {
    if (error instanceof TooLarge) return refuse(413, "body_too_large");
    return error instanceof BodyTimeout ? refuse(408, "body_timeout") : refuse(400, "bad_body");
  }
}

/**
 * The 32 bytes the caller names, from a JSON body of exactly `{ "sha256": "<64 lowercase hex>" }`,
 * or the refusal to send. The pathname, the store keys and the hash comparison all come from these
 * bytes, so no second parser can disagree with the first.
 */
async function readHash(request: Request): Promise<Uint8Array | Response> {
  const read = await readJson(request);
  if (read instanceof Response) return read;
  const checked = HashBody.safeParse(read.value);
  if (!checked.success) return refuse(400, "bad_sha256");
  return Uint8Array.from(Buffer.from(checked.data.sha256, "hex"));
}

/**
 * The name and size a token request states, from a JSON body of exactly `{ "sha256": "<64
 * lowercase hex>", "size": <bytes> }`, the size a whole number from 1 to DOCUMENT_CAP; or the
 * refusal to send: 400 bad_size for the size alone, 400 bad_sha256 for anything else.
 */
async function readTokenRequest(request: Request): Promise<{ hash: Uint8Array; size: number } | Response> {
  const read = await readJson(request);
  if (read instanceof Response) return read;
  const checked = TokenBody.safeParse(read.value);
  if (!checked.success) return refuse(400, checked.error.issues.every((issue) => issue.path[0] === "size") ? "bad_size" : "bad_sha256");
  return { hash: Uint8Array.from(Buffer.from(checked.data.sha256, "hex")), size: checked.data.size };
}

/** One of the UTC day's document byte budgets a token's size is booked on. */
interface ByteBudget {
  key: string;
  max: number;
  by: "client" | "net48" | "total";
}

/**
 * The store has no decrement, so each budget is two counters that only grow: what was booked under
 * its key, and what was given back under this one. A booking may count twice when a lost reply is
 * retried, which only overstates the day; so the booked counter moves by increment, and this one,
 * where a doubled write would understate it, only by addOnce.
 */
const returnedKey = (key: string): string => `${key}:returned`;
/** Every give-back of document bytes takes this lock, so no other one writes a returned counter between its read and its write (addOnce). */
const RETURN_LOCK = "docbytes:return";
/** A give-back is at most nine store calls; the lock ends on its own long after them if its holder dies. */
const RETURN_LOCK_SECONDS = 10;
/** A give-back that waits longer than this for another leaves its bytes booked, the side that overstates. */
const RETURN_LOCK_WAIT_MS = 5_000;

/**
 * The budgets a token request from `clientIp` books on for the UTC day of `now`, narrowest first:
 * the client's own, for IPv6 its /48's, then every client's together. The client and /48 keys are
 * the ones spendBudget kept this budget under before, so a day already booked carries over.
 */
function byteBudgets(clientIp: string, now: number): ByteBudget[] | undefined {
  const ip = clientKey(clientIp);
  if (ip === undefined) return undefined;
  const day = new Date(now).toISOString().slice(0, 10);
  // clientKey writes an IPv6 client as the first four groups of its /64, so the first three are its
  // /48, written as ratelimit.ts writes it: one parser for both.
  const net48 = ip.endsWith("::/64") ? `${ip.split(":").slice(0, 3).join(":")}::/48` : undefined;
  return [
    { key: `budget:docbytes-${day}:ip:${ip}`, max: DOC_BYTES_PER_CLIENT_DAY, by: "client" },
    ...(net48 === undefined ? [] : [{ key: `budget:docbytes-${day}:net48:${net48}`, max: DOC_BYTES_PER_NET48_DAY, by: "net48" as const }]),
    { key: `budget:docbytes:all:${day}`, max: DOC_BYTES_TOTAL_DAY, by: "total" },
  ];
}

/** A budget counter as a whole number. @throws For any other value, so a damaged counter refuses. */
async function countAt(store: SharedStore, key: string): Promise<number> {
  const raw = await store.get(key);
  if (raw === null) return 0;
  const count = Number(raw);
  if (!/^\d{1,16}$/.test(raw) || !Number.isSafeInteger(count)) throw new Error("A document byte counter holds an unexpected value.");
  return count;
}

/**
 * Gives `size` back on each budget key (threat model C31), under RETURN_LOCK and by addOnce, so a
 * write retried after a lost reply lands once and never makes a budget show less than it holds. A
 * write that fails or cannot be confirmed, or a lock not had in time, leaves that much booked, which
 * only ever overstates the day, and is never tried again. Never throws.
 */
async function giveBack(store: SharedStore, keys: readonly string[], size: number): Promise<void> {
  let reached = 0;
  try {
    await store.withLock(
      RETURN_LOCK,
      RETURN_LOCK_SECONDS,
      async () => {
        for (const key of keys) {
          reached += 1;
          if (!(await addOnce(store, returnedKey(key), BigInt(size), DOC_BYTES_KEY_SECONDS).catch(() => false))) logEvent("docbytes_unreturned", { size });
        }
      },
      { waitMs: RETURN_LOCK_WAIT_MS },
    );
  } catch {
    for (let i = reached; i < keys.length; i++) logEvent("docbytes_unreturned", { size });
  }
}

/**
 * Books `size` on every budget, narrowest first, all or none: a budget it would pass refuses and
 * what the earlier ones took is given back, so a refused request books nothing. Two requests that
 * race past the read are each checked again after their own increment, and one that crosses is
 * refused the same way. Fails closed on a store error or a counter it cannot read.
 */
async function bookBytes(store: SharedStore, budgets: readonly ByteBudget[], size: number): Promise<{ keys: string[] } | { refusedBy: ByteBudget["by"] | "store" }> {
  const taken: string[] = [];
  const refused = async (by: ByteBudget["by"] | "store") => {
    await giveBack(store, taken, size);
    return { refusedBy: by };
  };
  try {
    for (const budget of budgets) {
      // What was given back is read first: one landing between the two reads only makes the day look fuller.
      const returned = await countAt(store, returnedKey(budget.key));
      const booked = await countAt(store, budget.key);
      if (returned > booked) throw new Error("A document byte budget shows more given back than booked.");
      if (booked - returned + size > budget.max) return refused(budget.by);
      const after = (await store.incrWindow(budget.key, DOC_BYTES_KEY_SECONDS, size)) - returned;
      taken.push(budget.key);
      if (after > budget.max) return refused(budget.by);
    }
  } catch {
    return refused("store");
  }
  return { keys: taken };
}

/**
 * Books a token's stated size on the UTC day's document byte budgets before the token is issued
 * (threat model C28, C44): the client's own DOC_BYTES_PER_CLIENT_DAY, for IPv6 its /48's
 * DOC_BYTES_PER_NET48_DAY, then DOC_BYTES_TOTAL_DAY for every client together, all or none.
 *
 * @returns The budget keys it booked on, otherwise 429 upload_bytes with a retry-after of the time
 *   to UTC midnight, having booked nothing.
 */
async function bookDocumentBytes(ctx: DocumentContext, size: number): Promise<{ keys: string[] } | Response> {
  const budgets = byteBudgets(ctx.clientIp, ctx.now);
  const booked = budgets === undefined ? { refusedBy: "client" as const } : await bookBytes(ctx.store, budgets, size);
  if ("keys" in booked) return booked;
  logEvent("doctoken_refused", { reason: "upload_bytes", by: booked.refusedBy });
  return refuse(429, "upload_bytes", retry(secondsToUtcMidnight(ctx.now)));
}

/** Each issued token is numbered in turn, so the sweep walks them in the order they end. Ten years, so the numbers never start again. */
const TOKEN_SEQ_KEY = "doctoken:seq";
const TOKEN_SEQ_SECONDS = 315_360_000;
/** The last token number the sweep has settled. */
const TOKEN_CURSOR_KEY = "doctoken:settled-through";
const tokenKey = (n: number): string => `doctoken:${n}`;
const tokenNameKey = (hex: string): string => `doctoken:name:${hex}`;
/** A record lives as long as the day budgets it gives back to; past that there is nothing left to give back. */
const TOKEN_RECORD_SECONDS = DOC_BYTES_KEY_SECONDS;
/**
 * A token's bytes come back only this long after the token ends (threat model C28, C44): far longer
 * than an upload begun in its last second can still be running, so no bytes it lets in can land
 * after its booking was given back.
 */
export const UNUSED_TOKEN_GRACE_MS = 3_600_000;
/** Token records one sweep run settles at most; a busier stretch is taken over the next runs. */
const TOKEN_SETTLES_PER_RUN = 500;
const RETURNED_TOKEN = /^returned:[0-9a-f-]{36}$/;
const BUDGET_KEY = /^budget:docbytes(?:-\d{4}-\d{2}-\d{2}:(?:ip|net48):[0-9a-f.:/]{1,48}|:all:\d{4}-\d{2}-\d{2})$/;
/** What a token's record holds until its booking comes back: its name, size, end and the budget keys it booked on. */
const TokenRecord = z.strictObject({
  name: z.string().regex(HEX),
  size: z.number().int().min(1).max(DOCUMENT_CAP),
  until: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  keys: z.array(z.string().regex(BUDGET_KEY)).min(1).max(3),
});
type TokenRecord = z.infer<typeof TokenRecord>;

/** A token record read back as an input: the record, "returned" once its booking came back, or undefined for anything else, which gives nothing back. */
function readToken(raw: string): TokenRecord | "returned" | undefined {
  if (RETURNED_TOKEN.test(raw)) return "returned";
  try {
    const parsed = TokenRecord.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

/** Whether the token can no longer let anything in: its lifetime and the grace after it are over. */
const pastGrace = (record: TokenRecord, now: number): boolean => now >= record.until + UNUSED_TOKEN_GRACE_MS;

/**
 * Records a token under the next number before it reaches the client, so the sweep finds it however
 * the request ends, then links the name's latest number to it for verify, on a best-effort basis:
 * the sweep reaches every record by its number. When the record cannot be written, its booking comes
 * back here only by retiring that number (retireToken), because a record that landed with its reply
 * lost would otherwise give the same bytes back a second time; when even that fails, the booking
 * stays and the sweep gives it back from the record, if one landed.
 * @returns Whether the token was recorded. False means it must not be handed out.
 */
async function recordToken(store: SharedStore, record: TokenRecord): Promise<boolean> {
  let n: number;
  try {
    n = await store.incrWindow(TOKEN_SEQ_KEY, TOKEN_SEQ_SECONDS);
  } catch {
    // No record was written, so nothing else can give this booking back.
    await giveBack(store, record.keys, record.size);
    return false;
  }
  const key = tokenKey(n);
  const written = JSON.stringify(record);
  if (!(await claimOnce(store, key, written, TOKEN_RECORD_SECONDS).catch(() => false))) {
    if (await retireToken(store, key, written).catch(() => false)) await giveBack(store, record.keys, record.size);
    else logEvent("docbytes_kept", { size: record.size });
    return false;
  }
  const nameKey = tokenNameKey(record.name);
  try {
    const held = await store.get(nameKey);
    if ((await store.compareAndSet(nameKey, held, String(n), TOKEN_RECORD_SECONDS)) || (await store.get(nameKey)) === String(n)) return true;
  } catch {
    // Logged below; the sweep still settles the record.
  }
  logEvent("doctoken_name_unlinked");
  return true;
}

/**
 * Takes a token number whose record may or may not have landed for this request's own give-back:
 * an empty number gets a tombstone that no late write can pass, and the record, if it landed, moves
 * to one by compare-and-set. @returns Whether this request now holds the number's give-back.
 */
async function retireToken(store: SharedStore, key: string, written: string): Promise<boolean> {
  const mine = `returned:${randomUUID()}`;
  if (await claimOnce(store, key, mine, TOKEN_RECORD_SECONDS)) return true;
  return (await store.compareAndSet(key, written, mine, TOKEN_RECORD_SECONDS)) || (await store.get(key)) === mine;
}

/**
 * Gives a token's booking back, once (threat model C28, C31, C44): its record moves by
 * compare-and-set from the exact value read to one carrying this caller's own token, and only the
 * caller whose move landed (read back on a no) gives anything back.
 * @returns Whether this call gave the booking back.
 */
async function returnToken(store: SharedStore, key: string, raw: string, record: TokenRecord): Promise<boolean> {
  const mine = `returned:${randomUUID()}`;
  if (!(await store.compareAndSet(key, raw, mine, TOKEN_RECORD_SECONDS)) && (await store.get(key)) !== mine) return false;
  await giveBack(store, record.keys, record.size);
  logEvent("doctoken_bytes_returned", { size: record.size });
  return true;
}

/**
 * For verify, which has just found the name `hex` empty: gives back the booking of the latest token
 * issued for that name once it is past its grace. A failure is logged; the sweep still reaches it.
 */
async function returnIfUnused(store: SharedStore, hex: string, now: number): Promise<void> {
  try {
    const n = await store.get(tokenNameKey(hex));
    if (n === null || !/^[1-9]\d{0,15}$/.test(n)) return;
    const key = tokenKey(Number(n));
    const raw = await store.get(key);
    const record = raw === null ? undefined : readToken(raw);
    if (raw === null || record === undefined || record === "returned" || record.name !== hex || !pastGrace(record, now)) return;
    await returnToken(store, key, raw, record);
  } catch {
    logEvent("doctoken_return_failed");
  }
}

/**
 * Settles the token records past their grace, in the order they were issued, from where the last
 * run stopped (threat model C28, C44): a token whose name the blob store holds nothing under gives
 * its booking back; one whose name holds a blob keeps it. It stops at the first record not yet past
 * its grace, since every later one ends later, after TOKEN_SETTLES_PER_RUN numbers, or when the run
 * is out of time. A number with no record (one that lapsed, or one a retried count skipped) is
 * passed once a later number is settled, and a record it cannot read gives nothing back. The cursor
 * moves by compare-and-set from the value read.
 * @returns How many bookings it gave back. @throws When a store fails or another run moved the cursor.
 */
async function settleTokens(ctx: SweepContext, outOfTime: () => boolean): Promise<number> {
  const issued = await countAt(ctx.store, TOKEN_SEQ_KEY);
  const held = await ctx.store.get(TOKEN_CURSOR_KEY);
  if (held !== null && !/^\d{1,16}$/.test(held)) throw new Error("The token cursor holds an unexpected value.");
  // A cursor past the last number means the numbers started again, so every record is read afresh.
  const from = held === null || Number(held) > issued ? 0 : Number(held);
  let through = from;
  let returned = 0;
  for (let n = from + 1; n <= Math.min(issued, from + TOKEN_SETTLES_PER_RUN) && !outOfTime(); n++) {
    const key = tokenKey(n);
    const raw = await ctx.store.get(key);
    if (raw === null) continue;
    const record = readToken(raw);
    if (record !== undefined && record !== "returned") {
      if (!pastGrace(record, ctx.now)) break;
      const empty = (await ctx.blobs.head(`${PREFIX}${record.name}`, AbortSignal.timeout(STORE_TIMEOUT_MS))) === null;
      if (empty && (await returnToken(ctx.store, key, raw, record))) returned += 1;
    }
    through = n;
  }
  if (through === from) return returned;
  const to = String(through);
  if (!(await ctx.store.compareAndSet(TOKEN_CURSOR_KEY, held, to, TOKEN_SEQ_SECONDS)) && (await ctx.store.get(TOKEN_CURSOR_KEY)) !== to) {
    throw new Error("The token cursor moved under another run.");
  }
  return returned;
}

/** Where a document with this hash lives, or undefined when BLOB_ORIGIN is not an https origin. */
function targetOf(hash: Uint8Array, blobOrigin: string): Target | undefined {
  if (!isHttpsOrigin(blobOrigin)) return undefined;
  const hex = Buffer.from(hash).toString("hex");
  const pathname = `${PREFIX}${hex}`;
  return { hex, pathname, url: new URL(`${blobOrigin}/${pathname}`) };
}

/**
 * Reads the document at `url`, stopping once it passes the cap, and checks that its bytes are a
 * document named `hash`. Verify and the sweep both decide with this one check, so they can never
 * disagree (threat model C28). A read over the cap is the verdict "too_large".
 * @throws For any other read failure, a timeout included.
 */
async function checkDocument(blobs: BlobBackend, url: URL, hash: Uint8Array, signal: AbortSignal): Promise<Checked> {
  let bytes: Uint8Array | null;
  try {
    bytes = await blobs.read(url, DOCUMENT_CAP, signal);
  } catch (error) {
    if (error instanceof TooLarge) return { rejected: "too_large" };
    throw error;
  }
  if (bytes === null) return { rejected: "blob_missing" };
  if (bytes.byteLength === 0) return { rejected: "empty" };
  if (!sameHash(sha256(bytes), hash)) return { rejected: "hash_mismatch" };
  return { size: bytes.byteLength };
}

/**
 * Issues a short-lived token that lets the browser write one document straight to the blob store
 * (threat model C28, C29).
 *
 * The body is `{ sha256, size }`: the SHA-256 of the ciphertext as 64 lowercase hex characters, and
 * its length in bytes as a whole number from 1 to 26,214,400, sent as `application/json`. The token
 * allows a write to exactly `document/<sha256>`, only as `application/octet-stream`, at most `size`
 * bytes, with no random suffix and never over an existing blob, for ten minutes. The browser then
 * calls the client `put` from `@vercel/blob/client` with `{ access: "public", token, contentType }`,
 * and must call handleDocumentVerify before anything is signed.
 *
 * Every document that is posted is kept for good, whoever sends the post, so a token's `size` is
 * booked on the UTC day's document byte budgets before the token is issued (bookDocumentBytes,
 * threat model C44): DOC_BYTES_PER_CLIENT_DAY (25 MiB) for this client, its IPv6 /48 sharing four
 * times that, and DOC_BYTES_TOTAL_DAY (fifty clients' days) for every client together, all or
 * none. That bounds what the store can be made to keep in a day, however a document is later
 * posted. A request refused anywhere books nothing. Each issued token is recorded before it is
 * answered, and once its ten minutes and UNUSED_TOKEN_GRACE_MS (an hour) after them are over, a
 * token whose name still holds nothing gives its bytes back, once: found so by sweepUnverified, or
 * by handleDocumentVerify for the name's latest token.
 *
 * Answers 200 `{ exists: true, url }` when that pathname already holds a blob: no token is issued,
 * nothing is booked, and the browser skips the upload and verifies. Otherwise 200 `{ exists: false,
 * pathname, token, contentType, maxBytes, validUntil }`, with `maxBytes` equal to `size`, after any
 * "verified:<sha256>" mark for that empty name is deleted (logged stale_verified_mark_cleared), so
 * verify checks the new bytes instead of answering from a mark that outlived its blob (threat model
 * C28, C44).
 *
 * First of all, a request another site's page could have sent is refused with 403 `cross_site`
 * (refuseCrossSite, threat model C23), before anything is counted or read. Then refuses with 405
 * for another method, 415 for another content type, 413 for a body over 256 bytes, 408 for a body
 * that has not ended after 20 seconds, 400 bad_size for a size outside 1 to 26,214,400 or not a
 * whole number, 400 for any other body, 429 over the request limits or the hourly per-IP token
 * count (or when they cannot be checked), 429 upload_bytes (retry after UTC midnight) when either
 * byte budget would pass its ceiling, with no token, 500 when BLOB_ORIGIN is malformed or no token
 * can be built, 502 when the store fails or reports any other URL, and 503 when the shared store
 * cannot delete that mark or record the token.
 */
export async function handleDocumentToken(request: Request, ctx: DocumentContext): Promise<Response> {
  const crossSite = refuseCrossSite(request);
  if (crossSite !== undefined) return crossSite;
  if (request.method !== "POST") return refuse(405, "method_not_allowed", { allow: "POST" });
  const rules = ctx.tokenLimits ?? DOCUMENT_TOKEN_LIMITS;
  const verdict = await limit(ctx.store, { scope: "doctoken", clientIp: ctx.clientIp, perIp: rules.perIp, total: rules.total, windowSeconds: rules.windowSeconds });
  if (!verdict.ok) return refuse(429, "rate_limited", retry(verdict.retryAfter));
  const asked = await readTokenRequest(request);
  if (asked instanceof Response) return asked;
  const target = targetOf(asked.hash, ctx.env.BLOB_ORIGIN);
  if (target === undefined) {
    logEvent("doctoken_refused", { reason: "bad_blob_origin" });
    return refuse(500, "server_misconfigured");
  }

  let found: BlobInfo | null;
  try {
    found = await ctx.blobs.head(target.pathname, AbortSignal.timeout(STORE_TIMEOUT_MS));
  } catch {
    logEvent("doctoken_refused", { reason: "store_failed" });
    return refuse(502, "store_failed");
  }
  if (found !== null) {
    if (!sameUrl(found.url, target.url.href)) {
      logEvent("doctoken_refused", { reason: "unexpected_blob_url" });
      return refuse(502, "unexpected_blob_url");
    }
    return json(200, { exists: true, url: target.url.href });
  }

  const budget = { scope: "doctoken", clientIp: ctx.clientIp, max: rules.tokensPerIp, windowSeconds: rules.windowSeconds };
  const spent = await spendBudget(ctx.store, budget, 1);
  if (!spent.ok) return refuse(429, "token_budget_spent", retry(spent.retryAfter));

  // A mark with no blob outlived what it vouched for (a delete outside the sweep, a store switch).
  // Left in place, verify would answer from it for whatever bytes this token lets in.
  try {
    if (await ctx.store.delete(verifiedKey(target.hex))) logEvent("stale_verified_mark_cleared", { sha256: target.hex });
  } catch {
    logEvent("doctoken_refused", { reason: "shared_store_failed" });
    return refuse(503, "store_failed");
  }

  // Booked last of the refusals a caller can meet, and given back by every later one, so a request
  // refused anywhere books nothing.
  const booked = await bookDocumentBytes(ctx, asked.size);
  if (booked instanceof Response) return booked;

  const validUntil = ctx.now + DOCUMENT_TOKEN_SECONDS * 1000;
  let token: unknown;
  try {
    token = await (ctx.buildToken ?? generateClientTokenFromReadWriteToken)({
      token: ctx.env.BLOB_READ_WRITE_TOKEN,
      pathname: target.pathname,
      allowedContentTypes: [DOCUMENT_CONTENT_TYPE],
      maximumSizeInBytes: asked.size,
      validUntil,
      addRandomSuffix: false,
      allowOverwrite: false,
    });
  } catch {
    token = undefined;
  }
  if (typeof token !== "string" || !token.startsWith("vercel_blob_client_")) {
    await giveBack(ctx.store, booked.keys, asked.size);
    logEvent("doctoken_refused", { reason: "token_failed" });
    return refuse(500, "token_failed");
  }
  // The record goes in before the token leaves, so a token whose upload never arrives gives its
  // bytes back; one that cannot be recorded is never handed out.
  if (!(await recordToken(ctx.store, { name: target.hex, size: asked.size, until: validUntil, keys: booked.keys }))) {
    logEvent("doctoken_refused", { reason: "shared_store_failed" });
    return refuse(503, "store_failed");
  }
  logEvent("doctoken_issued", { size: asked.size });
  return json(200, { exists: false, pathname: target.pathname, token, contentType: DOCUMENT_CONTENT_TYPE, maxBytes: asked.size, validUntil });
}

/**
 * Reads a browser-uploaded document back from the blob origin and keeps it only if its SHA-256 is
 * its name (threat model C28, C30, C44). Run it after every upload, and before the chair signs the URL.
 *
 * The body is `{ sha256 }` as for handleDocumentToken. The bytes are streamed from
 * `${BLOB_ORIGIN}/document/<sha256>` (the URL the store reports must equal that form, parsed by
 * the same URL parser), stopping at 26,214,400 bytes, all within 30 seconds, then hashed.
 *
 * A document that already has its "verified:<sha256>" mark is answered 200 from the mark alone:
 * verify never reads or deletes it again (threat model C44). Only sweepUnverified can still delete
 * it, by the chain: when no DocumentPosted names it two hours after its upload, or its size is no
 * cipherSize a post stated. Otherwise it answers 200 `{ sha256, size, url }`
 * on a match and writes the mark. Deletes the blob and answers 409 `{ error }` when it is missing
 * ("blob_missing", which also gives back the bytes of the name's latest token once that token is
 * past its grace), over the cap ("too_large"), empty ("empty") or not the hash it is named for
 * ("hash_mismatch"). One older than 50 minutes is answered 409 "too_old" and not deleted: only
 * sweepUnverified deletes an old document, by the chain, so a store that lost its marks cannot
 * turn a verify into the delete of a posted document. The verified mark does not keep a document:
 * only a DocumentPosted event does (see sweepUnverified).
 *
 * Refuses without deleting: 403, 405, 415, 413, 408, 400 and 429 as for handleDocumentToken (rate
 * scope "docverify"), 500 when BLOB_ORIGIN is malformed, 502 when the store fails or reports another
 * URL, 503 when the shared store fails or holds a mark that is not a size within the cap, 504 on
 * timeout.
 */
export async function handleDocumentVerify(request: Request, ctx: DocumentContext): Promise<Response> {
  const crossSite = refuseCrossSite(request);
  if (crossSite !== undefined) return crossSite;
  if (request.method !== "POST") return refuse(405, "method_not_allowed", { allow: "POST" });
  const rules = ctx.verifyLimits ?? DOCUMENT_VERIFY_LIMITS;
  const verdict = await limit(ctx.store, { scope: "docverify", clientIp: ctx.clientIp, ...rules });
  if (!verdict.ok) return refuse(429, "rate_limited", retry(verdict.retryAfter));
  const hash = await readHash(request);
  if (hash instanceof Response) return hash;
  const target = targetOf(hash, ctx.env.BLOB_ORIGIN);
  if (target === undefined) {
    logEvent("docverify_refused", { reason: "bad_blob_origin" });
    return refuse(500, "server_misconfigured");
  }

  // Once verified, verify never deletes it (threat model C44): the mark is the answer, so a later
  // read that fails or comes back empty cannot take it away here. Only the sweep, by the chain, can.
  let mark: { size: bigint | undefined } | null;
  try {
    mark = await readVerified(ctx.store, target.hex);
  } catch {
    logEvent("docverify_refused", { reason: "shared_store_failed" });
    return refuse(503, "store_failed");
  }
  if (mark !== null) {
    if (mark.size === undefined) {
      logEvent("docverify_refused", { reason: "bad_verified_mark" });
      return refuse(503, "store_failed");
    }
    return json(200, { sha256: target.hex, size: Number(mark.size), url: target.url.href });
  }

  const signal = AbortSignal.timeout(ctx.timeoutMs ?? VERIFY_TIMEOUT_MS);
  const failed = (): Response => {
    const reason = signal.aborted ? "verify_timeout" : "store_failed";
    logEvent("docverify_refused", { reason });
    return reason === "verify_timeout" ? refuse(504, reason) : refuse(502, reason);
  };
  const reject = async (reason: string): Promise<Response> => {
    try {
      await ctx.blobs.delete([target.pathname], AbortSignal.timeout(STORE_TIMEOUT_MS));
    } catch {
      // The verdict stands; the sweep removes the blob later.
      logEvent("docverify_delete_failed");
    }
    logEvent("docverify_rejected", { reason });
    return refuse(409, reason);
  };

  let found: BlobInfo | null;
  try {
    found = await ctx.blobs.head(target.pathname, signal);
  } catch {
    return failed();
  }
  if (found === null) {
    await returnIfUnused(ctx.store, target.hex, ctx.now);
    return reject("blob_missing");
  }
  if (!sameUrl(found.url, target.url.href)) {
    logEvent("docverify_refused", { reason: "unexpected_blob_url" });
    return refuse(502, "unexpected_blob_url");
  }
  // Not deleted here: a store that lost its verified marks would make every posted document look
  // unverified. Only the sweep deletes an old document, and only by the chain (threat model C44).
  if (ctx.now - found.uploadedAt > VERIFY_WINDOW_MS) {
    logEvent("docverify_rejected", { reason: "too_old" });
    return refuse(409, "too_old");
  }

  let checked: Checked;
  try {
    checked = await checkDocument(ctx.blobs, target.url, hash, signal);
  } catch {
    return failed();
  }
  if ("rejected" in checked) return reject(checked.rejected);

  try {
    await ctx.store.setIfAbsent(verifiedKey(target.hex), String(checked.size), VERIFIED_SECONDS);
  } catch {
    logEvent("docverify_refused", { reason: "shared_store_failed" });
    return refuse(503, "store_failed");
  }
  return json(200, { sha256: target.hex, size: checked.size, url: target.url.href });
}

/** The blob store cursor a LISTING_CURSOR_KEY value names, or undefined to start from the first page: for none, "start", or anything else. */
function listingCursorOf(raw: string | null): string | undefined {
  return raw === null ? undefined : LISTING_AFTER.exec(raw)?.[1];
}

/**
 * Moves the listing cursor from the exact value this run last read or wrote to the one naming
 * `next` ("start" once the listing has ended). On a no, a store that applied the write and lost its
 * reply already holds the new value; anything else is another run, and this one stops.
 * @returns The value the key now holds.
 * @throws When another run moved the cursor.
 */
async function moveListing(store: SharedStore, from: string | null, next: string | undefined): Promise<string> {
  let to = next === undefined ? LISTING_START : `after:${next}`;
  if (listingCursorOf(to) !== next) {
    // Kept as "start" rather than as a value the next run would not read back the same.
    logEvent("docsweep_cursor_unkept");
    to = LISTING_START;
  }
  if (!(await store.compareAndSet(LISTING_CURSOR_KEY, from, to, LISTING_CURSOR_SECONDS)) && (await store.get(LISTING_CURSOR_KEY)) !== to) {
    throw new Error("The document sweep's listing cursor moved under another run.");
  }
  return to;
}

/** `lookup` for each hash, SWEEP_PARALLEL at a time, in the order given. */
async function inBatches<T>(hexes: readonly string[], lookup: (hex: string) => Promise<T>): Promise<T[]> {
  const found: T[] = [];
  for (let start = 0; start < hexes.length; start += SWEEP_PARALLEL) {
    found.push(...(await Promise.all(hexes.slice(start, start + SWEEP_PARALLEL).map(lookup))));
  }
  return found;
}

/**
 * Hashes one posted document that has no verified mark, with verify's own check, inside what the
 * run has left of SWEEP_HASH_BYTES and of its time. Writes no mark: the caller marks it verified
 * only once its size is one the chain stated. Returns the size its bytes hashed at, why it must be
 * deleted, why it could not be read (it is kept), or undefined when it stays for another reason: it
 * is gone already, or the run has no room left to hash it.
 */
async function checkPosted(ctx: SweepContext, blob: NamedBlob, run: HashRun): Promise<{ size: bigint } | { doomed: Exclude<Rejection, "blob_missing"> } | { unreadable: Unreadable } | undefined> {
  const hash = Uint8Array.from(Buffer.from(blob.hex, "hex"));
  const target = targetOf(hash, ctx.blobOrigin);
  if (target === undefined || !sameUrl(blob.url, target.url.href)) return { unreadable: "unexpected_blob_url" };
  // A size the store does not state as a whole number is charged as the cap, so the bound holds.
  const cost = Number.isSafeInteger(blob.size) && blob.size >= 0 ? Math.min(blob.size, DOCUMENT_CAP) : DOCUMENT_CAP;
  if (!run.stopped && run.outOfTime()) {
    run.stopped = true;
    run.timedOut = true;
  }
  if (!run.stopped && cost > run.left) run.stopped = true;
  if (run.stopped) {
    run.deferred += 1;
    return undefined;
  }
  run.left -= cost;
  const signal = AbortSignal.timeout(VERIFY_TIMEOUT_MS);
  let checked: Checked;
  try {
    checked = await checkDocument(ctx.blobs, target.url, hash, signal);
  } catch {
    return { unreadable: signal.aborted ? "read_timeout" : "read_failed" };
  }
  if ("size" in checked) return { size: BigInt(checked.size) };
  return checked.rejected === "blob_missing" ? undefined : { doomed: checked.rejected };
}

/**
 * Deletes every document blob that no registry DocumentPosted event names two hours after its
 * upload, verified or not, and every posted one whose bytes are not its name (threat model C28,
 * C44). Anything under `document/` not named by a 64-hex hash can never be posted, and goes once
 * older than an hour.
 *
 * Every keep decision comes from the chain: the "posted:<registry>:<sha256>" marks and the scan point that the
 * registry log scan in envelopeSweep.ts writes, both rebuilt from the deploy block if the store is
 * lost. A missing mark counts as "not posted" only once the scan point's block time is at least two
 * hours after the upload, so a scan that is behind, or one starting over after a wiped store,
 * never causes a posted document to be deleted. With no scan point, nothing named by a hash is
 * deleted. Does not cover a document posted more than two hours after its upload: it is deleted
 * first, so the app posts a document right after verifying it. Every document the sweep deletes
 * loses its "verified:<sha256>" mark first, so no mark outlives the bytes it vouched for: other
 * bytes later written under the freed name are read and hashed by verify, never answered from a
 * stale mark.
 *
 * A posted document is kept only at a size the chain stated for it: its size must be one of the
 * cipherSizes its posted mark records (postedSizes). The size is the one in its verified mark, or,
 * for one with no verified mark, the length its bytes hashed at. One whose size is not among them
 * is deleted, verified or not, and logged as document_size_mismatch; a verified one is decided from
 * its mark without a read. A posted mark that records no sizes (written before marks held them, or
 * for a hash posted with more than POSTED_SIZES_MAX sizes) never gets a document deleted for its
 * size, only for a hash mismatch.
 *
 * A chair can post a document it never verified, so a posted one with no "verified:<sha256>" mark
 * is read back from `${blobOrigin}/document/<sha256>` and hashed once, by the same check verify
 * makes, and only when the store reports that URL for it. A match at a size the chain stated writes
 * its verified mark, so it is never read again. A mismatch, an empty blob or one over 25 MiB is
 * deleted and logged as document_mismatch_deleted: the registry records sizes from 1 byte to 25 MiB
 * only, so none of them can be the document an event describes. A posted document that cannot be
 * read back (the read fails, runs past 30 seconds, or the store reports another URL for it) is never
 * deleted: it is logged as document_read_failed with its hash, reported in `unreadable`, and the run
 * goes on to the next document. One run hashes at most SWEEP_HASH_BYTES, as the store reports
 * sizes, and starts no hashing read after SWEEP_RUN_BUDGET_MS (240 s); the first document that does
 * not fit, and every one after it, is left unhashed and undeleted for a later run. Only documents
 * past two hours are hashed, which is past VERIFY_WINDOW_MS, no token is issued for a name that
 * holds a blob, and runs take the "docsweep:lock" lock one at a time, so nothing can delete or
 * replace a document between this run's read and its delete.
 *
 * Meant for a schedule; safe to run alongside verify because of VERIFY_WINDOW_MS. A run that finds
 * the lock held answers `{ done: "busy" }` at once, having read and deleted nothing. One run covers
 * at most 5,000 documents in pathname order, and starts no new page after 240 s. The listing goes on
 * where the last run stopped: after each page the run moves the "docsweep:cursor" key, by
 * compare-and-set from the value it read, to the page that follows, and back to the first page once
 * the listing has ended (threat model C31). So every name is reached within ceil(pages / 50) runs,
 * however many kept documents sort ahead of it. A document a run leaves unhashed is kept, and hashed
 * when the listing next reaches its page. A shared store or blob store listing or
 * delete failure, a scan point that holds an unexpected value, or a cursor another run moved, stops
 * the run and is thrown, and nothing is deleted for the page that failed. A listing that fails
 * while the run holds a cursor also moves the cursor back to "start" first, so a cursor the blob
 * store no longer takes stops one run, never every run after it.
 *
 * Then, with the time the run has left, it settles the document tokens past their ten minutes and
 * UNUSED_TOKEN_GRACE_MS (settleTokens): each one whose name the blob store still holds nothing
 * under gives its booked bytes back to the day's budgets, once, and is reported in `returned`. A
 * failure there is logged and left to the next run.
 * @throws Before anything is read, when blobOrigin is not an https origin.
 */
export async function sweepUnverified(ctx: SweepContext): Promise<DocumentSweepOutcome> {
  if (!isHttpsOrigin(ctx.blobOrigin)) throw new Error("BLOB_ORIGIN is not an https origin, so no posted document can be read back.");
  try {
    return await ctx.store.withLock(SWEEP_LOCK, SWEEP_LOCK_TTL_SECONDS, () => sweepLocked(ctx));
  } catch (error) {
    if (!(error instanceof LockBusy)) throw error;
    logEvent("docsweep_busy");
    return { done: "busy" };
  }
}

async function sweepLocked(ctx: SweepContext): Promise<DocumentSweepOutcome> {
  const clock = ctx.clock ?? (() => performance.now());
  const started = clock();
  const run: HashRun = { left: SWEEP_HASH_BYTES, stopped: false, deferred: 0, outOfTime: () => clock() - started >= SWEEP_RUN_BUDGET_MS, timedOut: false };
  const scanned = parsePostedScan(await ctx.store.get(POSTED_SCAN_KEY));
  let held = await ctx.store.get(LISTING_CURSOR_KEY);
  let cursor = listingCursorOf(held);
  let deleted = 0;
  const unreadable: string[] = [];
  for (let page = 0; page < SWEEP_MAX_PAGES; page++) {
    if (page > 0 && run.outOfTime()) {
      run.timedOut = true;
      break;
    }
    let listed: BlobPage;
    try {
      listed = await ctx.blobs.list(PREFIX, { limit: SWEEP_PAGE_SIZE, cursor, signal: AbortSignal.timeout(STORE_TIMEOUT_MS) });
    } catch (error) {
      // A cursor the blob store no longer takes would fail every run right here. The cursor only
      // decides where a run looks, never what it deletes, so the next run starts from the first page.
      if (cursor !== undefined) {
        await moveListing(ctx.store, held, undefined).then(
          () => logEvent("docsweep_cursor_reset"),
          () => logEvent("docsweep_cursor_unreset"),
        );
      }
      throw error;
    }
    const doomed: string[] = [];
    const due: NamedBlob[] = [];
    for (const blob of listed.blobs) {
      if (!blob.pathname.startsWith(PREFIX)) continue;
      const age = ctx.now - blob.uploadedAt;
      const hex = HEX_NAME.exec(blob.pathname)?.[1];
      if (hex === undefined) {
        if (age > SWEEP_AGE_MS) doomed.push(blob.pathname);
        // A missing mark means "not posted" only once the scan has read every block up to two hours
        // after the upload; a scan that is behind, or starting over, leaves the blob alone.
      } else if (scanned !== undefined && age > DOCUMENT_KEEP_MS && blob.uploadedAt + DOCUMENT_KEEP_MS <= scanned.time) {
        due.push({ ...blob, hex });
      }
    }
    const postedMarks = await inBatches(due.map(({ hex }) => hex), (hex) => ctx.store.get(postedKey(hex)));
    const posted: (NamedBlob & { sizes: readonly bigint[] | undefined })[] = [];
    for (const [i, blob] of due.entries()) {
      const mark = postedMarks[i] ?? null;
      if (mark === null) doomed.push(blob.pathname);
      else posted.push({ ...blob, sizes: postedSizes(mark) });
    }
    const verified = await inBatches(posted.map(({ hex }) => hex), (hex) => verifiedSize(ctx.store, hex));
    const mismatched: { hex: string; reason: string }[] = [];
    const misfits: { hex: string; size: bigint; sizes: readonly bigint[] }[] = [];
    for (const [i, blob] of posted.entries()) {
      let size = verified[i];
      if (size === undefined) {
        const verdict = await checkPosted(ctx, blob, run);
        if (verdict === undefined) continue;
        if ("unreadable" in verdict) {
          unreadable.push(blob.hex);
          logEvent("document_read_failed", { sha256: blob.hex, reason: verdict.unreadable });
          continue;
        }
        if ("doomed" in verdict) {
          doomed.push(blob.pathname);
          mismatched.push({ hex: blob.hex, reason: verdict.doomed });
          continue;
        }
        size = verdict.size;
      }
      if (blob.sizes !== undefined && !blob.sizes.includes(size)) {
        doomed.push(blob.pathname);
        misfits.push({ hex: blob.hex, size, sizes: blob.sizes });
      } else if (verified[i] === undefined) {
        await ctx.store.setIfAbsent(verifiedKey(blob.hex), size.toString(), VERIFIED_SECONDS);
      }
    }
    if (doomed.length > 0) {
      // The verified mark goes first: left behind, it would vouch for whatever bytes are later written
      // under the freed name, since verify answers from the mark without reading them.
      await inBatches(
        doomed.flatMap((pathname) => HEX_NAME.exec(pathname)?.[1] ?? []),
        (hex) => ctx.store.delete(verifiedKey(hex)),
      );
      await ctx.blobs.delete(doomed, AbortSignal.timeout(STORE_TIMEOUT_MS));
      deleted += doomed.length;
      logEvent("docsweep_deleted", { count: doomed.length });
      for (const { hex, reason } of mismatched) logEvent("document_mismatch_deleted", { sha256: hex, reason });
      for (const { hex, size, sizes } of misfits) logEvent("document_size_mismatch", { sha256: hex, size: Number(size), posted: sizes.join(",") });
    }
    // Moved even past a page with work left on it: a cursor held for unhashed documents would let
    // whoever keeps posting them stop the sweep reaching every name after that page.
    held = await moveListing(ctx.store, held, listed.cursor);
    if (listed.cursor === undefined) break;
    cursor = listed.cursor;
  }
  if (run.deferred > 0) logEvent("docsweep_hash_deferred", { count: run.deferred });
  // Second to the deletes: a failure here is logged and left to the next run, never the run's answer.
  const returned = await settleTokens(ctx, run.outOfTime).catch(() => {
    logEvent("doctoken_settle_failed");
    return 0;
  });
  return { done: "swept", deleted, deferred: run.deferred, unreadable, outOfTime: run.timedOut, returned };
}
