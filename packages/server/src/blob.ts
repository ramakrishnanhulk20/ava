import { MAX_ENVELOPE_SIZE, sha256 } from "@ava/core";
import { parseEnvelope } from "@qorechain/qoreseal";
import { BlobNotFoundError, del, head, list, put } from "@vercel/blob";
import { isHttpsOrigin } from "./env.ts";
import { BodyTimeout, declaredLength, json, readBody, readCapped, refuse, refuseCrossSite, TooLarge, type HandlerContext } from "./http.ts";
import { logEvent } from "./log.ts";
import { hasBudget, limit, spendBudget } from "./ratelimit.ts";
import type { SharedStore } from "./store.ts";

/** What the store reports about one blob. `uploadedAt` is in milliseconds since the epoch. */
export interface BlobInfo {
  pathname: string;
  url: string;
  size: number;
  uploadedAt: number;
}

/** One page of a listing. `cursor` is present only when another page follows. */
export interface BlobPage {
  blobs: BlobInfo[];
  cursor?: string;
}

/** Where uploaded bytes are kept. Pathnames are always `${kind}/${sha256hex}`, chosen by the server. */
export interface BlobBackend {
  exists(pathname: string): Promise<boolean>;
  /** Writes new bytes. Must refuse, never overwrite, when the pathname already holds a blob. */
  put(pathname: string, bytes: Uint8Array): Promise<{ url: string }>;
  /** The blob's details, or null when the pathname holds nothing. Every other store error is thrown. */
  head(pathname: string, signal?: AbortSignal): Promise<BlobInfo | null>;
  /** Deletes every pathname given. A pathname that holds nothing is not an error. */
  delete(pathnames: readonly string[], signal?: AbortSignal): Promise<void>;
  /**
   * One page of at most `limit` blobs whose pathname starts with `prefix`, in pathname order.
   * @throws TypeError for an empty prefix, so a listing can never cover the whole store by mistake.
   */
  list(prefix: string, page: { limit: number; cursor?: string; signal?: AbortSignal }): Promise<BlobPage>;
  /**
   * Reads the bytes served at `url`, the exact URL object the caller checked, stopping the moment
   * they pass `cap`, so nothing past the cap is buffered. Null when nothing is there.
   * @throws TooLarge past the cap; any other failure, a redirect included, as an Error.
   */
  read(url: URL, cap: number, signal?: AbortSignal): Promise<Uint8Array | null>;
}

function checkPrefix(prefix: string): void {
  if (typeof prefix !== "string" || prefix.length === 0) throw new TypeError("A listing needs a non-empty prefix.");
}

async function discard(response: Response): Promise<void> {
  await response.body?.cancel().catch(() => undefined);
}

/**
 * BlobBackend on Vercel Blob. Every blob is written public, under exactly the pathname given (no
 * random suffix), never over an existing one, and as `application/octet-stream` whatever the bytes
 * are, so the store has no reason to serve anything as a page or a script (threat model C28, C29).
 */
export class VercelBlobBackend implements BlobBackend {
  readonly #token: string;

  constructor(token: string) {
    this.#token = token;
  }

  async exists(pathname: string): Promise<boolean> {
    try {
      await head(pathname, { token: this.#token });
      return true;
    } catch (error) {
      if (error instanceof BlobNotFoundError) return false;
      throw error;
    }
  }

  async put(pathname: string, bytes: Uint8Array): Promise<{ url: string }> {
    const result = await put(pathname, Buffer.from(bytes), {
      access: "public",
      addRandomSuffix: false,
      allowOverwrite: false,
      contentType: "application/octet-stream",
      token: this.#token,
    });
    return { url: result.url };
  }

  async head(pathname: string, signal?: AbortSignal): Promise<BlobInfo | null> {
    try {
      const found = await head(pathname, { token: this.#token, abortSignal: signal });
      return { pathname: found.pathname, url: found.url, size: found.size, uploadedAt: found.uploadedAt.getTime() };
    } catch (error) {
      if (error instanceof BlobNotFoundError) return null;
      throw error;
    }
  }

  async delete(pathnames: readonly string[], signal?: AbortSignal): Promise<void> {
    if (pathnames.length === 0) return;
    await del([...pathnames], { token: this.#token, abortSignal: signal });
  }

  async list(prefix: string, page: { limit: number; cursor?: string; signal?: AbortSignal }): Promise<BlobPage> {
    checkPrefix(prefix);
    const result = await list({ prefix, limit: page.limit, cursor: page.cursor, token: this.#token, abortSignal: page.signal });
    const blobs = result.blobs.map((blob) => ({ pathname: blob.pathname, url: blob.url, size: blob.size, uploadedAt: blob.uploadedAt.getTime() }));
    // A store that says "more" without a cursor ends the listing rather than starting it over.
    return result.hasMore && typeof result.cursor === "string" && result.cursor !== "" ? { blobs, cursor: result.cursor } : { blobs };
  }

  /**
   * Fetches the public URL with no credentials. A stated length over the cap is refused before
   * the body is pulled; a missing or wrong length is caught while reading. Redirects are refused,
   * not followed, so the bytes always come from the URL that was checked.
   */
  async read(url: URL, cap: number, signal?: AbortSignal): Promise<Uint8Array | null> {
    if (url.protocol !== "https:") throw new TypeError("Blobs are read over https only.");
    const response = await fetch(url, { redirect: "manual", signal, headers: { accept: "application/octet-stream" } });
    if (response.status === 404) {
      await discard(response);
      return null;
    }
    if (response.status !== 200 || response.body === null) {
      await discard(response);
      throw new Error(`The blob store answered ${response.status}.`);
    }
    const stated = response.headers.get("content-length");
    if (stated !== null && /^\d{1,16}$/.test(stated) && Number(stated) > cap) {
      await discard(response);
      throw new TooLarge();
    }
    return readCapped(response.body, cap, signal);
  }
}

/** BlobBackend in process memory, for tests only. Refuses to exist when NODE_ENV is "production". */
export class MemoryBlobBackend implements BlobBackend {
  readonly blobs = new Map<string, Uint8Array>();
  /** When each blob was written, in milliseconds. Tests set it to age a blob; a blob with none counts as written at 0. */
  readonly uploadedAt = new Map<string, number>();
  /** Bytes every read so far has pulled from the stored blobs, so tests can see a read stop at its cap. */
  pulled = 0;
  readonly #origin: string;
  readonly #now: () => number;
  readonly #chunkSize: number;

  /**
   * @param origin The origin its URLs start with. Tests pass a wrong one to prove the URL check.
   * @param options.now The clock that stamps each write, in milliseconds. Defaults to Date.now.
   * @param options.chunkSize Bytes per piece a read hands out, 65,536 by default. Reads state no
   *   length, so only the cap while reading can stop them.
   */
  constructor(origin: string, options: { now?: () => number; chunkSize?: number } = {}) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("MemoryBlobBackend is for tests only and cannot be used when NODE_ENV is production.");
    }
    this.#origin = origin;
    this.#now = options.now ?? Date.now;
    this.#chunkSize = options.chunkSize ?? 65_536;
  }

  async exists(pathname: string): Promise<boolean> {
    return this.blobs.has(pathname);
  }

  async put(pathname: string, bytes: Uint8Array): Promise<{ url: string }> {
    if (this.blobs.has(pathname)) throw new Error("This blob already exists.");
    this.blobs.set(pathname, Uint8Array.from(bytes));
    this.uploadedAt.set(pathname, this.#now());
    return { url: `${this.#origin}/${pathname}` };
  }

  async head(pathname: string): Promise<BlobInfo | null> {
    const bytes = this.blobs.get(pathname);
    if (bytes === undefined) return null;
    return { pathname, url: `${this.#origin}/${pathname}`, size: bytes.byteLength, uploadedAt: this.uploadedAt.get(pathname) ?? 0 };
  }

  async delete(pathnames: readonly string[]): Promise<void> {
    for (const pathname of pathnames) {
      this.blobs.delete(pathname);
      this.uploadedAt.delete(pathname);
    }
  }

  async list(prefix: string, page: { limit: number; cursor?: string }): Promise<BlobPage> {
    checkPrefix(prefix);
    if (!Number.isSafeInteger(page.limit) || page.limit < 1) throw new TypeError("A page limit is a whole number of at least 1.");
    const after = page.cursor;
    const names = [...this.blobs.keys()].filter((name) => name.startsWith(prefix) && (after === undefined || name > after)).sort();
    const taken = names.slice(0, page.limit);
    const blobs: BlobInfo[] = [];
    for (const name of taken) {
      const info = await this.head(name);
      if (info !== null) blobs.push(info);
    }
    const last = taken.at(-1);
    return names.length > taken.length && last !== undefined ? { blobs, cursor: last } : { blobs };
  }

  async read(url: URL, cap: number, signal?: AbortSignal): Promise<Uint8Array | null> {
    const base = `${this.#origin}/`;
    if (!url.href.startsWith(base)) return null;
    const bytes = this.blobs.get(url.href.slice(base.length));
    if (bytes === undefined) return null;
    let offset = 0;
    const stream = new ReadableStream<Uint8Array>(
      {
        pull: (controller) => {
          if (offset >= bytes.byteLength) {
            controller.close();
            return;
          }
          const piece = bytes.slice(offset, offset + this.#chunkSize);
          offset += piece.byteLength;
          this.pulled += piece.byteLength;
          controller.enqueue(piece);
        },
      },
      // No queue ahead of the reader: every byte counted in `pulled` is one the reader asked for.
      { highWaterMark: 0 },
    );
    return readCapped(stream, cap, signal);
  }
}

export interface UploadContext extends HandlerContext {
  blobs: BlobBackend;
  /** BLOB_ORIGIN from loadEnv: the public origin every returned URL must start with. */
  blobOrigin: string;
  /** Overrides UPLOAD_LIMITS. */
  limits?: { perIp: number; total: number; windowSeconds: number; bytesPerIp: number };
  /**
   * Set only by server code for an upload it makes itself (the demo bot's joins, its scheduled guest
   * removals), never from anything in a request. The upload then skips the cross-site check and
   * every per-IP and anonymous limit, and counts against INTERNAL_UPLOAD_LIMITS for its own scope.
   */
  internal?: "demo-bot" | "sweep";
}

/**
 * The largest upload of each kind this endpoint takes, equal to the largest the registry records.
 * Envelopes only: documents go through the document token and verify path in docupload.ts.
 */
export const UPLOAD_CAPS = { envelope: MAX_ENVELOPE_SIZE } as const;

/**
 * Per hour: uploads per IP, and per IP the bytes of 20 of the largest envelopes. The total is 50
 * times the per-IP limit, so only an attacker with 50 or more addresses can reach it and stop
 * everyone's uploads (docs/security/runbook.md, Known limits).
 */
export const UPLOAD_LIMITS = { perIp: 20, total: 1_000, windowSeconds: 3600, bytesPerIp: 20 * MAX_ENVELOPE_SIZE } as const;

/**
 * Per UTC day, for each internal scope on its own: the server's own uploads. A demo join or a guest
 * removal uploads one envelope, and the demo admits at most 120 guests a day (DEMO_JOIN_LIMITS.perDay
 * in config.ts), so 600 is five times what a full day needs. Anonymous traffic can never spend it.
 */
export const INTERNAL_UPLOAD_LIMITS = { perDay: 600 } as const;

const INTERNAL_SCOPES: ReadonlySet<string> = new Set(["demo-bot", "sweep"]);
// The key is named for its UTC day, so it lives two days and a new day always starts a new count.
const INTERNAL_DAY_KEY_SECONDS = 2 * 86_400;

/** Counts one server-side upload against its scope's budget for the UTC day. False, never a throw, on a store error. */
async function countInternal(store: SharedStore, scope: string, now: number): Promise<boolean> {
  try {
    const day = new Date(now).toISOString().slice(0, 10);
    if ((await store.incrWindow(`rate:upload:internal:${scope}:${day}`, INTERNAL_DAY_KEY_SECONDS)) <= INTERNAL_UPLOAD_LIMITS.perDay) return true;
    logEvent("rate_limited", { scope: "upload", internal: scope, reason: "per_day" });
  } catch {
    logEvent("rate_refused", { scope: "upload", internal: scope, reason: "store_error" });
  }
  return false;
}

/** Seconds from `now` (milliseconds since the epoch) to the next UTC midnight, for a retry-after; 60 for a clock that gives no sane answer. */
export function secondsToUtcMidnight(now: number): number {
  const next = new Date(now);
  next.setUTCHours(24, 0, 0, 0);
  const seconds = Math.ceil((next.getTime() - now) / 1000);
  return Number.isSafeInteger(seconds) && seconds > 0 ? seconds : 60;
}

type Kind = keyof typeof UPLOAD_CAPS;

function kindOf(request: Request): Kind | undefined {
  const { search } = new URL(request.url);
  return search === "?kind=envelope" ? "envelope" : undefined;
}

/** Both sides through the one URL parser, so case, encoding or a trailing part can never slip past. */
export function sameUrl(given: string, expected: string): boolean {
  try {
    const a = new URL(given);
    const b = new URL(expected);
    return a.href === b.href && a.search === "" && a.hash === "";
  } catch {
    return false;
  }
}

/**
 * Stores an encrypted epoch-key envelope under the SHA-256 of the bytes the server received
 * (threat model C23, C28, C29, C30). Documents are not taken here: they go through docupload.ts.
 *
 * First of all, a request another site's page could have sent is refused with 403 `cross_site`
 * (refuseCrossSite), and a content type other than exactly `application/octet-stream` with 415
 * `content_type`; neither is counted, read or stored. The query is exactly `kind=envelope`;
 * `kind=document` and anything else is refused with 400. Any name or path the client sends is
 * ignored. The body is read as a stream, refused with 413 the moment it passes the 110,000-byte
 * cap, before more is buffered, and with 408 `body_timeout` when it has not ended after 20 seconds.
 * Bytes that QoreSeal's parseEnvelope does not accept as an envelope are refused with 400
 * `not_an_envelope` and never stored, after they are counted against the IP's byte budget. An
 * existing blob is never written again: the answer is 200 with its URL. A new one is 201. Either
 * way the body is `{ sha256, size, url }`, with `sha256` as 64 lowercase hex characters and `url`
 * checked to equal `${blobOrigin}/${kind}/${sha256}` before it is returned, because the chair will
 * sign it and a signed URL stays on chain.
 *
 * With `ctx.internal` set by server code, the cross-site check and every per-IP and anonymous
 * limit are skipped, and the upload counts against INTERNAL_UPLOAD_LIMITS for that scope instead.
 *
 * Refuses with 403 cross-site, 405 for another method, 415 for another content type, 400 for a bad
 * query, an empty body or bytes that are not an envelope, 408 for a body that does not end, 413
 * over the cap, 429 over the request limits, the hourly per-IP byte budget or an internal scope's
 * day (or when they cannot be checked), 500 for an unknown internal scope or a malformed
 * BLOB_ORIGIN, and 502 when the store fails or answers with any other URL.
 */
export async function handleUpload(request: Request, ctx: UploadContext): Promise<Response> {
  // Server code builds its own request when it sets `internal`, so there is no browser to check.
  const crossSite = ctx.internal === undefined ? refuseCrossSite(request) : undefined;
  if (crossSite !== undefined) return crossSite;
  if (request.method !== "POST") return refuse(405, "method_not_allowed", { allow: "POST" });
  // A form or a beacon can only send a few simple types, so requiring this one shuts both out.
  if (request.headers.get("content-type") !== "application/octet-stream") return refuse(415, "content_type");
  if (ctx.internal !== undefined && !INTERNAL_SCOPES.has(ctx.internal)) {
    logEvent("upload_refused", { reason: "bad_internal_scope" });
    return refuse(500, "server_misconfigured");
  }
  const rules = ctx.limits ?? UPLOAD_LIMITS;
  const retry = (seconds: number) => ({ "retry-after": String(seconds) });
  if (ctx.internal === undefined) {
    const verdict = await limit(ctx.store, { scope: "upload", clientIp: ctx.clientIp, ...rules });
    if (!verdict.ok) return refuse(429, "rate_limited", retry(verdict.retryAfter));
  } else if (!(await countInternal(ctx.store, ctx.internal, ctx.now))) {
    return refuse(429, "rate_limited", retry(secondsToUtcMidnight(ctx.now)));
  }
  const kind = kindOf(request);
  if (kind === undefined) return refuse(400, "bad_kind");
  if (!isHttpsOrigin(ctx.blobOrigin)) {
    logEvent("upload_refused", { reason: "bad_blob_origin" });
    return refuse(500, "server_misconfigured");
  }
  const cap = UPLOAD_CAPS[kind];
  const stated = declaredLength(request);
  if (stated !== undefined && stated > cap) return refuse(413, "body_too_large");
  const budget = ctx.internal === undefined ? { scope: "upload", clientIp: ctx.clientIp, max: rules.bytesPerIp, windowSeconds: rules.windowSeconds } : undefined;
  if (budget !== undefined) {
    const left = await hasBudget(ctx.store, budget);
    if (!left.ok) return refuse(429, "byte_budget_spent", retry(left.retryAfter));
  }
  if (request.body === null) return refuse(400, "empty_body");

  let bytes: Uint8Array;
  try {
    bytes = await readBody(request.body, cap);
  } catch (error) {
    const reason = error instanceof TooLarge ? "too_large" : error instanceof BodyTimeout ? "body_timeout" : "unreadable";
    logEvent("upload_refused", { kind, reason });
    if (error instanceof TooLarge) return refuse(413, "body_too_large");
    return error instanceof BodyTimeout ? refuse(408, "body_timeout") : refuse(400, "bad_body");
  }
  if (bytes.byteLength === 0) return refuse(400, "empty_body");
  if (budget !== undefined) {
    const spent = await spendBudget(ctx.store, budget, bytes.byteLength);
    if (!spent.ok) return refuse(429, "byte_budget_spent", retry(spent.retryAfter));
  }
  // QoreSeal's own parser decides what an envelope is, so the store holds nothing else. It reads
  // the header and the recipient entries; it cannot tell whether the payload will decrypt.
  try {
    parseEnvelope(bytes);
  } catch {
    logEvent("upload_refused", { kind, reason: "not_an_envelope" });
    return refuse(400, "not_an_envelope");
  }

  const hex = Buffer.from(sha256(bytes)).toString("hex");
  const pathname = `${kind}/${hex}`;
  const expected = `${ctx.blobOrigin}/${pathname}`;
  const answer = (status: 200 | 201) => json(status, { sha256: hex, size: bytes.byteLength, url: expected });

  try {
    if (await ctx.blobs.exists(pathname)) return answer(200);
  } catch {
    logEvent("upload_refused", { kind, reason: "store_failed" });
    return refuse(502, "store_failed");
  }
  let stored: { url: string };
  try {
    stored = await ctx.blobs.put(pathname, bytes);
  } catch {
    // The same pathname means the same bytes, so a parallel upload that won the race is a success.
    const raced = await ctx.blobs.exists(pathname).catch(() => false);
    if (raced) return answer(200);
    logEvent("upload_refused", { kind, reason: "store_failed" });
    return refuse(502, "store_failed");
  }
  if (!sameUrl(stored.url, expected)) {
    logEvent("upload_refused", { kind, reason: "unexpected_blob_url" });
    return refuse(502, "unexpected_blob_url");
  }
  return answer(201);
}
