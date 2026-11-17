import { MAX_CIPHER_SIZE, sameHash, sha256 } from "@ava/core";
import { generateClientTokenFromReadWriteToken, type GenerateClientTokenOptions } from "@vercel/blob/client";
import { z } from "zod";
import { sameUrl, type BlobBackend, type BlobInfo } from "./blob.ts";
import { isHttpsOrigin, type ServerEnv } from "./env.ts";
import { declaredLength, json, readCapped, refuse, TooLarge, type HandlerContext } from "./http.ts";
import { logEvent } from "./log.ts";
import { limit, spendBudget } from "./ratelimit.ts";
import type { SharedStore } from "./store.ts";

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
/** How long the "pending:" record of an issued token is kept. */
export const PENDING_SECONDS = 3600;
/**
 * The shared store gives every write a lifetime, so a "verified:" mark is written for ten years,
 * which outlives the project.
 */
export const VERIFIED_SECONDS = 315_360_000;
/** The whole verify (look up, read up to 25 MiB, hash) must finish within this. */
export const VERIFY_TIMEOUT_MS = 30_000;
/**
 * An unverified document older than this can no longer be verified and is deleted when asked.
 * The gap to SWEEP_AGE_MS is far longer than a verify can take, so a verify and the sweep never
 * work on the same blob at once: the sweep cannot delete a blob a verify is about to approve.
 */
export const VERIFY_WINDOW_MS = 50 * 60_000;
/** The sweep deletes unverified documents older than this. */
export const SWEEP_AGE_MS = 60 * 60_000;
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

const BODY_CAP = 256;
const STORE_TIMEOUT_MS = 10_000;
// A listing page and a delete batch of 100 stay well inside the store's request limits. Fifty pages
// bound one sweep to 5,000 documents; each page costs at most 100 mark lookups, 20 at a time, and
// one delete.
const SWEEP_PAGE_SIZE = 100;
const SWEEP_MAX_PAGES = 50;
const SWEEP_PARALLEL = 20;

const HashBody = z.strictObject({ sha256: z.string().regex(/^[0-9a-f]{64}$/) });
const HEX_NAME = /^document\/([0-9a-f]{64})$/;

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
  /** Milliseconds since the epoch, from the scheduler's clock. */
  now: number;
}

interface Target {
  hex: string;
  pathname: string;
  url: URL;
}

const pendingKey = (hex: string): string => `pending:${hex}`;
const verifiedKey = (hex: string): string => `verified:${hex}`;
const retry = (seconds: number): Record<string, string> => ({ "retry-after": String(seconds) });

/**
 * The 32 bytes the caller names, from a JSON body of exactly `{ "sha256": "<64 lowercase hex>" }`,
 * or the refusal to send. The pathname, the store keys and the hash comparison all come from these
 * bytes, so no second parser can disagree with the first.
 */
async function readHash(request: Request): Promise<Uint8Array | Response> {
  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") return refuse(415, "json_only");
  const stated = declaredLength(request);
  if (stated !== undefined && stated > BODY_CAP) return refuse(413, "body_too_large");
  if (request.body === null) return refuse(400, "bad_body");
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readCapped(request.body, BODY_CAP)));
  } catch (error) {
    return error instanceof TooLarge ? refuse(413, "body_too_large") : refuse(400, "bad_body");
  }
  const checked = HashBody.safeParse(parsed);
  if (!checked.success) return refuse(400, "bad_sha256");
  return Uint8Array.from(Buffer.from(checked.data.sha256, "hex"));
}

/** Where a document with this hash lives, or undefined when BLOB_ORIGIN is not an https origin. */
function targetOf(hash: Uint8Array, blobOrigin: string): Target | undefined {
  if (!isHttpsOrigin(blobOrigin)) return undefined;
  const hex = Buffer.from(hash).toString("hex");
  const pathname = `${PREFIX}${hex}`;
  return { hex, pathname, url: new URL(`${blobOrigin}/${pathname}`) };
}

/**
 * Issues a short-lived token that lets the browser write one document straight to the blob store
 * (threat model C28, C29).
 *
 * The body is `{ sha256 }`, the SHA-256 of the ciphertext as 64 lowercase hex characters, sent as
 * `application/json`. The token allows a write to exactly `document/<sha256>`, only as
 * `application/octet-stream`, at most 26,214,400 bytes, with no random suffix and never over an
 * existing blob, for ten minutes. The browser then calls the client `put` from
 * `@vercel/blob/client` with `{ access: "public", token, contentType }`, and must call
 * handleDocumentVerify before anything is signed.
 *
 * Answers 200 `{ exists: true, url }` when that pathname already holds a blob: no token is issued
 * and the browser skips the upload and verifies. Otherwise 200 `{ exists: false, pathname, token,
 * contentType, maxBytes, validUntil }`, after a "pending:<sha256>" record (one hour) is written.
 *
 * Refuses with 405 for another method, 415 for another content type, 413 for a body over 256
 * bytes, 400 for any other body, 429 over the request limits or the hourly per-IP token count (or
 * when they cannot be checked), 500 when BLOB_ORIGIN is malformed or no token can be built, 502
 * when the store fails or reports any other URL, and 503 when the record cannot be written.
 */
export async function handleDocumentToken(request: Request, ctx: DocumentContext): Promise<Response> {
  if (request.method !== "POST") return refuse(405, "method_not_allowed", { allow: "POST" });
  const rules = ctx.tokenLimits ?? DOCUMENT_TOKEN_LIMITS;
  const verdict = await limit(ctx.store, { scope: "doctoken", clientIp: ctx.clientIp, perIp: rules.perIp, total: rules.total, windowSeconds: rules.windowSeconds });
  if (!verdict.ok) return refuse(429, "rate_limited", retry(verdict.retryAfter));
  const hash = await readHash(request);
  if (hash instanceof Response) return hash;
  const target = targetOf(hash, ctx.env.BLOB_ORIGIN);
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
  try {
    await ctx.store.setIfAbsent(pendingKey(target.hex), String(ctx.now), PENDING_SECONDS);
  } catch {
    logEvent("doctoken_refused", { reason: "store_failed" });
    return refuse(503, "store_failed");
  }

  const validUntil = ctx.now + DOCUMENT_TOKEN_SECONDS * 1000;
  let token: unknown;
  try {
    token = await (ctx.buildToken ?? generateClientTokenFromReadWriteToken)({
      token: ctx.env.BLOB_READ_WRITE_TOKEN,
      pathname: target.pathname,
      allowedContentTypes: [DOCUMENT_CONTENT_TYPE],
      maximumSizeInBytes: DOCUMENT_CAP,
      validUntil,
      addRandomSuffix: false,
      allowOverwrite: false,
    });
  } catch {
    token = undefined;
  }
  if (typeof token !== "string" || !token.startsWith("vercel_blob_client_")) {
    logEvent("doctoken_refused", { reason: "token_failed" });
    return refuse(500, "token_failed");
  }
  logEvent("doctoken_issued");
  return json(200, { exists: false, pathname: target.pathname, token, contentType: DOCUMENT_CONTENT_TYPE, maxBytes: DOCUMENT_CAP, validUntil });
}

/**
 * Reads a browser-uploaded document back from the blob origin and keeps it only if its SHA-256 is
 * its name (threat model C28, C30, C44). Run it after every upload, and before the chair signs the URL.
 *
 * The body is `{ sha256 }` as for handleDocumentToken. The bytes are streamed from
 * `${BLOB_ORIGIN}/document/<sha256>` (the URL the store reports must equal that form, parsed by
 * the same URL parser), stopping at 26,214,400 bytes, all within 30 seconds, then hashed.
 *
 * A document that already has its "verified:<sha256>" mark is answered 200 from the mark alone: it
 * is never read or deleted again (threat model C44). Otherwise it answers 200 `{ sha256, size, url }`
 * on a match and writes the mark. Deletes the blob and answers 409 `{ error }` when it is missing
 * ("blob_missing"), over the cap ("too_large"), empty ("empty"), not the hash it is named for
 * ("hash_mismatch"), or older than 50 minutes ("too_old", because the sweep will take it).
 *
 * Refuses without deleting: 405, 415, 413, 400 and 429 as for handleDocumentToken (rate scope
 * "docverify"), 500 when BLOB_ORIGIN is malformed, 502 when the store fails or reports another URL,
 * 503 when the shared store fails or holds a mark that is not a size within the cap, 504 on timeout.
 */
export async function handleDocumentVerify(request: Request, ctx: DocumentContext): Promise<Response> {
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

  // Once verified, never deleted (threat model C44): the mark is the answer, so a later read that
  // fails or comes back empty can never take an approved document away.
  let mark: string | null;
  try {
    mark = await ctx.store.get(verifiedKey(target.hex));
  } catch {
    logEvent("docverify_refused", { reason: "shared_store_failed" });
    return refuse(503, "store_failed");
  }
  if (mark !== null) {
    const size = /^[1-9][0-9]{0,8}$/.test(mark) ? Number(mark) : 0;
    if (size < 1 || size > DOCUMENT_CAP) {
      logEvent("docverify_refused", { reason: "bad_verified_mark" });
      return refuse(503, "store_failed");
    }
    return json(200, { sha256: target.hex, size, url: target.url.href });
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
  if (found === null) return reject("blob_missing");
  if (!sameUrl(found.url, target.url.href)) {
    logEvent("docverify_refused", { reason: "unexpected_blob_url" });
    return refuse(502, "unexpected_blob_url");
  }
  if (ctx.now - found.uploadedAt > VERIFY_WINDOW_MS) return reject("too_old");

  let bytes: Uint8Array | null;
  try {
    bytes = await ctx.blobs.read(target.url, DOCUMENT_CAP, signal);
  } catch (error) {
    if (error instanceof TooLarge) return reject("too_large");
    return failed();
  }
  if (bytes === null) return reject("blob_missing");
  if (bytes.byteLength === 0) return reject("empty");
  if (!sameHash(sha256(bytes), hash)) return reject("hash_mismatch");

  try {
    await ctx.store.setIfAbsent(verifiedKey(target.hex), String(bytes.byteLength), VERIFIED_SECONDS);
  } catch {
    logEvent("docverify_refused", { reason: "shared_store_failed" });
    return refuse(503, "store_failed");
  }
  return json(200, { sha256: target.hex, size: bytes.byteLength, url: target.url.href });
}

/**
 * Deletes every document blob older than an hour that has no "verified:" mark, and returns how
 * many it deleted (threat model C28). Anything under `document/` that is not named by a 64-hex
 * hash can never be verified, so it goes too. Meant for a schedule; safe to run alongside verify
 * because of VERIFY_WINDOW_MS.
 *
 * One run covers at most 5,000 documents in pathname order. A shared store or blob store failure
 * stops the run and is thrown, and nothing is deleted for the page that failed.
 */
export async function sweepUnverified(ctx: SweepContext): Promise<number> {
  let cursor: string | undefined;
  let deleted = 0;
  for (let page = 0; page < SWEEP_MAX_PAGES; page++) {
    const listed = await ctx.blobs.list(PREFIX, { limit: SWEEP_PAGE_SIZE, cursor, signal: AbortSignal.timeout(STORE_TIMEOUT_MS) });
    const old = listed.blobs.filter((blob) => blob.pathname.startsWith(PREFIX) && ctx.now - blob.uploadedAt > SWEEP_AGE_MS);
    const doomed: string[] = [];
    for (let start = 0; start < old.length; start += SWEEP_PARALLEL) {
      const batch = old.slice(start, start + SWEEP_PARALLEL);
      const marks = await Promise.all(
        batch.map((blob) => {
          const hex = HEX_NAME.exec(blob.pathname)?.[1];
          return hex === undefined ? Promise.resolve(null) : ctx.store.get(verifiedKey(hex));
        }),
      );
      batch.forEach((blob, i) => {
        if (marks[i] === null) doomed.push(blob.pathname);
      });
    }
    if (doomed.length > 0) {
      await ctx.blobs.delete(doomed, AbortSignal.timeout(STORE_TIMEOUT_MS));
      deleted += doomed.length;
      logEvent("docsweep_deleted", { count: doomed.length });
    }
    if (listed.cursor === undefined) break;
    cursor = listed.cursor;
  }
  return deleted;
}
