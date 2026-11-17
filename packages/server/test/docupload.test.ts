// Not covered here: a real Vercel Blob store. Whether the store itself enforces the token's
// pathname, content type, size cap and no-overwrite rule, and the headers it serves blobs with
// (C29), was checked in a separate live run on 17 Nov 2026. Also not covered: browser
// multipart uploads and the store's CDN cache after a delete.
import { createHash } from "node:crypto";
import { generateClientTokenFromReadWriteToken, getPayloadFromClientToken } from "@vercel/blob/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryBlobBackend } from "../src/blob.ts";
import {
  DOCUMENT_CAP,
  handleDocumentToken,
  handleDocumentVerify,
  sweepUnverified,
  type DocumentContext,
} from "../src/docupload.ts";
import { MemoryStore } from "../src/store.ts";
import { failingStore } from "./fixtures.ts";

const ORIGIN = "https://store123.public.blob.vercel-storage.com";
const FAKE_STORE_CREDENTIAL = "vercel_blob_rw_store123_notarealsecret";
const NOW = Date.UTC(2026, 10, 17, 10, 0, 0);
const MINUTE = 60_000;

type TestContext = DocumentContext & { blobs: MemoryBlobBackend; store: MemoryStore };

function context(extra: Partial<DocumentContext> = {}): TestContext {
  return {
    clientIp: "203.0.113.7",
    now: NOW,
    store: new MemoryStore({ now: () => NOW }),
    blobs: new MemoryBlobBackend(ORIGIN, { now: () => NOW }),
    env: { BLOB_ORIGIN: ORIGIN, BLOB_READ_WRITE_TOKEN: FAKE_STORE_CREDENTIAL },
    ...extra,
  } as TestContext;
}

function hexOf(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function post(route: "token" | "verify", body: unknown, headers: Record<string, string> = { "content-type": "application/json" }): Request {
  return new Request(`http://app.local/api/documents/${route}`, {
    method: "POST",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function bytesOf(size: number, seed: number): Uint8Array {
  return new Uint8Array(size).map((_, i) => (i * 131 + seed) & 0xff);
}

beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("handleDocumentToken", () => {
  it("issues a token only for a valid sha256, for exactly that pathname, type, size and lifetime", async () => {
    const buildToken = vi.fn(generateClientTokenFromReadWriteToken);
    const ctx = context({ buildToken });
    const hex = hexOf(bytesOf(1_000, 1));
    const response = await handleDocumentToken(post("token", { sha256: hex }), ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    const body = (await response.json()) as { exists: boolean; pathname: string; token: string; validUntil: number };
    expect(body).toMatchObject({ exists: false, pathname: `document/${hex}`, contentType: "application/octet-stream", maxBytes: 26_214_400 });

    expect(buildToken).toHaveBeenCalledTimes(1);
    expect(buildToken.mock.calls[0]?.[0]).toEqual({
      token: FAKE_STORE_CREDENTIAL,
      pathname: `document/${hex}`,
      allowedContentTypes: ["application/octet-stream"],
      maximumSizeInBytes: 26_214_400,
      validUntil: NOW + 10 * MINUTE,
      addRandomSuffix: false,
      allowOverwrite: false,
    });
    const payload = getPayloadFromClientToken(body.token);
    expect(payload).toEqual({
      pathname: `document/${hex}`,
      allowedContentTypes: ["application/octet-stream"],
      maximumSizeInBytes: 26_214_400,
      validUntil: NOW + 10 * MINUTE,
      addRandomSuffix: false,
      allowOverwrite: false,
    });
    expect(body.token).not.toContain("notarealsecret");
    expect(await ctx.store.get(`pending:${hex}`)).toBe(String(NOW));

    const refused: Array<[Request, number]> = [
      [post("token", { sha256: hex.toUpperCase() }), 400],
      [post("token", { sha256: hex.slice(1) }), 400],
      [post("token", { sha256: `0x${hex}` }), 400],
      [post("token", { sha256: hex, pathname: "index.html" }), 400],
      [post("token", {}), 400],
      [post("token", "not json"), 400],
      [post("token", { sha256: hex }, { "content-type": "text/plain" }), 415],
      [post("token", { sha256: hex, pad: "x".repeat(300) }), 413],
      [new Request("http://app.local/api/documents/token"), 405],
    ];
    for (const [request, status] of refused) expect((await handleDocumentToken(request, ctx)).status).toBe(status);
    expect(buildToken).toHaveBeenCalledTimes(1);
  });

  it("answers exists for a pathname that already holds a blob, and issues no token", async () => {
    const buildToken = vi.fn(generateClientTokenFromReadWriteToken);
    const ctx = context({ buildToken, tokenLimits: { perIp: 10, total: 10, windowSeconds: 3600, tokensPerIp: 1 } });
    const bytes = bytesOf(2_000, 2);
    await ctx.blobs.put(`document/${hexOf(bytes)}`, bytes);
    const response = await handleDocumentToken(post("token", { sha256: hexOf(bytes) }), ctx);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ exists: true, url: `${ORIGIN}/document/${hexOf(bytes)}` });
    expect(buildToken).not.toHaveBeenCalled();
    // The exists answer spent none of the one-token budget.
    expect((await handleDocumentToken(post("token", { sha256: hexOf(bytesOf(10, 3)) }), ctx)).status).toBe(200);
    expect(buildToken).toHaveBeenCalledTimes(1);
  });
});

describe("handleDocumentVerify", () => {
  it("accepts bytes that hash to their name, marks them verified, and answers the expected URL", async () => {
    const ctx = context();
    for (const size of [5_000_000, DOCUMENT_CAP]) {
      const bytes = bytesOf(size, size & 0xff);
      const hex = hexOf(bytes);
      await ctx.blobs.put(`document/${hex}`, bytes);
      const response = await handleDocumentVerify(post("verify", { sha256: hex }), ctx);
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ sha256: hex, size, url: `${ORIGIN}/document/${hex}` });
      expect(await ctx.store.get(`verified:${hex}`)).toBe(String(size));
      expect(ctx.blobs.blobs.has(`document/${hex}`)).toBe(true);
    }
  });

  it("deletes and answers 409 on a hash mismatch, over the cap, empty, or missing", async () => {
    const ctx = context({ blobs: new MemoryBlobBackend(ORIGIN, { now: () => NOW, chunkSize: 1_048_576 }) });
    const named = (seed: number) => hexOf(bytesOf(100, seed));

    const swapped = named(10);
    await ctx.blobs.put(`document/${swapped}`, bytesOf(100, 11));
    const big = named(12);
    await ctx.blobs.put(`document/${big}`, new Uint8Array(DOCUMENT_CAP + 3 * 1_048_576));
    const empty = hexOf(new Uint8Array(0));
    await ctx.blobs.put(`document/${empty}`, new Uint8Array(0));
    const missing = named(13);
    const deleted = vi.spyOn(ctx.blobs, "delete");

    for (const [hex, reason] of [[swapped, "hash_mismatch"], [big, "too_large"], [empty, "empty"], [missing, "blob_missing"]] as const) {
      const response = await handleDocumentVerify(post("verify", { sha256: hex }), ctx);
      expect(response.status).toBe(409);
      expect(await response.json()).toEqual({ error: reason });
      expect(deleted).toHaveBeenLastCalledWith([`document/${hex}`], expect.any(AbortSignal));
      expect(ctx.blobs.blobs.has(`document/${hex}`)).toBe(false);
      expect(await ctx.store.get(`verified:${hex}`)).toBeNull();
    }
    // The oversized read stopped at the first piece past the cap, not at the end of the blob.
    expect(ctx.blobs.pulled).toBeGreaterThan(DOCUMENT_CAP);
    expect(ctx.blobs.pulled).toBeLessThanOrEqual(100 + DOCUMENT_CAP + 1_048_576);
  });

  it("answers no URL but the expected one, and deletes nothing on a store mismatch", async () => {
    const bytes = bytesOf(1_000, 4);
    const hex = hexOf(bytes);
    for (const origin of ["https://evil.example", `${ORIGIN}/extra`]) {
      const ctx = context({ blobs: new MemoryBlobBackend(origin, { now: () => NOW }) });
      await ctx.blobs.put(`document/${hex}`, bytes);
      const verify = await handleDocumentVerify(post("verify", { sha256: hex }), ctx);
      expect(verify.status).toBe(502);
      expect(await verify.json()).toEqual({ error: "unexpected_blob_url" });
      expect((await handleDocumentToken(post("token", { sha256: hex }), ctx)).status).toBe(502);
      expect(ctx.blobs.blobs.has(`document/${hex}`)).toBe(true);
      expect(await ctx.store.get(`verified:${hex}`)).toBeNull();
    }
    for (const bad of [`${ORIGIN}/`, "http://store123.public.blob.vercel-storage.com", "https://STORE123.public.blob.vercel-storage.com"]) {
      const ctx = context({ env: { BLOB_ORIGIN: bad, BLOB_READ_WRITE_TOKEN: FAKE_STORE_CREDENTIAL } });
      expect((await handleDocumentVerify(post("verify", { sha256: hex }), ctx)).status).toBe(500);
      expect((await handleDocumentToken(post("token", { sha256: hex }), ctx)).status).toBe(500);
    }
  });

  it("deletes an unverified document past the verify window, and still accepts a verified one", async () => {
    const ctx = context({ blobs: new MemoryBlobBackend(ORIGIN, { now: () => NOW - 51 * MINUTE }) });
    const stale = bytesOf(500, 5);
    const kept = bytesOf(500, 6);
    await ctx.blobs.put(`document/${hexOf(stale)}`, stale);
    await ctx.blobs.put(`document/${hexOf(kept)}`, kept);
    await ctx.store.setIfAbsent(`verified:${hexOf(kept)}`, "500", 3600);
    const late = await handleDocumentVerify(post("verify", { sha256: hexOf(stale) }), ctx);
    expect(late.status).toBe(409);
    expect(await late.json()).toEqual({ error: "too_old" });
    expect(ctx.blobs.blobs.has(`document/${hexOf(stale)}`)).toBe(false);
    expect((await handleDocumentVerify(post("verify", { sha256: hexOf(kept) }), ctx)).status).toBe(200);
  });

  it("answers a verified document from its mark, never reading or deleting it again, even after the store once reads it as missing", async () => {
    const ctx = context();
    const bytes = bytesOf(1_000, 8);
    const hex = hexOf(bytes);
    await ctx.blobs.put(`document/${hex}`, bytes);
    expect((await handleDocumentVerify(post("verify", { sha256: hex }), ctx)).status).toBe(200);

    const read = vi.spyOn(ctx.blobs, "read").mockResolvedValue(null);
    const deleted = vi.spyOn(ctx.blobs, "delete");
    const again = await handleDocumentVerify(post("verify", { sha256: hex }), ctx);
    expect(again.status).toBe(200);
    expect(await again.json()).toEqual({ sha256: hex, size: 1_000, url: `${ORIGIN}/document/${hex}` });
    expect(read).not.toHaveBeenCalled();
    expect(deleted).not.toHaveBeenCalled();
    expect(ctx.blobs.blobs.has(`document/${hex}`)).toBe(true);
  });

  it("answers 504 when the read runs past the timeout, and deletes nothing", async () => {
    const ctx = context({ timeoutMs: 50 });
    const bytes = bytesOf(1_000, 7);
    await ctx.blobs.put(`document/${hexOf(bytes)}`, bytes);
    vi.spyOn(ctx.blobs, "read").mockImplementation(
      (_url, _cap, signal) => new Promise<Uint8Array | null>((_, reject) => signal?.addEventListener("abort", () => reject(signal.reason), { once: true })),
    );
    const deleted = vi.spyOn(ctx.blobs, "delete");
    const response = await handleDocumentVerify(post("verify", { sha256: hexOf(bytes) }), ctx);
    expect(response.status).toBe(504);
    expect(await response.json()).toEqual({ error: "verify_timeout" });
    expect(deleted).not.toHaveBeenCalled();
    expect(ctx.blobs.blobs.has(`document/${hexOf(bytes)}`)).toBe(true);
  });
});

describe("rate limits", () => {
  it("trip per IP and in total for both routes, ignore X-Forwarded-For, and cap tokens per IP", async () => {
    const ctx = context({
      tokenLimits: { perIp: 2, total: 3, windowSeconds: 3600, tokensPerIp: 10 },
      verifyLimits: { perIp: 1, total: 2, windowSeconds: 3600 },
    });
    const json = { "content-type": "application/json" };
    const tokenStatuses: number[] = [];
    for (const [i, forwarded] of ["198.51.100.1", "198.51.100.2", "198.51.100.3"].entries()) {
      tokenStatuses.push((await handleDocumentToken(post("token", { sha256: hexOf(bytesOf(10, i)) }, { ...json, "x-forwarded-for": forwarded }), ctx)).status);
    }
    expect(tokenStatuses).toEqual([200, 200, 429]);
    expect((await handleDocumentToken(post("token", { sha256: hexOf(bytesOf(10, 20)) }), { ...ctx, clientIp: "203.0.113.8" })).status).toBe(200);
    expect((await handleDocumentToken(post("token", { sha256: hexOf(bytesOf(10, 21)) }), { ...ctx, clientIp: "203.0.113.9" })).status).toBe(429);

    const verifyStatus = async (clientIp: string) => (await handleDocumentVerify(post("verify", { sha256: hexOf(bytesOf(10, 30)) }), { ...ctx, clientIp })).status;
    expect([await verifyStatus("203.0.113.7"), await verifyStatus("203.0.113.7"), await verifyStatus("203.0.113.8"), await verifyStatus("203.0.113.9")]).toEqual([409, 429, 409, 429]);

    const budget = context({ tokenLimits: { perIp: 10, total: 10, windowSeconds: 3600, tokensPerIp: 2 } });
    const issued = [40, 41, 42].map((seed) => hexOf(bytesOf(10, seed)));
    const statuses: number[] = [];
    for (const hex of issued) statuses.push((await handleDocumentToken(post("token", { sha256: hex }), budget)).status);
    expect(statuses).toEqual([200, 200, 429]);

    const down = context({ store: failingStore() as MemoryStore });
    expect((await handleDocumentToken(post("token", { sha256: issued[0] }), down)).status).toBe(429);
    expect((await handleDocumentVerify(post("verify", { sha256: issued[0] }), down)).status).toBe(429);
  });
});

describe("sweepUnverified", () => {
  it("deletes only unverified documents older than an hour, across pages, and stops when the store is down", async () => {
    const store = new MemoryStore({ now: () => NOW });
    const blobs = new MemoryBlobBackend(ORIGIN);
    const add = (pathname: string, ageMinutes: number): void => {
      blobs.blobs.set(pathname, new Uint8Array([1]));
      blobs.uploadedAt.set(pathname, NOW - ageMinutes * MINUTE);
    };
    const hexFor = (label: string): string => hexOf(new TextEncoder().encode(label));
    const oldUnverified = Array.from({ length: 150 }, (_, i) => `document/${hexFor(`old-${i}`)}`);
    for (const pathname of oldUnverified) add(pathname, 61);
    const oldVerified = Array.from({ length: 5 }, (_, i) => hexFor(`verified-${i}`));
    for (const hex of oldVerified) {
      add(`document/${hex}`, 600);
      await store.setIfAbsent(`verified:${hex}`, "1", 3600);
    }
    const young = Array.from({ length: 5 }, (_, i) => `document/${hexFor(`young-${i}`)}`);
    for (const pathname of young) add(pathname, 59);
    const envelope = `envelope/${hexFor("envelope")}`;
    add(envelope, 600);
    add("document/not-a-hash", 600);

    expect(await sweepUnverified({ blobs, store, now: NOW })).toBe(151);
    const left = [...blobs.blobs.keys()].sort();
    expect(left).toEqual([...oldVerified.map((hex) => `document/${hex}`), ...young, envelope].sort());
    expect(await sweepUnverified({ blobs, store, now: NOW })).toBe(0);

    const late = `document/${hexFor("late")}`;
    add(late, 120);
    await expect(sweepUnverified({ blobs, store: failingStore(), now: NOW })).rejects.toThrow();
    expect(blobs.blobs.has(late)).toBe(true);
  });
});
