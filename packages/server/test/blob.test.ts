// Not covered here: a real Vercel Blob store. How it serves blobs (separate origin, attachment,
// nosniff, sandbox CSP) is the hosting layer's part of C29 and is checked live. Deleting envelopes
// no board references is test/envelopeSweep.test.ts. VercelBlobBackend is checked against a mocked
// @vercel/blob and a stubbed fetch.
import { createHash } from "node:crypto";
import { generateSealKeys, seal } from "@qorechain/qoreseal";
import * as vercelBlob from "@vercel/blob";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { INTERNAL_UPLOAD_LIMITS, MemoryBlobBackend, UPLOAD_CAPS, VercelBlobBackend, handleUpload, type UploadContext } from "../src/blob.ts";
import { uploadEnvelope } from "../src/demoBoard.ts";
import { TooLarge } from "../src/http.ts";
import { MemoryStore } from "../src/store.ts";
import { APP_HEADERS, CROSS_SITE_HEADERS, failingStore, stalledBody } from "./fixtures.ts";

vi.mock("@vercel/blob", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@vercel/blob")>()),
  del: vi.fn(),
  head: vi.fn(),
  list: vi.fn(),
  put: vi.fn(),
}));

const ORIGIN = "https://store123.public.blob.vercel-storage.com";

function hexOf(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

const RECIPIENT = generateSealKeys();
/** One ML-KEM-only recipient: the fixed header, its 1,632-byte entry, the nonce and the tag. */
const SMALLEST_ENVELOPE = 1_688;

/** A real QoreSeal envelope of exactly `size` bytes, its payload filled with `seed`. */
function envelopeOf(seed: number, size = 1_700): Uint8Array<ArrayBuffer> {
  const plaintext = new Uint8Array(size - SMALLEST_ENVELOPE).fill(seed);
  return Uint8Array.from(seal({ chainId: "qorechain-diana", purpose: "blob-test", recipients: [{ mlkemPublicKey: RECIPIENT.mlkemPublicKey }], plaintext, mode: "mlkem" }));
}

function context(extra: Partial<UploadContext> = {}): UploadContext {
  return { clientIp: "203.0.113.7", now: Date.now(), store: new MemoryStore(), blobs: new MemoryBlobBackend(ORIGIN), blobOrigin: ORIGIN, ...extra };
}

/** An upload as our app sends it; `headers` adds to or replaces those headers. */
function upload(kind: string, body: BodyInit | null, headers: Record<string, string> = {}): Request {
  return new Request(`http://app.local/api/upload?kind=${kind}`, {
    method: "POST",
    body,
    headers: { ...APP_HEADERS, "content-type": "application/octet-stream", ...headers },
    duplex: "half",
  } as RequestInit);
}

/**
 * An endless stream of `chunk`-byte pieces that counts every byte it was asked for. Its queue size
 * is 0, so it never pulls ahead on its own: every counted byte is one the handler asked to read.
 */
function countingStream(chunk: number) {
  const counter = { pulled: 0, cancelled: false };
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        counter.pulled += chunk;
        controller.enqueue(new Uint8Array(chunk).fill(7));
      },
      cancel() {
        counter.cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  return { stream, counter };
}

beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("handleUpload", () => {
  it("stores an envelope under the hash of the bytes received", async () => {
    const ctx = context();
    const bytes = envelopeOf(1);
    const response = await handleUpload(upload("envelope", bytes), ctx);
    expect(response.status).toBe(201);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    const hex = hexOf(bytes);
    expect(await response.json()).toEqual({ sha256: hex, size: 1_700, url: `${ORIGIN}/envelope/${hex}` });
    expect((ctx.blobs as MemoryBlobBackend).blobs.get(`envelope/${hex}`)).toEqual(bytes);
  });

  it("refuses kind=document with 400 and stores nothing: documents use the token and verify path", async () => {
    const ctx = context();
    const put = vi.spyOn(ctx.blobs, "put");
    const response = await handleUpload(upload("document", new Uint8Array(300_000).fill(5)), ctx);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "bad_kind" });
    expect(put).not.toHaveBeenCalled();
    expect(Object.keys(UPLOAD_CAPS)).toEqual(["envelope"]);
  });

  it("ignores a client name and path, and refuses any query but kind", async () => {
    const ctx = context();
    const put = vi.spyOn(ctx.blobs, "put");
    const bytes = envelopeOf(2);
    const response = await handleUpload(
      upload("envelope", bytes, {
        "content-disposition": 'inline; filename="../../index.html"',
        "x-vercel-blob-pathname": "index.html",
        "x-filename": "evil.svg",
      }),
      ctx,
    );
    expect(response.status).toBe(201);
    expect(put).toHaveBeenCalledTimes(1);
    expect(put.mock.calls[0]).toEqual([`envelope/${hexOf(bytes)}`, bytes]);
    for (const query of ["envelope&name=evil.html", "document", "other", "envelope&kind=document", "Envelope", "%65nvelope"]) {
      expect((await handleUpload(upload(query, bytes), ctx)).status).toBe(400);
    }
    const octet = { ...APP_HEADERS, "content-type": "application/octet-stream" };
    expect((await handleUpload(new Request("http://app.local/api/upload", { method: "POST", body: bytes, headers: octet }), ctx)).status).toBe(400);
    expect((await handleUpload(new Request("http://app.local/api/upload?kind=envelope", { headers: APP_HEADERS }), ctx)).status).toBe(405);
    expect(put).toHaveBeenCalledTimes(1);
  });

  it("refuses bytes that do not parse as a QoreSeal envelope, and stores nothing", async () => {
    const ctx = context();
    const put = vi.spyOn(ctx.blobs, "put");
    const real = envelopeOf(6);
    const wrongVersion = Uint8Array.from(real);
    wrongVersion[4] = 0xff;
    const notEnvelopes = [new TextEncoder().encode("<script>alert(1)</script>"), new Uint8Array(1_700).fill(7), real.slice(0, 40), wrongVersion];
    for (const bytes of notEnvelopes) {
      const response = await handleUpload(upload("envelope", bytes), ctx);
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "not_an_envelope" });
    }
    expect(put).not.toHaveBeenCalled();
    expect((await handleUpload(upload("envelope", real), ctx)).status).toBe(201);
  });

  it("never writes an existing blob again", async () => {
    const ctx = context();
    const put = vi.spyOn(ctx.blobs, "put");
    const bytes = envelopeOf(9);
    const first = await handleUpload(upload("envelope", bytes), ctx);
    const second = await handleUpload(upload("envelope", bytes), ctx);
    expect(first.status).toBe(201);
    expect(second.status).toBe(200);
    expect(await second.json()).toEqual(await first.json());
    expect(put).toHaveBeenCalledTimes(1);
  });

  it("accepts exactly the cap and refuses one byte more", async () => {
    const ctx = context();
    expect((await handleUpload(upload("envelope", envelopeOf(3, UPLOAD_CAPS.envelope)), ctx)).status).toBe(201);
    expect((await handleUpload(upload("envelope", new Uint8Array(UPLOAD_CAPS.envelope + 1)), ctx)).status).toBe(413);
  });

  it("stops reading the moment the cap is passed, before the rest of the body is pulled", async () => {
    for (const chunk of [16_384, 65_536]) {
      const ctx = context();
      const put = vi.spyOn(ctx.blobs, "put");
      const { stream, counter } = countingStream(chunk);
      const response = await handleUpload(upload("envelope", stream), ctx);
      expect(response.status).toBe(413);
      expect(counter.pulled).toBeGreaterThan(UPLOAD_CAPS.envelope);
      expect(counter.pulled).toBeLessThanOrEqual(UPLOAD_CAPS.envelope + chunk);
      expect(counter.cancelled).toBe(true);
      expect(put).not.toHaveBeenCalled();
    }
    const { stream, counter } = countingStream(16_384);
    const stated = await handleUpload(upload("envelope", stream, { "content-length": String(UPLOAD_CAPS.envelope + 1) }), context());
    expect(stated.status).toBe(413);
    expect(counter.pulled).toBe(0);
  });

  it("refuses a URL from the store that is not the expected one", async () => {
    for (const origin of ["https://evil.example", `${ORIGIN}/extra`]) {
      const response = await handleUpload(upload("envelope", envelopeOf(4)), context({ blobs: new MemoryBlobBackend(origin) }));
      expect(response.status).toBe(502);
      expect(await response.json()).toEqual({ error: "unexpected_blob_url" });
    }
    const withQuery: MemoryBlobBackend = new MemoryBlobBackend(ORIGIN);
    vi.spyOn(withQuery, "put").mockImplementation(async (pathname) => ({ url: `${ORIGIN}/${pathname}?download=1` }));
    expect((await handleUpload(upload("envelope", envelopeOf(5)), context({ blobs: withQuery }))).status).toBe(502);
  });

  it("rate limits per IP and in total, ignores X-Forwarded-For, and keeps a per-IP byte budget", async () => {
    const ctx = context({ limits: { perIp: 2, total: 3, windowSeconds: 3600, bytesPerIp: 6_000 } });
    const put = vi.spyOn(ctx.blobs, "put");
    const statuses: number[] = [];
    for (const [i, forwarded] of ["198.51.100.1", "198.51.100.2", "198.51.100.3"].entries()) {
      statuses.push((await handleUpload(upload("envelope", envelopeOf(10 + i), { "x-forwarded-for": forwarded }), ctx)).status);
    }
    expect(statuses).toEqual([201, 201, 429]);
    const other = { ...ctx, clientIp: "203.0.113.8" };
    expect((await handleUpload(upload("envelope", envelopeOf(20)), other)).status).toBe(201);
    expect((await handleUpload(upload("envelope", envelopeOf(21)), { ...ctx, clientIp: "203.0.113.9" })).status).toBe(429);
    expect(put).toHaveBeenCalledTimes(3);

    const budget = context({ limits: { perIp: 10, total: 10, windowSeconds: 3600, bytesPerIp: 2_500 } });
    const budgetPut = vi.spyOn(budget.blobs, "put");
    expect((await handleUpload(upload("envelope", envelopeOf(30)), budget)).status).toBe(201);
    const over = await handleUpload(upload("envelope", envelopeOf(31)), budget);
    expect(over.status).toBe(429);
    expect(await over.json()).toEqual({ error: "byte_budget_spent" });
    expect(budgetPut).toHaveBeenCalledTimes(1);
  });

  it("counts the server's own uploads on a daily budget per scope, never against the anonymous limits", async () => {
    const ctx = context({ limits: { perIp: 1, total: 1, windowSeconds: 3600, bytesPerIp: 2_000 } });
    expect((await handleUpload(upload("envelope", envelopeOf(50)), ctx)).status).toBe(201);
    expect((await handleUpload(upload("envelope", envelopeOf(51)), { ...ctx, clientIp: "203.0.113.8" })).status).toBe(429);

    const bot: UploadContext = { ...ctx, internal: "demo-bot" };
    const envelope = envelopeOf(52);
    expect(await uploadEnvelope(envelope, bot)).toEqual({ hash: `0x${hexOf(envelope)}`, size: 1_700 });
    for (let i = 1; i < INTERNAL_UPLOAD_LIMITS.perDay; i++) await uploadEnvelope(envelope, bot);
    await expect(uploadEnvelope(envelope, bot)).rejects.toMatchObject({ status: 429, reason: "upload_failed" });
    expect(await uploadEnvelope(envelopeOf(53), { ...ctx, internal: "sweep" })).toMatchObject({ size: 1_700 });

    // The bot spent nothing of the anonymous limits, and they still hold for everyone else.
    expect((await handleUpload(upload("envelope", envelopeOf(54)), { ...ctx, clientIp: "203.0.113.9" })).status).toBe(429);
    expect(await ctx.store.get("rate:upload:ip:203.0.113.7")).toBe("1");
    expect(INTERNAL_UPLOAD_LIMITS).toEqual({ perDay: 600 });
    const unknown = await handleUpload(upload("envelope", envelopeOf(55)), { ...ctx, internal: "admin" as never });
    expect(unknown.status).toBe(500);
  });

  it("gives up on a body that has not ended after 20 seconds with 408, and stores nothing", async () => {
    vi.useFakeTimers();
    const ctx = context();
    const put = vi.spyOn(ctx.blobs, "put");
    const body = stalledBody();
    const pending = handleUpload(upload("envelope", body.stream), ctx);
    let settled = false;
    void pending.then(() => (settled = true));
    for (let i = 0; i < 1_000 && !body.waiting(); i++) await Promise.resolve();
    expect(body.waiting()).toBe(true);
    await vi.advanceTimersByTimeAsync(19_999);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    const response = await pending;
    expect(response.status).toBe(408);
    expect(await response.json()).toEqual({ error: "body_timeout" });
    expect(put).not.toHaveBeenCalled();
  });

  it("fails closed when the shared store is down", async () => {
    const ctx = context({ store: failingStore() });
    const put = vi.spyOn(ctx.blobs, "put");
    expect((await handleUpload(upload("envelope", new Uint8Array(10)), ctx)).status).toBe(429);
    expect(put).not.toHaveBeenCalled();
  });

  it("refuses with 403 what a cross-site page can send, before it counts, reads the body or reaches the store", async () => {
    const ctx = context();
    const touched = [vi.spyOn(ctx.store, "incrWindow"), vi.spyOn(ctx.store, "get"), vi.spyOn(ctx.blobs, "exists"), vi.spyOn(ctx.blobs, "put")];
    for (const headers of CROSS_SITE_HEADERS) {
      const { stream, counter } = countingStream(1_024);
      const request = new Request("http://app.local/api/upload?kind=envelope", {
        method: "POST",
        body: stream,
        headers: { "content-type": "application/octet-stream", ...headers },
        duplex: "half",
      } as RequestInit);
      const response = await handleUpload(request, ctx);
      expect({ headers, status: response.status }).toEqual({ headers, status: 403 });
      expect(await response.json()).toEqual({ error: "cross_site" });
      expect(counter.pulled).toBe(0);
    }
    for (const spy of touched) expect(spy).not.toHaveBeenCalled();
  });

  it("refuses with 415 any content type but exactly application/octet-stream, and counts nothing", async () => {
    const ctx = context();
    const counted = vi.spyOn(ctx.store, "incrWindow");
    const put = vi.spyOn(ctx.blobs, "put");
    for (const contentType of ["text/plain", "text/plain;charset=UTF-8", "application/x-www-form-urlencoded", "multipart/form-data", "application/octet-stream; charset=utf-8", undefined]) {
      const headers: Record<string, string> = { "x-ava": "1", "sec-fetch-site": "same-origin", ...(contentType === undefined ? {} : { "content-type": contentType }) };
      const request = new Request("http://app.local/api/upload?kind=envelope", { method: "POST", body: envelopeOf(40), headers });
      const response = await handleUpload(request, ctx);
      expect({ contentType, status: response.status }).toEqual({ contentType, status: 415 });
      expect(await response.json()).toEqual({ error: "content_type" });
      expect(request.bodyUsed).toBe(false);
    }
    expect(counted).not.toHaveBeenCalled();
    expect(put).not.toHaveBeenCalled();
  });
});

describe("VercelBlobBackend", () => {
  it("writes public, at the exact pathname, never over an existing blob, as octet-stream", async () => {
    vi.mocked(vercelBlob.put).mockResolvedValue({ url: `${ORIGIN}/envelope/ab` } as vercelBlob.PutBlobResult);
    const backend = new VercelBlobBackend("token-value");
    expect(await backend.put("envelope/ab", new Uint8Array([1, 2, 3]))).toEqual({ url: `${ORIGIN}/envelope/ab` });
    expect(vi.mocked(vercelBlob.put)).toHaveBeenCalledWith("envelope/ab", Buffer.from([1, 2, 3]), {
      access: "public",
      addRandomSuffix: false,
      allowOverwrite: false,
      contentType: "application/octet-stream",
      token: "token-value",
    });
  });

  it("reads a missing blob as absent and lets every other store error through", async () => {
    const backend = new VercelBlobBackend("token-value");
    vi.mocked(vercelBlob.head).mockRejectedValueOnce(new vercelBlob.BlobNotFoundError());
    expect(await backend.exists("envelope/ab")).toBe(false);
    vi.mocked(vercelBlob.head).mockRejectedValueOnce(new vercelBlob.BlobServiceNotAvailable());
    await expect(backend.exists("envelope/ab")).rejects.toBeInstanceOf(vercelBlob.BlobServiceNotAvailable);
    vi.mocked(vercelBlob.head).mockResolvedValueOnce({} as vercelBlob.HeadBlobResult);
    expect(await backend.exists("envelope/ab")).toBe(true);
  });

  it("heads, deletes and lists by prefix through the store with its token", async () => {
    const backend = new VercelBlobBackend("token-value");
    const at = new Date("2026-11-17T10:00:00Z");
    vi.mocked(vercelBlob.head).mockResolvedValueOnce({ pathname: "document/ab", url: `${ORIGIN}/document/ab`, size: 5, uploadedAt: at } as vercelBlob.HeadBlobResult);
    expect(await backend.head("document/ab")).toEqual({ pathname: "document/ab", url: `${ORIGIN}/document/ab`, size: 5, uploadedAt: at.getTime() });
    vi.mocked(vercelBlob.head).mockRejectedValueOnce(new vercelBlob.BlobNotFoundError());
    expect(await backend.head("document/cd")).toBeNull();

    await backend.delete(["document/ab", "document/cd"]);
    expect(vi.mocked(vercelBlob.del)).toHaveBeenCalledWith(["document/ab", "document/cd"], { token: "token-value", abortSignal: undefined });
    await backend.delete([]);
    expect(vi.mocked(vercelBlob.del)).toHaveBeenCalledTimes(1);

    const blob = { pathname: "document/ab", url: `${ORIGIN}/document/ab`, size: 5, uploadedAt: at, downloadUrl: "", etag: "" };
    vi.mocked(vercelBlob.list).mockResolvedValueOnce({ blobs: [blob], hasMore: true, cursor: "next" });
    expect(await backend.list("document/", { limit: 100 })).toEqual({ blobs: [{ pathname: "document/ab", url: `${ORIGIN}/document/ab`, size: 5, uploadedAt: at.getTime() }], cursor: "next" });
    expect(vi.mocked(vercelBlob.list)).toHaveBeenCalledWith({ prefix: "document/", limit: 100, cursor: undefined, token: "token-value", abortSignal: undefined });
    vi.mocked(vercelBlob.list).mockResolvedValueOnce({ blobs: [], hasMore: true });
    expect(await backend.list("document/", { limit: 100, cursor: "next" })).toEqual({ blobs: [] });
    await expect(backend.list("", { limit: 100 })).rejects.toBeInstanceOf(TypeError);
  });

  it("reads the checked URL with no redirect, refusing a stated or streamed length over the cap", async () => {
    const backend = new VercelBlobBackend("token-value");
    const url = new URL(`${ORIGIN}/document/ab`);
    const fetchMock = vi.spyOn(globalThis, "fetch");

    fetchMock.mockResolvedValueOnce(new Response(new Uint8Array([1, 2, 3]), { status: 200 }));
    expect(await backend.read(url, 3)).toEqual(new Uint8Array([1, 2, 3]));
    expect(fetchMock.mock.calls[0]?.[0]).toBe(url);
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ redirect: "manual" });

    fetchMock.mockResolvedValueOnce(new Response(null, { status: 404 }));
    expect(await backend.read(url, 3)).toBeNull();

    const stated = countingStream(1_024);
    fetchMock.mockResolvedValueOnce(new Response(stated.stream, { status: 200, headers: { "content-length": "4096" } }));
    await expect(backend.read(url, 3_000)).rejects.toBeInstanceOf(TooLarge);
    expect(stated.counter.pulled).toBe(0);

    const endless = countingStream(1_024);
    fetchMock.mockResolvedValueOnce(new Response(endless.stream, { status: 200 }));
    await expect(backend.read(url, 3_000)).rejects.toBeInstanceOf(TooLarge);
    expect(endless.counter.pulled).toBeLessThanOrEqual(3_000 + 1_024);
    expect(endless.counter.cancelled).toBe(true);

    fetchMock.mockResolvedValueOnce(new Response(null, { status: 307, headers: { location: "https://evil.example/x" } }));
    await expect(backend.read(url, 3)).rejects.toThrow("answered 307");
    await expect(backend.read(new URL("http://store123.public.blob.vercel-storage.com/document/ab"), 3)).rejects.toBeInstanceOf(TypeError);
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });
});

describe("MemoryBlobBackend", () => {
  it("heads, lists by prefix in pages, deletes, and reads only its own origin", async () => {
    let now = 1_000;
    const backend = new MemoryBlobBackend(ORIGIN, { now: () => now });
    await backend.put("document/aa", new Uint8Array([1]));
    now = 2_000;
    await backend.put("document/bb", new Uint8Array([2, 2]));
    await backend.put("envelope/cc", new Uint8Array([3]));
    expect(await backend.head("document/bb")).toEqual({ pathname: "document/bb", url: `${ORIGIN}/document/bb`, size: 2, uploadedAt: 2_000 });
    expect(await backend.head("document/zz")).toBeNull();

    const first = await backend.list("document/", { limit: 1 });
    expect(first.blobs.map((blob) => blob.pathname)).toEqual(["document/aa"]);
    expect(first.cursor).toBe("document/aa");
    const second = await backend.list("document/", { limit: 1, cursor: first.cursor });
    expect(second).toEqual({ blobs: [{ pathname: "document/bb", url: `${ORIGIN}/document/bb`, size: 2, uploadedAt: 2_000 }] });
    await expect(backend.list("", { limit: 1 })).rejects.toBeInstanceOf(TypeError);

    expect(await backend.read(new URL(`${ORIGIN}/document/bb`), 10)).toEqual(new Uint8Array([2, 2]));
    expect(await backend.read(new URL("https://evil.example/document/bb"), 10)).toBeNull();
    await backend.delete(["document/bb", "document/missing"]);
    expect(await backend.head("document/bb")).toBeNull();
    expect([...backend.blobs.keys()]).toEqual(["document/aa", "envelope/cc"]);
  });

  it("stops a read the moment it passes the cap", async () => {
    const backend = new MemoryBlobBackend(ORIGIN, { chunkSize: 1_000 });
    await backend.put("document/big", new Uint8Array(50_000));
    await expect(backend.read(new URL(`${ORIGIN}/document/big`), 10_500)).rejects.toBeInstanceOf(TooLarge);
    expect(backend.pulled).toBe(11_000);
  });
});
