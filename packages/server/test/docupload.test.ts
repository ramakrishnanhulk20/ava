// Not covered here: a real Vercel Blob store. Whether the store itself enforces the token's
// pathname, content type, size cap and no-overwrite rule, and the headers it serves blobs with
// (C29), was checked in a separate live run on 17 Nov 2026. Also not covered: browser
// multipart uploads, the store's CDN cache after a delete, and the live chain: DocumentPosted logs
// and block times come from a stub chain, and the gap between the blob store's clock and block
// time is not modelled.
import { createHash } from "node:crypto";
import { generateClientTokenFromReadWriteToken, getPayloadFromClientToken } from "@vercel/blob/client";
import type { Hex } from "viem";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryBlobBackend } from "../src/blob.ts";
import { DOC_BYTES_PER_CLIENT_DAY, DOC_BYTES_TOTAL_DAY, REGISTRY_ADDRESS, REGISTRY_DEPLOY_BLOCK } from "../src/config.ts";
import {
  DOCUMENT_CAP,
  DOCUMENT_TOKEN_SECONDS,
  UNUSED_TOKEN_GRACE_MS,
  handleDocumentToken,
  handleDocumentVerify,
  POSTED_SCAN_KEY,
  POSTED_SIZES_MAX,
  postedKey,
  postedSizes,
  SWEEP_HASH_BYTES,
  sweepUnverified,
  verifiedSize,
  type DocumentContext,
  type SweepContext,
} from "../src/docupload.ts";
import { referencedKey, sweepUnreferencedEnvelopes, type EnvelopeLogs } from "../src/envelopeSweep.ts";
import { MemoryStore, type SharedStore } from "../src/store.ts";
import { APP_HEADERS, CROSS_SITE_HEADERS, failingStore, retriedWrites, stalledBody } from "./fixtures.ts";

const ORIGIN = "https://store123.public.blob.vercel-storage.com";
const FAKE_STORE_CREDENTIAL = "vercel_blob_rw_store123_notarealsecret";
const NOW = Date.UTC(2026, 10, 17, 10, 0, 0);
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
/** When the registry's deploy block landed on the stub chain, unless a test says otherwise. */
const GENESIS = NOW - 24 * HOUR;

/**
 * The registry's logs on a stub chain where block DEPLOY + n lands n seconds after `genesis`. The
 * latest block is the one at `head()`, and `post` emits a DocumentPosted for a hash and the
 * cipherSize its poster signed, in that block.
 */
function stubChain(genesis: number, head: () => number) {
  const posted: { block: bigint; hex: string; size: number }[] = [];
  const blockAt = (time: number): bigint => REGISTRY_DEPLOY_BLOCK + BigInt(Math.floor((time - genesis) / 1_000));
  const logs: EnvelopeLogs = {
    latestBlock: async () => blockAt(head()),
    envelopeHashes: async () => [],
    documentPosts: async (fromBlock, toBlock) =>
      posted.filter((e) => e.block >= fromBlock && e.block <= toBlock).map((e) => ({ cipherHash: `0x${e.hex}` as Hex, cipherSize: BigInt(e.size) })),
    blockTime: async (block) => genesis + Number(block - REGISTRY_DEPLOY_BLOCK) * 1_000,
  };
  return {
    logs,
    post: (hex: string, size: number): void => {
      posted.push({ block: blockAt(head()), hex, size });
    },
  };
}

/** The sizes the posted mark of `hex` holds. @throws When there is no posted mark at all. */
async function sizesPosted(store: SharedStore, hex: string): Promise<readonly bigint[] | undefined> {
  const mark = await store.get(postedKey(hex));
  if (mark === null) throw new Error(`No posted mark for ${hex}.`);
  return postedSizes(mark);
}

/** One run of the log scan, the job that marks posted documents. */
function scan(store: SharedStore, blobs: MemoryBlobBackend, logs: EnvelopeLogs, now: number) {
  return sweepUnreferencedEnvelopes({ blobs, store, now, logs });
}

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

/** A request as our app sends it; `headers` adds to or replaces the app's own headers. */
function post(route: "token" | "verify", body: unknown, headers: Record<string, string> = { "content-type": "application/json" }): Request {
  return new Request(`http://app.local/api/documents/${route}`, {
    method: "POST",
    headers: { ...APP_HEADERS, ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function bytesOf(size: number, seed: number): Uint8Array {
  return new Uint8Array(size).map((_, i) => (i * 131 + seed) & 0xff);
}

/** Token limits so roomy that only the document byte budgets can refuse. */
const ROOMY_TOKENS = { perIp: 1_000, total: 10_000, windowSeconds: 3600, tokensPerIp: 1_000 };

/** The bytes a document byte budget holds: what was booked under `key`, less what was given back. */
async function held(store: SharedStore, key: string): Promise<number> {
  return Number((await store.get(key)) ?? 0) - Number((await store.get(`${key}:returned`)) ?? 0);
}

async function answerOf(response: Response): Promise<{ status: number; error: unknown }> {
  return { status: response.status, error: ((await response.json()) as { error?: unknown }).error };
}

beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("handleDocumentToken", () => {
  it("issues a token only for a valid sha256, for exactly that pathname, type, size and lifetime", async () => {
    const buildToken = vi.fn(generateClientTokenFromReadWriteToken);
    const ctx = context({ buildToken });
    const hex = hexOf(bytesOf(1_000, 1));
    const response = await handleDocumentToken(post("token", { sha256: hex, size: 1_000 }), ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    const body = (await response.json()) as { exists: boolean; pathname: string; token: string; validUntil: number };
    expect(body).toMatchObject({ exists: false, pathname: `document/${hex}`, contentType: "application/octet-stream", maxBytes: 1_000 });

    expect(buildToken).toHaveBeenCalledTimes(1);
    expect(buildToken.mock.calls[0]?.[0]).toEqual({
      token: FAKE_STORE_CREDENTIAL,
      pathname: `document/${hex}`,
      allowedContentTypes: ["application/octet-stream"],
      maximumSizeInBytes: 1_000,
      validUntil: NOW + 10 * MINUTE,
      addRandomSuffix: false,
      allowOverwrite: false,
    });
    const payload = getPayloadFromClientToken(body.token);
    expect(payload).toEqual({
      pathname: `document/${hex}`,
      allowedContentTypes: ["application/octet-stream"],
      maximumSizeInBytes: 1_000,
      validUntil: NOW + 10 * MINUTE,
      addRandomSuffix: false,
      allowOverwrite: false,
    });
    expect(body.token).not.toContain("notarealsecret");
    expect(await ctx.store.get(`pending:${hex}`)).toBeNull();

    const refused: Array<[Request, number]> = [
      [post("token", { sha256: hex.toUpperCase(), size: 1_000 }), 400],
      [post("token", { sha256: hex.slice(1), size: 1_000 }), 400],
      [post("token", { sha256: `0x${hex}` }), 400],
      [post("token", { sha256: hex, pathname: "index.html" }), 400],
      [post("token", {}), 400],
      [post("token", "not json"), 400],
      [post("token", { sha256: hex, size: 1_000 }, { "content-type": "text/plain" }), 415],
      [post("token", { sha256: hex, pad: "x".repeat(300) }), 413],
      [new Request("http://app.local/api/documents/token", { headers: APP_HEADERS }), 405],
    ];
    for (const [request, status] of refused) expect((await handleDocumentToken(request, ctx)).status).toBe(status);
    // A token is only ever for the size its request states, a whole number within the registry's cap.
    for (const size of [undefined, 0, -1, 1.5, DOCUMENT_CAP + 1, "1000", null]) {
      const response = await handleDocumentToken(post("token", { sha256: hex, size }), ctx);
      expect({ size, status: response.status, body: await response.json() }).toEqual({ size, status: 400, body: { error: "bad_size" } });
    }
    expect(buildToken).toHaveBeenCalledTimes(1);
  });

  it("answers exists for a pathname that already holds a blob, and issues no token", async () => {
    const buildToken = vi.fn(generateClientTokenFromReadWriteToken);
    const ctx = context({ buildToken, tokenLimits: { perIp: 10, total: 10, windowSeconds: 3600, tokensPerIp: 1 } });
    const bytes = bytesOf(2_000, 2);
    await ctx.blobs.put(`document/${hexOf(bytes)}`, bytes);
    const response = await handleDocumentToken(post("token", { sha256: hexOf(bytes), size: 1_000 }), ctx);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ exists: true, url: `${ORIGIN}/document/${hexOf(bytes)}` });
    expect(buildToken).not.toHaveBeenCalled();
    // The exists answer spent none of the one-token budget.
    expect((await handleDocumentToken(post("token", { sha256: hexOf(bytesOf(10, 3)), size: 1_000 }), ctx)).status).toBe(200);
    expect(buildToken).toHaveBeenCalledTimes(1);
  });

  it("issues each token for exactly the size its request states, and refuses 429 upload_bytes with no token past 25 MiB a client, its /48 at four times that, or fifty times that in all, in a UTC day", async () => {
    expect(DOC_BYTES_PER_CLIENT_DAY).toBe(DOCUMENT_CAP);
    expect(DOC_BYTES_TOTAL_DAY).toBe(50 * DOC_BYTES_PER_CLIENT_DAY);
    const buildToken = vi.fn(generateClientTokenFromReadWriteToken);
    const ctx = context({ buildToken, tokenLimits: ROOMY_TOKENS });
    let seed = 0;
    const ask = async (clientIp: string, size: number, now = NOW) => handleDocumentToken(post("token", { sha256: hexOf(bytesOf(16, ++seed)), size }), { ...ctx, clientIp, now });

    const small = await ask("198.51.100.1", 1_000);
    const { token, maxBytes } = (await small.json()) as { token: string; maxBytes: number };
    expect(maxBytes).toBe(1_000);
    expect(getPayloadFromClientToken(token).maximumSizeInBytes).toBe(1_000);

    // 25 MiB is one full document: 1,000 bytes already booked leave room for the rest of one and no more.
    expect(await (await ask("198.51.100.1", DOCUMENT_CAP)).json()).toEqual({ error: "upload_bytes" });
    expect((await ask("198.51.100.1", DOCUMENT_CAP - 1_000)).status).toBe(200);
    const over = await ask("198.51.100.1", 1);
    expect(over.status).toBe(429);
    expect(await over.json()).toEqual({ error: "upload_bytes" });
    expect(over.headers.get("retry-after")).toBe(String(14 * 3600));
    // Of three requests racing for one fresh client's day, one is booked.
    const raced = await Promise.all([1, 2, 3].map(() => ask("198.51.100.2", DOCUMENT_CAP)));
    expect(raced.map((r) => r.status).sort()).toEqual([200, 429, 429]);
    expect(await held(ctx.store, `budget:docbytes-2026-11-17:ip:198.51.100.2`)).toBe(DOCUMENT_CAP);
    expect(buildToken).toHaveBeenCalledTimes(3);

    // Each /64 of one /48 has its own 25 MiB, and the /48 as a whole 100 MiB.
    for (let net = 0; net < 4; net++) expect((await ask(`2001:db8:5:${net}::1`, DOCUMENT_CAP)).status).toBe(200);
    expect(await (await ask("2001:db8:5:4::1", 1)).json()).toEqual({ error: "upload_bytes" });

    // Fifty full documents in all: the six booked above leave room for 44 more, one to a client.
    for (let i = 0; i < 44; i++) expect((await ask(`198.51.100.${10 + i}`, DOCUMENT_CAP)).status).toBe(200);
    expect(await (await ask("198.51.100.60", DOCUMENT_CAP)).json()).toEqual({ error: "upload_bytes" });
    expect(buildToken).toHaveBeenCalledTimes(3 + 4 + 44);
    // A new UTC day books afresh.
    expect((await ask("198.51.100.60", DOCUMENT_CAP, NOW + 24 * HOUR)).status).toBe(200);
  });

  it("needs fifty addresses to spend the day's shared total: eleven asking four full documents each leave a twelfth served, and a refused request books nothing", async () => {
    const ctx = context({ tokenLimits: ROOMY_TOKENS });
    let seed = 100;
    const ask = async (clientIp: string, size: number) => handleDocumentToken(post("token", { sha256: hexOf(bytesOf(16, ++seed)), size }), { ...ctx, clientIp });
    const total = "budget:docbytes:all:2026-11-17";
    for (let client = 1; client <= 11; client++) {
      const statuses: number[] = [];
      for (let n = 0; n < 4; n++) statuses.push((await ask(`198.51.100.${client}`, DOCUMENT_CAP)).status);
      expect({ client, statuses }).toEqual({ client, statuses: [200, 429, 429, 429] });
    }
    expect(await held(ctx.store, total)).toBe(11 * DOCUMENT_CAP);
    expect((await ask("198.51.100.12", 1_024)).status).toBe(200);
    expect(await held(ctx.store, total)).toBe(11 * DOCUMENT_CAP + 1_024);

    // A request the shared total refuses books nothing on its client or on the total.
    for (let client = 13; client <= 50; client++) expect((await ask(`198.51.100.${client}`, DOCUMENT_CAP)).status).toBe(200);
    const before = await held(ctx.store, total);
    expect(before).toBe(49 * DOCUMENT_CAP + 1_024);
    expect(await (await ask("198.51.100.51", DOCUMENT_CAP)).json()).toEqual({ error: "upload_bytes" });
    expect(await held(ctx.store, total)).toBe(before);
    expect(await held(ctx.store, "budget:docbytes-2026-11-17:ip:198.51.100.51")).toBe(0);
    expect((await ask("198.51.100.51", DOCUMENT_CAP - 1_024)).status).toBe(200);
    expect(await held(ctx.store, total)).toBe(DOC_BYTES_TOTAL_DAY);
  });

  it("gives a refused request's booking back once, though the store applied each give-back write twice after a lost reply", async () => {
    const store = new MemoryStore({ now: () => NOW });
    const lossy = retriedWrites(store, (_write, key) => key.endsWith(":returned"));
    const total = "budget:docbytes:all:2026-11-17";
    await store.incrWindow(total, 172_800, DOC_BYTES_TOTAL_DAY - 1_000);
    const refused = await handleDocumentToken(post("token", { sha256: hexOf(bytesOf(16, 210)), size: DOCUMENT_CAP }), context({ store: lossy, clientIp: "198.51.100.77", tokenLimits: ROOMY_TOKENS }));
    expect(await answerOf(refused)).toEqual({ status: 429, error: "upload_bytes" });
    expect(await held(store, "budget:docbytes-2026-11-17:ip:198.51.100.77")).toBe(0);
    expect(await held(store, total)).toBe(DOC_BYTES_TOTAL_DAY - 1_000);
  });

  it("hands out no token it cannot record, and gives its booking back exactly once though the record landed with its reply lost", async () => {
    let clock = NOW;
    const store = new MemoryStore({ now: () => clock });
    const blobs = new MemoryBlobBackend(ORIGIN, { now: () => clock });
    const buildToken = vi.fn(generateClientTokenFromReadWriteToken);
    // The record's write lands, its reply is lost, and the read that would tell fails too.
    const lossy: SharedStore = {
      ...retriedWrites(store, (write, key) => write === "setIfAbsent" && /^doctoken:\d+$/.test(key)),
      get: async (key) => {
        if (/^doctoken:\d+$/.test(key) && clock === NOW) throw new Error("store unreachable");
        return store.get(key);
      },
    };
    const refused = await handleDocumentToken(post("token", { sha256: hexOf(bytesOf(16, 9)), size: DOCUMENT_CAP }), context({ store: lossy, blobs, buildToken, tokenLimits: ROOMY_TOKENS }));
    expect(await answerOf(refused)).toEqual({ status: 503, error: "store_failed" });
    const total = "budget:docbytes:all:2026-11-17";
    expect(await held(store, total)).toBe(DOCUMENT_CAP);

    clock = NOW + DOCUMENT_TOKEN_SECONDS * 1_000 + UNUSED_TOKEN_GRACE_MS;
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ returned: 1 });
    expect(await held(store, total)).toBe(0);
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ returned: 0 });
    expect(await held(store, total)).toBe(0);
  });

  it("gives an unused token's bytes back once, after its lifetime and the grace that follows, found empty by the sweep or by verify, and keeps a used token's", async () => {
    let clock = NOW;
    const store = new MemoryStore({ now: () => clock });
    const blobs = new MemoryBlobBackend(ORIGIN, { now: () => clock });
    const from = (clientIp: string) => context({ store, blobs, now: clock, clientIp, tokenLimits: ROOMY_TOKENS });
    const ask = async (clientIp: string, sha256: string, size: number) => handleDocumentToken(post("token", { sha256, size }), from(clientIp));
    const day = (ip: string) => `budget:docbytes-2026-11-17:ip:${ip}`;
    const total = "budget:docbytes:all:2026-11-17";
    const usedBytes = bytesOf(2_000, 2);
    const [unused, used, abandoned] = [hexOf(bytesOf(16, 1)), hexOf(usedBytes), hexOf(bytesOf(16, 3))];
    expect((await ask("198.51.100.1", unused, DOCUMENT_CAP)).status).toBe(200);
    expect((await ask("198.51.100.2", used, 2_000)).status).toBe(200);
    expect((await ask("198.51.100.3", abandoned, DOCUMENT_CAP)).status).toBe(200);
    await blobs.put(`document/${used}`, usedBytes);
    // While a token may still be used, its client's day stays spent.
    expect(await (await ask("198.51.100.1", hexOf(bytesOf(16, 4)), 1)).json()).toEqual({ error: "upload_bytes" });
    const sweep = () => sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock });

    clock = NOW + DOCUMENT_TOKEN_SECONDS * 1_000 + UNUSED_TOKEN_GRACE_MS - 1;
    await sweep();
    expect(await held(store, total)).toBe(2 * DOCUMENT_CAP + 2_000);
    expect((await handleDocumentVerify(post("verify", { sha256: abandoned }), from("198.51.100.3"))).status).toBe(409);
    expect(await held(store, day("198.51.100.3"))).toBe(DOCUMENT_CAP);

    clock += 1;
    expect(await answerOf(await handleDocumentVerify(post("verify", { sha256: abandoned }), from("198.51.100.3")))).toEqual({ status: 409, error: "blob_missing" });
    expect(await held(store, day("198.51.100.3"))).toBe(0);
    await sweep();
    expect({ unused: await held(store, day("198.51.100.1")), used: await held(store, day("198.51.100.2")), total: await held(store, total) }).toEqual({ unused: 0, used: 2_000, total: 2_000 });
    // Given back once: neither another sweep nor another verify gives anything more.
    await sweep();
    expect((await handleDocumentVerify(post("verify", { sha256: abandoned }), from("198.51.100.3"))).status).toBe(409);
    expect(await held(store, total)).toBe(2_000);
    expect((await ask("198.51.100.1", hexOf(bytesOf(16, 5)), DOCUMENT_CAP)).status).toBe(200);
  });

  it("clears a verified mark whose blob is gone before issuing a token, so other bytes uploaded under the name are checked, not vouched for", async () => {
    const buildToken = vi.fn(generateClientTokenFromReadWriteToken);
    const ctx = context({ buildToken });
    const hex = hexOf(bytesOf(1_000, 190));
    // What a blob deleted by hand, or left behind on a store switch, leaves: the mark and no blob.
    await ctx.store.setIfAbsent(`verified:${hex}`, "1000", 3600);
    const cleared = vi.spyOn(ctx.store, "delete").mockRejectedValueOnce(new Error("store is down"));
    const down = await handleDocumentToken(post("token", { sha256: hex, size: 1_000 }), ctx);
    expect(down.status).toBe(503);
    expect(buildToken).not.toHaveBeenCalled();
    expect(await ctx.store.get(`verified:${hex}`)).toBe("1000");

    expect(await (await handleDocumentToken(post("token", { sha256: hex, size: 1_000 }), ctx)).json()).toMatchObject({ exists: false, pathname: `document/${hex}` });
    expect(cleared).toHaveBeenLastCalledWith(`verified:${hex}`);
    expect(await ctx.store.get(`verified:${hex}`)).toBeNull();
    expect(vi.mocked(console.warn).mock.calls.map(([line]) => JSON.parse(String(line)))).toContainEqual({ event: "stale_verified_mark_cleared", sha256: hex });

    await ctx.blobs.put(`document/${hex}`, bytesOf(1_000, 191));
    const verify = await handleDocumentVerify(post("verify", { sha256: hex }), ctx);
    expect(verify.status).toBe(409);
    expect(await verify.json()).toEqual({ error: "hash_mismatch" });
    expect(ctx.blobs.blobs.has(`document/${hex}`)).toBe(false);
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
      expect((await handleDocumentToken(post("token", { sha256: hex, size: 1_000 }), ctx)).status).toBe(502);
      expect(ctx.blobs.blobs.has(`document/${hex}`)).toBe(true);
      expect(await ctx.store.get(`verified:${hex}`)).toBeNull();
    }
    for (const bad of [`${ORIGIN}/`, "http://store123.public.blob.vercel-storage.com", "https://STORE123.public.blob.vercel-storage.com"]) {
      const ctx = context({ env: { BLOB_ORIGIN: bad, BLOB_READ_WRITE_TOKEN: FAKE_STORE_CREDENTIAL } });
      expect((await handleDocumentVerify(post("verify", { sha256: hex }), ctx)).status).toBe(500);
      expect((await handleDocumentToken(post("token", { sha256: hex, size: 1_000 }), ctx)).status).toBe(500);
    }
  });

  it("refuses an unverified document past the verify window and leaves it to the sweep, and still accepts a verified one", async () => {
    const ctx = context({ blobs: new MemoryBlobBackend(ORIGIN, { now: () => NOW - 51 * MINUTE }) });
    const stale = bytesOf(500, 5);
    const kept = bytesOf(500, 6);
    await ctx.blobs.put(`document/${hexOf(stale)}`, stale);
    await ctx.blobs.put(`document/${hexOf(kept)}`, kept);
    await ctx.store.setIfAbsent(`verified:${hexOf(kept)}`, "500", 3600);
    const late = await handleDocumentVerify(post("verify", { sha256: hexOf(stale) }), ctx);
    expect(late.status).toBe(409);
    expect(await late.json()).toEqual({ error: "too_old" });
    expect(ctx.blobs.blobs.has(`document/${hexOf(stale)}`)).toBe(true);
    expect(await ctx.store.get(`verified:${hexOf(stale)}`)).toBeNull();
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

describe("verifiedSize", () => {
  it("returns the size verify stored, and nothing for no mark, a damaged mark or a malformed name, where verify itself refuses", async () => {
    const ctx = context();
    const bytes = bytesOf(1_234, 9);
    const hex = hexOf(bytes);
    expect(await verifiedSize(ctx.store, hex)).toBeUndefined();
    await ctx.blobs.put(`document/${hex}`, bytes);
    expect((await handleDocumentVerify(post("verify", { sha256: hex }), ctx)).status).toBe(200);
    expect(await verifiedSize(ctx.store, hex)).toBe(1_234n);

    const other = hexOf(bytesOf(10, 1));
    const markWith = async (value: string): Promise<void> => {
      await ctx.store.delete(`verified:${other}`);
      await ctx.store.setIfAbsent(`verified:${other}`, value, 3600);
    };
    const read = vi.spyOn(ctx.blobs, "read");
    for (const junk of ["0", "-5", "01", "1e3", " 12", "12 ", "0x10", "abc", "", "26214401", "99999999999999999999"]) {
      await markWith(junk);
      expect({ junk, size: await verifiedSize(ctx.store, other) }).toEqual({ junk, size: undefined });
      expect({ junk, status: (await handleDocumentVerify(post("verify", { sha256: other }), ctx)).status }).toEqual({ junk, status: 503 });
    }
    expect(read).not.toHaveBeenCalled();
    await markWith(String(DOCUMENT_CAP));
    expect(await verifiedSize(ctx.store, other)).toBe(BigInt(DOCUMENT_CAP));
    expect(await (await handleDocumentVerify(post("verify", { sha256: other }), ctx)).json()).toMatchObject({ size: DOCUMENT_CAP });

    const looked = vi.spyOn(ctx.store, "get");
    for (const bad of [hex.toUpperCase(), `0x${hex}`, hex.slice(1), `${hex}0`, "", `document/${hex}`]) expect(await verifiedSize(ctx.store, bad)).toBeUndefined();
    expect(looked).not.toHaveBeenCalled();
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
      tokenStatuses.push((await handleDocumentToken(post("token", { sha256: hexOf(bytesOf(10, i)), size: 1_000 }, { ...json, "x-forwarded-for": forwarded }), ctx)).status);
    }
    expect(tokenStatuses).toEqual([200, 200, 429]);
    expect((await handleDocumentToken(post("token", { sha256: hexOf(bytesOf(10, 20)), size: 1_000 }), { ...ctx, clientIp: "203.0.113.8" })).status).toBe(200);
    expect((await handleDocumentToken(post("token", { sha256: hexOf(bytesOf(10, 21)), size: 1_000 }), { ...ctx, clientIp: "203.0.113.9" })).status).toBe(429);

    const verifyStatus = async (clientIp: string) => (await handleDocumentVerify(post("verify", { sha256: hexOf(bytesOf(10, 30)) }), { ...ctx, clientIp })).status;
    expect([await verifyStatus("203.0.113.7"), await verifyStatus("203.0.113.7"), await verifyStatus("203.0.113.8"), await verifyStatus("203.0.113.9")]).toEqual([409, 429, 409, 429]);

    const budget = context({ tokenLimits: { perIp: 10, total: 10, windowSeconds: 3600, tokensPerIp: 2 } });
    const issued = [40, 41, 42].map((seed) => hexOf(bytesOf(10, seed)));
    const statuses: number[] = [];
    for (const hex of issued) statuses.push((await handleDocumentToken(post("token", { sha256: hex, size: 1_000 }), budget)).status);
    expect(statuses).toEqual([200, 200, 429]);

    const down = context({ store: failingStore() as MemoryStore });
    expect((await handleDocumentToken(post("token", { sha256: issued[0], size: 1_000 }), down)).status).toBe(429);
    expect((await handleDocumentVerify(post("verify", { sha256: issued[0] }), down)).status).toBe(429);
  });
});

describe("request bodies", () => {
  it("that have not ended after 20 seconds are refused with 408 on token and verify, and nothing is issued or read", async () => {
    vi.useFakeTimers();
    const buildToken = vi.fn(generateClientTokenFromReadWriteToken);
    const ctx = context({ buildToken });
    const head = vi.spyOn(ctx.blobs, "head");
    for (const [route, handler] of [["token", handleDocumentToken], ["verify", handleDocumentVerify]] as const) {
      const body = stalledBody();
      const request = new Request(`http://app.local/api/documents/${route}`, {
        method: "POST",
        headers: { ...APP_HEADERS, "content-type": "application/json" },
        body: body.stream,
        duplex: "half",
      } as RequestInit);
      const pending = handler(request, ctx);
      let settled = false;
      void pending.then(() => (settled = true));
      for (let i = 0; i < 1_000 && !body.waiting(); i++) await Promise.resolve();
      expect(body.waiting()).toBe(true);
      await vi.advanceTimersByTimeAsync(19_999);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      const response = await pending;
      expect({ route, status: response.status }).toEqual({ route, status: 408 });
      expect(await response.json()).toEqual({ error: "body_timeout" });
    }
    expect(buildToken).not.toHaveBeenCalled();
    expect(head).not.toHaveBeenCalled();
  });
});

describe("cross-site requests", () => {
  it("are refused with 403 on token and verify, before anything is counted, read or looked up", async () => {
    const buildToken = vi.fn(generateClientTokenFromReadWriteToken);
    const ctx = context({ buildToken });
    const bytes = bytesOf(1_000, 50);
    await ctx.blobs.put(`document/${hexOf(bytes)}`, bytes);
    const touched = [vi.spyOn(ctx.store, "incrWindow"), vi.spyOn(ctx.store, "get"), vi.spyOn(ctx.store, "setIfAbsent"), vi.spyOn(ctx.blobs, "head"), vi.spyOn(ctx.blobs, "read"), vi.spyOn(ctx.blobs, "delete")];
    for (const [route, handler] of [["token", handleDocumentToken], ["verify", handleDocumentVerify]] as const) {
      for (const headers of CROSS_SITE_HEADERS) {
        const request = new Request(`http://app.local/api/documents/${route}`, {
          method: "POST",
          headers: { "content-type": "application/json", ...headers },
          body: JSON.stringify({ sha256: hexOf(bytes) }),
        });
        const response = await handler(request, ctx);
        expect({ route, headers, status: response.status }).toEqual({ route, headers, status: 403 });
        expect(await response.json()).toEqual({ error: "cross_site" });
        expect(request.bodyUsed).toBe(false);
      }
    }
    for (const spy of touched) expect(spy).not.toHaveBeenCalled();
    expect(buildToken).not.toHaveBeenCalled();
    expect(ctx.blobs.blobs.has(`document/${hexOf(bytes)}`)).toBe(true);
  });
});

describe("sweepUnverified", () => {
  it("deletes, across pages, documents no DocumentPosted names two hours on and other names an hour on, and stops when the store is down", async () => {
    const store = new MemoryStore({ now: () => NOW });
    const blobs = new MemoryBlobBackend(ORIGIN);
    const chain = stubChain(GENESIS, () => NOW);
    const add = (pathname: string, ageMinutes: number, bytes = new Uint8Array([1])): void => {
      blobs.blobs.set(pathname, bytes);
      blobs.uploadedAt.set(pathname, NOW - ageMinutes * MINUTE);
    };
    const hexFor = (label: string): string => hexOf(new TextEncoder().encode(label));
    const oldUnposted = Array.from({ length: 150 }, (_, i) => `document/${hexFor(`old-${i}`)}`);
    for (const pathname of oldUnposted) add(pathname, 121);
    // Posted documents hold the bytes they are named for: a posted mismatch is deleted.
    const oldPosted = Array.from({ length: 5 }, (_, i) => hexFor(`posted-${i}`));
    for (const [i, hex] of oldPosted.entries()) {
      add(`document/${hex}`, 600, new TextEncoder().encode(`posted-${i}`));
      chain.post(hex, `posted-${i}`.length);
    }
    const young = Array.from({ length: 5 }, (_, i) => `document/${hexFor(`young-${i}`)}`);
    for (const pathname of young) add(pathname, 119);
    add("document/not-a-hash", 61);
    await scan(store, blobs, chain.logs, NOW);
    // Added after the scan, which runs the envelope sweep: this sweep must leave it alone.
    const envelope = `envelope/${hexFor("envelope")}`;
    add(envelope, 600);

    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: NOW })).toMatchObject({ deleted: 151 });
    const left = [...blobs.blobs.keys()].sort();
    expect(left).toEqual([...oldPosted.map((hex) => `document/${hex}`), ...young, envelope].sort());
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: NOW })).toMatchObject({ deleted: 0 });

    const late = `document/${hexFor("late")}`;
    add(late, 180);
    await expect(sweepUnverified({ blobs, store: failingStore(), blobOrigin: ORIGIN, now: NOW })).rejects.toThrow();
    expect(blobs.blobs.has(late)).toBe(true);
  });

  it("keeps its listing cursor across runs, so a name behind 5,000 kept documents is reached, and starts over after the last page", async () => {
    const store = new MemoryStore({ now: () => NOW });
    const blobs = new MemoryBlobBackend(ORIGIN);
    const old = NOW - 3 * HOUR;
    const add = (hex: string): void => {
      blobs.blobs.set(`document/${hex}`, new Uint8Array([1]));
      blobs.uploadedAt.set(`document/${hex}`, old);
    };
    // Posted and verified at the size the chain stated, so every one is kept and none is read.
    for (let i = 0; i < 5_000; i++) {
      const hex = `1${i.toString(16).padStart(63, "0")}`;
      add(hex);
      await store.setIfAbsent(postedKey(hex), `${REGISTRY_DEPLOY_BLOCK}:1`, 3600);
      await store.setIfAbsent(`verified:${hex}`, "1", 3600);
    }
    const unposted = "f".repeat(64);
    add(unposted);
    await store.setIfAbsent(POSTED_SCAN_KEY, `${REGISTRY_DEPLOY_BLOCK + 1n}:${NOW}`, 3600);
    const read = vi.spyOn(blobs, "read");
    const moved = vi.spyOn(store, "compareAndSet");
    const placed = vi.spyOn(store, "setIfAbsent");
    const sweep = () => sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: NOW });

    // 5,001 names make 51 pages: the first run stops at its cap of 50, the second reads the last.
    expect(await sweep()).toMatchObject({ done: "swept", deleted: 0, outOfTime: false });
    expect(blobs.blobs.has(`document/${unposted}`)).toBe(true);
    expect(await sweep()).toMatchObject({ done: "swept", deleted: 1, outOfTime: false });
    expect(blobs.blobs.has(`document/${unposted}`)).toBe(false);
    expect(read).not.toHaveBeenCalled();
    expect(moved).toHaveBeenCalled();
    expect(moved.mock.calls.filter(([key]) => key !== "docsweep:cursor")).toEqual([]);
    expect(placed.mock.calls.filter(([key]) => key === "docsweep:cursor")).toEqual([]);

    const first = "0".repeat(64);
    add(first);
    expect(await sweep()).toMatchObject({ done: "swept", deleted: 1 });
    expect(blobs.blobs.has(`document/${first}`)).toBe(false);
  });

  it("starts again from the first page once the blob store refuses the listing cursor it holds, so that cursor never stops every later run", async () => {
    const store = new MemoryStore({ now: () => NOW });
    const blobs = new MemoryBlobBackend(ORIGIN);
    const unposted = "a".repeat(64);
    blobs.blobs.set(`document/${unposted}`, new Uint8Array([1]));
    blobs.uploadedAt.set(`document/${unposted}`, NOW - 3 * HOUR);
    await store.setIfAbsent(POSTED_SCAN_KEY, `${REGISTRY_DEPLOY_BLOCK + 1n}:${NOW}`, 3600);
    await store.setIfAbsent("docsweep:cursor", "after:a cursor the store has since forgotten", 3600);
    const real = blobs.list.bind(blobs);
    vi.spyOn(blobs, "list").mockImplementation(async (prefix, page) => {
      if (page.cursor !== undefined) throw new Error("The blob store refused the cursor.");
      return real(prefix, page);
    });
    const sweep = () => sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: NOW });

    await expect(sweep()).rejects.toThrow("refused the cursor");
    expect(await store.get("docsweep:cursor")).toBe("start");
    expect(blobs.blobs.has(`document/${unposted}`)).toBe(true);
    expect(await sweep()).toMatchObject({ done: "swept", deleted: 1 });
    expect(blobs.blobs.size).toBe(0);
  });
});

describe("sweepUnverified on documents posted without a verify", () => {
  /**
   * Stores each document as `document/<name>` holding `bytes`, posts `name` with `size` (its byte
   * length unless given) on the stub chain, then moves the clock and the log scan two hours and a
   * minute on. Stored without a copy, so the full-size documents are held once.
   */
  async function postedUnverified(docs: readonly { name: string; bytes: Uint8Array; size?: number }[], chunkSize?: number) {
    let clock = NOW;
    const store = new MemoryStore({ now: () => clock });
    const blobs = new MemoryBlobBackend(ORIGIN, { now: () => clock, chunkSize });
    const chain = stubChain(GENESIS, () => clock);
    for (const { name, bytes, size } of docs) {
      blobs.blobs.set(`document/${name}`, bytes);
      blobs.uploadedAt.set(`document/${name}`, clock);
      chain.post(name, size ?? bytes.byteLength);
    }
    clock = NOW + 2 * HOUR + MINUTE;
    await scan(store, blobs, chain.logs, clock);
    return { store, blobs, now: clock, sweep: (extra: Partial<SweepContext> = {}) => sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock, ...extra }) };
  }

  const warned = (): unknown[] => vi.mocked(console.warn).mock.calls.map(([line]) => JSON.parse(String(line)));

  it("deletes one whose bytes do not hash to its name, and logs it", async () => {
    const name = hexOf(bytesOf(900, 100));
    const { store, blobs, now, sweep } = await postedUnverified([{ name, bytes: bytesOf(900, 101) }]);
    // A store that reports another URL for it gets no read and no delete, as in verify.
    expect(await sweepUnverified({ blobs, store, blobOrigin: "https://other.public.blob.vercel-storage.com", now })).toMatchObject({ deleted: 0, unreadable: [name] });
    expect(blobs.blobs.has(`document/${name}`)).toBe(true);
    expect(warned()).toContainEqual({ event: "document_read_failed", sha256: name, reason: "unexpected_blob_url" });

    expect(await sweep()).toMatchObject({ deleted: 1 });
    expect(blobs.blobs.has(`document/${name}`)).toBe(false);
    expect(await store.get(`verified:${name}`)).toBeNull();
    expect(warned()).toContainEqual({ event: "document_mismatch_deleted", sha256: name, reason: "hash_mismatch" });
    await expect(sweepUnverified({ blobs, store, blobOrigin: "http://store123.public.blob.vercel-storage.com", now })).rejects.toThrow();
  });

  it("keeps one whose bytes hash to its name, marks it verified, and never reads it again", async () => {
    const bytes = bytesOf(900, 102);
    const name = hexOf(bytes);
    const { store, blobs, sweep } = await postedUnverified([{ name, bytes }]);
    expect(await sweep()).toMatchObject({ deleted: 0 });
    expect(blobs.blobs.has(`document/${name}`)).toBe(true);
    expect(await store.get(`verified:${name}`)).toBe("900");

    const read = vi.spyOn(blobs, "read");
    expect(await sweep()).toMatchObject({ deleted: 0 });
    expect(read).not.toHaveBeenCalled();
    expect(blobs.blobs.has(`document/${name}`)).toBe(true);
  });

  it("hashes at most SWEEP_HASH_BYTES a run and leaves the rest, a mismatch included, unhashed for the next run", async () => {
    expect(SWEEP_HASH_BYTES).toBe(200 * 1_048_576);
    const docs = Array.from({ length: 9 }, (_, i) => {
      const bytes = new Uint8Array(DOCUMENT_CAP).fill(i + 1);
      return { name: hexOf(bytes), bytes };
    }).sort((a, b) => (a.name < b.name ? -1 : 1));
    // Eight full-size documents fill the bound, so the last in pathname order waits a run.
    const last = docs.at(-1) as (typeof docs)[number];
    last.bytes = new Uint8Array(DOCUMENT_CAP).fill(200);
    const { store, blobs, sweep } = await postedUnverified(docs, 1_048_576);

    expect(await sweep()).toMatchObject({ deleted: 0, deferred: 1, outOfTime: false });
    expect(blobs.pulled).toBe(SWEEP_HASH_BYTES);
    for (const { name } of docs.slice(0, 8)) expect(await store.get(`verified:${name}`)).toBe(String(DOCUMENT_CAP));
    expect(blobs.blobs.has(`document/${last.name}`)).toBe(true);
    expect(await store.get(`verified:${last.name}`)).toBeNull();

    expect(await sweep()).toMatchObject({ deleted: 1 });
    expect(blobs.pulled).toBe(SWEEP_HASH_BYTES + DOCUMENT_CAP);
    expect(blobs.blobs.has(`document/${last.name}`)).toBe(false);
    expect(blobs.blobs.size).toBe(8);
  });

  it("runs one sweep at a time: a second run while the first holds the lock is busy and deletes nothing", async () => {
    const name = hexOf(bytesOf(900, 110));
    const { blobs, sweep } = await postedUnverified([{ name, bytes: bytesOf(900, 111) }]);
    const deleted = vi.spyOn(blobs, "delete");
    const outcomes = await Promise.all([sweep(), sweep()]);
    expect(outcomes).toContainEqual({ done: "busy" });
    expect(outcomes).toContainEqual(expect.objectContaining({ done: "swept", deleted: 1 }));
    expect(deleted).toHaveBeenCalledTimes(1);
    expect(blobs.blobs.has(`document/${name}`)).toBe(false);
    expect(await sweep()).toMatchObject({ done: "swept", deleted: 0 });
  });

  it("starts no hashing read once the run has used its time budget, and leaves the rest for the next run", async () => {
    const docs = Array.from({ length: 5 }, (_, i) => {
      const bytes = bytesOf(900, 120 + i);
      return { name: hexOf(bytes), bytes };
    });
    const { store, blobs, sweep } = await postedUnverified(docs);
    let elapsed = 0;
    const real = blobs.read.bind(blobs);
    // Each read takes 100 s on the run's clock, so the 240 s budget starts three of them.
    const read = vi.spyOn(blobs, "read").mockImplementation(async (url, cap, signal) => {
      elapsed += 100_000;
      return real(url, cap, signal);
    });
    const clock = (): number => elapsed;
    const marked = async (): Promise<number> => (await Promise.all(docs.map(({ name }) => store.get(`verified:${name}`)))).filter((mark) => mark !== null).length;

    expect(await sweep({ clock })).toMatchObject({ done: "swept", deleted: 0, deferred: 2, outOfTime: true });
    expect(read).toHaveBeenCalledTimes(3);
    expect(await marked()).toBe(3);
    expect(blobs.blobs.size).toBe(5);

    expect(await sweep({ clock })).toMatchObject({ done: "swept", deleted: 0, deferred: 0, outOfTime: false });
    expect(read).toHaveBeenCalledTimes(5);
    expect(await marked()).toBe(5);
  });

  it("moves its cursor past a page where it left a posted document unhashed, and hashes it on the next pass over that page", async () => {
    const mismatched = Array.from({ length: 5 }, (_, i) => ({ name: `0${i.toString(16).padStart(63, "0")}`, bytes: bytesOf(900, 160 + i) }));
    const { store, blobs, sweep } = await postedUnverified(mismatched);
    // Kept documents fill the rest of the first page and start a second one.
    for (let i = 0; i < 100; i++) {
      const hex = `e${i.toString(16).padStart(63, "0")}`;
      blobs.blobs.set(`document/${hex}`, new Uint8Array([1]));
      blobs.uploadedAt.set(`document/${hex}`, NOW);
      await store.setIfAbsent(postedKey(hex), `${REGISTRY_DEPLOY_BLOCK}:1`, 3600);
      await store.setIfAbsent(`verified:${hex}`, "1", 3600);
    }
    let elapsed = 0;
    const real = blobs.read.bind(blobs);
    const read = vi.spyOn(blobs, "read").mockImplementation(async (url, cap, signal) => {
      elapsed += 100_000;
      return real(url, cap, signal);
    });
    const clock = (): number => elapsed;

    // A run that keeps leaving work behind must not hold the cursor, or names further on wait forever.
    expect(await sweep({ clock })).toMatchObject({ done: "swept", deleted: 3, deferred: 2, outOfTime: true });
    expect(await sweep({ clock })).toMatchObject({ done: "swept", deleted: 0, deferred: 0, outOfTime: false });
    expect(read).toHaveBeenCalledTimes(3);
    expect(await sweep({ clock })).toMatchObject({ done: "swept", deleted: 2, deferred: 0, outOfTime: false });
    expect(mismatched.filter(({ name }) => blobs.blobs.has(`document/${name}`))).toEqual([]);
  });

  it("skips and reports a posted document it cannot read, never deletes it, and carries on with the next blob and the next page", async () => {
    const unreadable = "0".repeat(64);
    const mismatched = ["1", "a", "b"].map((digit) => digit.repeat(64));
    const { blobs, sweep } = await postedUnverified([unreadable, ...mismatched].map((name) => ({ name, bytes: bytesOf(900, 130) })));
    // A hundred unposted documents sort between them, so the last two mismatches are on the second page.
    for (let i = 0; i < 100; i++) {
      const pathname = `document/5${i.toString(16).padStart(63, "0")}`;
      blobs.blobs.set(pathname, new Uint8Array([1]));
      blobs.uploadedAt.set(pathname, NOW);
    }
    const real = blobs.read.bind(blobs);
    vi.spyOn(blobs, "read").mockImplementation(async (url, cap, signal) => {
      if (url.pathname === `/document/${unreadable}`) throw new Error("The blob store answered 500.");
      return real(url, cap, signal);
    });

    expect(await sweep()).toMatchObject({ done: "swept", deleted: 103, unreadable: [unreadable] });
    expect([...blobs.blobs.keys()]).toEqual([`document/${unreadable}`]);
    expect(warned()).toContainEqual({ event: "document_read_failed", sha256: unreadable, reason: "read_failed" });
    for (const name of mismatched) expect(warned()).toContainEqual({ event: "document_mismatch_deleted", sha256: name, reason: "hash_mismatch" });
  });

  it("finds in each posted mark the cipherSize of every DocumentPosted naming the document, up to POSTED_SIZES_MAX of them", async () => {
    let head = NOW - HOUR;
    const store = new MemoryStore({ now: () => NOW });
    const blobs = new MemoryBlobBackend(ORIGIN);
    const chain = stubChain(GENESIS, () => head);
    const [once, twice, crowded, before] = ["once", "twice", "crowded", "before"].map((label) => hexOf(new TextEncoder().encode(label))) as [string, string, string, string];
    chain.post(once, 1_000);
    chain.post(twice, 2_000);
    await scan(store, blobs, chain.logs, NOW);
    const first = await store.get(postedKey(once));
    expect(first).toMatch(/^\d+:1000$/);
    expect(await sizesPosted(store, twice)).toEqual([2_000n]);

    // Read by a later run: one hash posted again with another size and with its first, one posted
    // with more sizes than a mark tracks, and one whose mark was written before marks held sizes.
    head = NOW;
    chain.post(twice, 1_999);
    chain.post(twice, 2_000);
    chain.post(once, 1_000);
    for (let size = 1; size <= POSTED_SIZES_MAX + 1; size++) chain.post(crowded, size);
    const blockOnly = String(REGISTRY_DEPLOY_BLOCK + 7n);
    await store.setIfAbsent(postedKey(before), blockOnly, 3600);
    chain.post(before, 5);
    await scan(store, blobs, chain.logs, NOW);
    expect(await store.get(postedKey(once))).toBe(first);
    expect(await sizesPosted(store, twice)).toEqual([1_999n, 2_000n]);
    expect(await store.get(postedKey(crowded))).toMatch(/^\d+$/);
    expect(await sizesPosted(store, crowded)).toBeUndefined();
    expect(await store.get(postedKey(before))).toBe(blockOnly);
    expect(await sizesPosted(store, before)).toBeUndefined();

    for (const raw of ["", "abc", "12:", "12:0", "12:26214401", "12:5,5", "12:6,5", "12:1,2,3,4,5", "12:05", "-1:5", "12:5 "]) expect({ raw, sizes: postedSizes(raw) }).toEqual({ raw, sizes: undefined });
    for (const cipherSize of [0n, BigInt(DOCUMENT_CAP) + 1n, 1_000 as unknown as bigint]) {
      const lying: EnvelopeLogs = { ...chain.logs, documentPosts: async () => [{ cipherHash: `0x${once}`, cipherSize }] };
      await expect(scan(new MemoryStore({ now: () => NOW }), blobs, lying, NOW)).rejects.toThrow();
    }
  });

  it("deletes a posted document whose size is no posted cipherSize, verified or not, reading only the unverified, and logs it", async () => {
    let clock = NOW;
    const store = new MemoryStore({ now: () => clock });
    const blobs = new MemoryBlobBackend(ORIGIN, { now: () => clock });
    const chain = stubChain(GENESIS, () => clock);
    const ctx = context({ store, blobs });
    const [verifiedShort, verifiedRight, verifiedTwice, unverifiedLong, unverifiedRight] = [800, 700, 500, 900, 600].map((size, i) => bytesOf(size, 140 + i)) as [Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array];
    for (const bytes of [verifiedShort, verifiedRight, verifiedTwice]) {
      await blobs.put(`document/${hexOf(bytes)}`, bytes);
      expect((await handleDocumentVerify(post("verify", { sha256: hexOf(bytes) }), ctx)).status).toBe(200);
    }
    for (const bytes of [unverifiedLong, unverifiedRight]) await blobs.put(`document/${hexOf(bytes)}`, bytes);
    chain.post(hexOf(verifiedShort), 799);
    chain.post(hexOf(verifiedRight), 700);
    chain.post(hexOf(verifiedTwice), 499);
    chain.post(hexOf(verifiedTwice), 500);
    chain.post(hexOf(unverifiedLong), 901);
    chain.post(hexOf(unverifiedRight), 600);
    clock = NOW + 2 * HOUR + MINUTE;
    await scan(store, blobs, chain.logs, clock);
    const read = vi.spyOn(blobs, "read");

    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ done: "swept", deleted: 2, unreadable: [] });
    expect([...blobs.blobs.keys()].sort()).toEqual([verifiedRight, verifiedTwice, unverifiedRight].map((bytes) => `document/${hexOf(bytes)}`).sort());
    expect(read.mock.calls.map(([url]) => url.pathname).sort()).toEqual([unverifiedLong, unverifiedRight].map((bytes) => `/document/${hexOf(bytes)}`).sort());
    expect(await store.get(`verified:${hexOf(unverifiedLong)}`)).toBeNull();
    expect(await store.get(`verified:${hexOf(unverifiedRight)}`)).toBe("600");
    expect(warned()).toContainEqual({ event: "document_size_mismatch", sha256: hexOf(verifiedShort), size: 800, posted: "799" });
    expect(warned()).toContainEqual({ event: "document_size_mismatch", sha256: hexOf(unverifiedLong), size: 900, posted: "901" });
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 0 });
  });

  it("keeps a posted document whose mark was written before marks held sizes, deleting it only for a hash mismatch", async () => {
    const verified = bytesOf(800, 150);
    const matching = bytesOf(900, 151);
    const wrong = hexOf(bytesOf(900, 152));
    const { store, blobs, sweep } = await postedUnverified([
      { name: hexOf(verified), bytes: verified, size: 1 },
      { name: hexOf(matching), bytes: matching, size: 1 },
      { name: wrong, bytes: bytesOf(900, 153), size: 1 },
    ]);
    for (const name of [hexOf(verified), hexOf(matching), wrong]) {
      await store.delete(postedKey(name));
      await store.setIfAbsent(postedKey(name), String(REGISTRY_DEPLOY_BLOCK + 9n), 3600);
    }
    await store.setIfAbsent(`verified:${hexOf(verified)}`, "800", 3600);

    expect(await sweep()).toMatchObject({ done: "swept", deleted: 1 });
    expect([...blobs.blobs.keys()].sort()).toEqual([`document/${hexOf(verified)}`, `document/${hexOf(matching)}`].sort());
    expect(await store.get(`verified:${hexOf(matching)}`)).toBe("900");
    expect(warned()).toContainEqual({ event: "document_mismatch_deleted", sha256: wrong, reason: "hash_mismatch" });
    expect(warned().filter((line) => (line as { event: string }).event === "document_size_mismatch")).toEqual([]);
  });
});

describe("document lifetime", () => {
  it("deletes verified documents no DocumentPosted names once two hours have passed, and keeps a posted one", async () => {
    let clock = NOW;
    const store = new MemoryStore({ now: () => clock });
    const blobs = new MemoryBlobBackend(ORIGIN, { now: () => clock });
    const chain = stubChain(GENESIS, () => clock);
    const ctx = context({ store, blobs });
    const hexes: string[] = [];
    for (let i = 0; i < 13; i++) {
      const bytes = bytesOf(1_000, 60 + i);
      hexes.push(hexOf(bytes));
      await blobs.put(`document/${hexOf(bytes)}`, bytes);
      expect((await handleDocumentVerify(post("verify", { sha256: hexOf(bytes) }), ctx)).status).toBe(200);
    }
    const [posted, ...unposted] = hexes as [string, ...string[]];
    clock += 5 * MINUTE;
    chain.post(posted, 1_000);

    clock = NOW + 2 * HOUR - MINUTE;
    await scan(store, blobs, chain.logs, clock);
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 0 });
    clock = NOW + 2 * HOUR + MINUTE;
    await scan(store, blobs, chain.logs, clock);
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 12 });
    expect([...blobs.blobs.keys()]).toEqual([`document/${posted}`]);
    for (const hex of unposted) expect(await store.get(`verified:${hex}`)).toBeNull();

    clock += 48 * HOUR;
    await scan(store, blobs, chain.logs, clock);
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 0 });
    expect(blobs.blobs.has(`document/${posted}`)).toBe(true);
  });

  it("keeps a document the scan has not read two hours past, however old, until the scan passes it", async () => {
    let clock = NOW;
    let head = NOW;
    const store = new MemoryStore({ now: () => clock });
    const blobs = new MemoryBlobBackend(ORIGIN, { now: () => clock });
    const chain = stubChain(GENESIS, () => head);
    await scan(store, blobs, chain.logs, clock);

    clock = NOW + MINUTE;
    const late = bytesOf(500, 80);
    const postedLate = bytesOf(500, 81);
    await blobs.put(`document/${hexOf(late)}`, late);
    await blobs.put(`document/${hexOf(postedLate)}`, postedLate);
    clock = NOW + 49 * HOUR;
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 0 });

    // Posted half an hour after its upload, in a block a scan that is behind has not reached.
    head = NOW + 31 * MINUTE;
    chain.post(hexOf(postedLate), 500);
    head = NOW + 11 * MINUTE;
    expect(await scan(store, blobs, chain.logs, clock)).toMatchObject({ caughtUp: true });
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 0 });

    head = clock;
    await scan(store, blobs, chain.logs, clock);
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 1 });
    expect(blobs.blobs.has(`document/${hexOf(late)}`)).toBe(false);
    expect(blobs.blobs.has(`document/${hexOf(postedLate)}`)).toBe(true);
  });

  it("deletes a document's verified mark with it, so other bytes later uploaded under its name are read and refused, never vouched for", async () => {
    let clock = NOW;
    const store = new MemoryStore({ now: () => clock });
    const blobs = new MemoryBlobBackend(ORIGIN, { now: () => clock });
    const chain = stubChain(GENESIS, () => clock);
    const unposted = bytesOf(1_000, 170);
    const misfit = bytesOf(800, 171);
    for (const bytes of [unposted, misfit]) {
      await blobs.put(`document/${hexOf(bytes)}`, bytes);
      expect((await handleDocumentVerify(post("verify", { sha256: hexOf(bytes) }), context({ store, blobs }))).status).toBe(200);
    }
    chain.post(hexOf(misfit), 799);
    clock = NOW + 2 * HOUR + MINUTE;
    await scan(store, blobs, chain.logs, clock);
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 2 });
    for (const bytes of [unposted, misfit]) expect(await store.get(`verified:${hexOf(bytes)}`)).toBeNull();

    // The name is free again, so a fresh token lets anyone write other bytes under it.
    const ctx = context({ store, blobs, now: clock });
    const hex = hexOf(unposted);
    expect(await (await handleDocumentToken(post("token", { sha256: hex, size: 1_000 }), ctx)).json()).toMatchObject({ exists: false });
    await blobs.put(`document/${hex}`, bytesOf(1_000, 172));
    const again = await handleDocumentVerify(post("verify", { sha256: hex }), ctx);
    expect(again.status).toBe(409);
    expect(await again.json()).toEqual({ error: "hash_mismatch" });
    expect(blobs.blobs.has(`document/${hex}`)).toBe(false);
    expect(await verifiedSize(store, hex)).toBeUndefined();
  });

  it("reads again from the deploy block when the cursor was moved by a scan that marked no documents", async () => {
    let clock = NOW;
    const store = new MemoryStore({ now: () => clock });
    const blobs = new MemoryBlobBackend(ORIGIN, { now: () => clock });
    const chain = stubChain(GENESIS, () => clock);
    const posted = bytesOf(700, 95);
    await blobs.put(`document/${hexOf(posted)}`, posted);
    chain.post(hexOf(posted), 700);
    const envelopesOnly: EnvelopeLogs = { latestBlock: chain.logs.latestBlock, envelopeHashes: chain.logs.envelopeHashes };
    await scan(store, blobs, envelopesOnly, clock);

    clock = NOW + 3 * HOUR;
    await scan(store, blobs, chain.logs, clock);
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 0 });
    expect(blobs.blobs.has(`document/${hexOf(posted)}`)).toBe(true);
  });

  it("keeps every posted document through a wiped store, while the scan rebuilds its marks from the deploy block", async () => {
    let clock = NOW;
    let store = new MemoryStore({ now: () => clock });
    const blobs = new MemoryBlobBackend(ORIGIN, { now: () => clock });
    // A week of blocks: more than one run's 50 pages, so the rebuild takes two runs.
    const chain = stubChain(NOW - 7 * 24 * HOUR, () => clock);
    const posted = bytesOf(800, 90);
    const unposted = bytesOf(800, 91);
    for (const bytes of [posted, unposted]) {
      await blobs.put(`document/${hexOf(bytes)}`, bytes);
      expect((await handleDocumentVerify(post("verify", { sha256: hexOf(bytes) }), context({ store, blobs }))).status).toBe(200);
    }
    clock += 10 * MINUTE;
    chain.post(hexOf(posted), 800);

    clock = NOW + 90 * MINUTE;
    store = new MemoryStore({ now: () => clock });
    const again = await handleDocumentVerify(post("verify", { sha256: hexOf(posted) }), context({ store, blobs, now: clock }));
    expect(again.status).toBe(409);
    clock = NOW + 48 * HOUR;
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 0 });
    expect(await scan(store, blobs, chain.logs, clock)).toMatchObject({ caughtUp: false });
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 0 });
    expect(await scan(store, blobs, chain.logs, clock)).toMatchObject({ caughtUp: true });
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 1 });
    expect(blobs.blobs.has(`document/${hexOf(posted)}`)).toBe(true);
    expect(blobs.blobs.has(`document/${hexOf(unposted)}`)).toBe(false);
  });

  it("names the posted and referenced marks for the registry, so marks no scan of it wrote keep nothing, and rebuilds its own from the deploy block before it deletes anything named by a hash", async () => {
    let clock = NOW;
    const store = new MemoryStore({ now: () => clock });
    const blobs = new MemoryBlobBackend(ORIGIN, { now: () => clock });
    const chain = stubChain(GENESIS, () => clock);
    const [ours, theirs] = [bytesOf(700, 200), bytesOf(700, 201)];
    for (const bytes of [ours, theirs]) await blobs.put(`document/${hexOf(bytes)}`, bytes);
    const [granted, stale] = [hexOf(bytesOf(50, 202)), hexOf(bytesOf(50, 203))];
    for (const hex of [granted, stale]) await blobs.put(`envelope/${hex}`, new Uint8Array([1]));
    chain.post(hexOf(ours), 700);
    const grantedAt = await chain.logs.latestBlock();
    const logs: EnvelopeLogs = { ...chain.logs, envelopeHashes: async (fromBlock, toBlock) => (grantedAt >= fromBlock && grantedAt <= toBlock ? [`0x${granted}` as Hex] : []) };
    // What the store held before marks named a registry: marks by hash alone, here for blobs this
    // registry never named, and this registry's scan cursor and scan point, read up to now.
    const registry = REGISTRY_ADDRESS.toLowerCase();
    await store.setIfAbsent(`posted:${hexOf(theirs)}`, `${REGISTRY_DEPLOY_BLOCK}:700`, 3600);
    await store.setIfAbsent(`referenced:${stale}`, String(REGISTRY_DEPLOY_BLOCK), 3600);
    clock = NOW + 3 * HOUR;
    const head = await chain.logs.latestBlock();
    await store.setIfAbsent(`envsweep:next-block:${registry}`, String(head + 1n), 3600);
    await store.setIfAbsent(`docsweep:scanned-through:${registry}`, `${head}:${clock}`, 3600);

    expect(postedKey(hexOf(ours))).toBe(`posted:${registry}:${hexOf(ours)}`);
    expect(referencedKey(granted)).toBe(`referenced:${registry}:${granted}`);
    // No scan has run under the new names yet, so no document named by a hash is deleted.
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 0 });
    expect(blobs.blobs.size).toBe(4);

    expect(await scan(store, blobs, logs, clock)).toMatchObject({ caughtUp: true, referenced: 1, deleted: 1 });
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 1 });
    expect([...blobs.blobs.keys()].sort()).toEqual([`document/${hexOf(ours)}`, `envelope/${granted}`].sort());
    expect(await sizesPosted(store, hexOf(ours))).toEqual([700n]);
    expect(await store.get(referencedKey(granted))).not.toBeNull();
  });

  it("ignores a scan cursor and scan point another registry's scan left, so this registry's earlier posts are still marked and kept", async () => {
    let clock = NOW;
    const store = new MemoryStore({ now: () => clock });
    const blobs = new MemoryBlobBackend(ORIGIN, { now: () => clock });
    const chain = stubChain(GENESIS, () => clock);
    const posted = bytesOf(600, 180);
    await blobs.put(`document/${hexOf(posted)}`, posted);
    chain.post(hexOf(posted), 600);
    clock = NOW + 3 * HOUR;
    // Left under the names every scan used before they named a registry, read through a block an
    // hour past this post: what a scan of the previous registry leaves when the app moves to a new one.
    const far = REGISTRY_DEPLOY_BLOCK + 90_000n;
    await store.setIfAbsent("envsweep:next-block", String(far + 1n), 3600);
    await store.setIfAbsent("docsweep:scanned-through", `${far}:${NOW + HOUR}`, 3600);

    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 0 });
    expect(await scan(store, blobs, chain.logs, clock)).toMatchObject({ caughtUp: true });
    expect(await sweepUnverified({ blobs, store, blobOrigin: ORIGIN, now: clock })).toMatchObject({ deleted: 0 });
    expect(blobs.blobs.has(`document/${hexOf(posted)}`)).toBe(true);
    expect(await sizesPosted(store, hexOf(posted))).toEqual([600n]);
  });
});
