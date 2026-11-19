import { randomBytes } from "node:crypto";
import { MAX_ENVELOPE_SIZE, newEpochKey, sealEpochKey, sha256 } from "@ava/core";
import { DOCUMENT_CAP, DOCUMENT_CONTENT_TYPE, VERIFY_WINDOW_MS } from "../../packages/server/src/docupload.ts";
import { notRun, verdict, type Attack, type Probe } from "../lib/attack.ts";
import { readBlob } from "../lib/blobs.ts";
import { sleep } from "../lib/chain.ts";
import type { Ctx } from "../lib/context.ts";
import { dev, devOrReset, notConfigured, ownHeaders, said, type DevAnswer } from "../lib/dev.ts";
import { REGISTRY, noteIssuedToken, storePut } from "../lib/guard.ts";
import { random32 } from "../lib/registry.ts";

const OCTET = { "content-type": "application/octet-stream" };
const JSON_HEADERS = { "content-type": "application/json" };
/** A blob the CDN has not seen yet answers 404 at once; a deleted one can take a little while to go. */
const DELETE_SEEN_WITHIN_MS = 60_000;
/** Past the 50-minute verify window, with two minutes between our clock and the store's. */
const MARK_ONLY_AFTER_MS = VERIFY_WINDOW_MS + 120_000;

const hexOf = (bytes: Uint8Array): string => Buffer.from(sha256(bytes)).toString("hex");
const sameBytes = (a: Uint8Array | undefined, b: Uint8Array): boolean => a !== undefined && Buffer.from(a).equals(Buffer.from(b));

/** A real QoreSeal envelope, sealed locally to the wallet's own ML-KEM key; it never goes on chain. */
function testEnvelope(ctx: Ctx): Uint8Array {
  return sealEpochKey({ registry: REGISTRY, boardRef: random32(), epoch: 0n, epochKey: newEpochKey(), recipients: [{ address: ctx.wallet.evm, kemPublicKey: ctx.wallet.seal.mlkemPublicKey }] });
}

const upload = (from: string, path: string, body: Uint8Array, extra: { chunked?: boolean; headers?: Record<string, string> } = {}): Promise<DevAnswer> =>
  dev({ method: "POST", path, from, headers: { ...OCTET, ...extra.headers }, body, ...(extra.chunked ? { chunked: true } : {}) });

const token = (from: string, sha: string): Promise<DevAnswer> => dev({ method: "POST", path: "/api/document/token", from, headers: JSON_HEADERS, body: JSON.stringify({ sha256: sha }) });
const verify = (from: string, sha: string): Promise<DevAnswer> => dev({ method: "POST", path: "/api/document/verify", from, headers: JSON_HEADERS, body: JSON.stringify({ sha256: sha }), timeoutMs: 60_000 });

/** A token our handler issued for exactly this hash, or undefined. Every token is recorded with the guard before it is used. */
function issued(a: DevAnswer, sha: string): string | undefined {
  const j = a.json as { exists?: unknown; pathname?: unknown; token?: unknown; contentType?: unknown; maxBytes?: unknown } | undefined;
  if (a.status !== 200 || j?.exists !== false || j.pathname !== `document/${sha}` || j.contentType !== DOCUMENT_CONTENT_TYPE || j.maxBytes !== DOCUMENT_CAP || typeof j.token !== "string") return undefined;
  noteIssuedToken(j.token);
  return j.token;
}

/** One upload straight to the store with a client token, the way a browser makes it. */
async function put(pathname: string, bytes: Uint8Array, tokenValue: string, contentType: string): Promise<{ ok: true; url: string } | { ok: false; why: string }> {
  try {
    const r = await storePut(pathname, bytes, { token: tokenValue, contentType });
    return { ok: true, url: r.url };
  } catch (err) {
    // The blob client's errors leave `name` as "Error"; only their class tells them apart.
    const name = err instanceof Error ? (err.constructor?.name || err.name) : "Error";
    const message = err instanceof Error ? err.message.replace(/\s+/g, " ").slice(0, 160) : String(err);
    return { ok: false, why: `${name}: ${message}` };
  }
}

/**
 * Refused by the store itself: the client library answered with one of the store's own refusal
 * errors. Not counted: the client's own size check (it makes no other before sending), and every
 * error that means no answer came back (network, abort, rate limit, service down, unknown). Each
 * attack also shows the effect where it can, because the store's wording is not ours to rely on.
 */
const refusedByStore = (r: { ok: true; url: string } | { ok: false; why: string }): boolean => {
  if (r.ok) return false;
  const name = r.why.split(":")[0] ?? "";
  const noAnswer = ["TypeError", "BlobUnknownError", "BlobServiceNotAvailable", "BlobServiceRateLimited", "BlobRequestAbortedError"].includes(name);
  return name.startsWith("Blob") && !noAnswer && !/Body size of \d+ bytes exceeds/.test(r.why);
};
const putLine = (label: string, r: { ok: true; url: string } | { ok: false; why: string }): string => `${label}: ${r.ok ? `STORED at ${r.url}` : `refused by the store (${r.why})`}`;

const notEnvelope: Attack = {
  id: "C28-not-envelope",
  claim: "The envelope upload stores only QoreSeal envelopes, under the server's own hash: random bytes and the qoreseal: text form are refused, so are another kind, an extra query, no query, a stated or streamed body over 110,000 bytes and GET; a real envelope is stored under its SHA-256.",
  costUqor: 0n,
  async run(ctx) {
    const from = ctx.ips.fresh();
    const real = testEnvelope(ctx);
    const sha = hexOf(real);
    const cases: [string, () => Promise<DevAnswer | undefined>, number, string?][] = [
      ["2,000 random bytes", () => upload(from, "/api/upload?kind=envelope", randomBytes(2_000)), 400, "not_an_envelope"],
      ["the envelope as qoreseal: text", () => upload(from, "/api/upload?kind=envelope", new TextEncoder().encode(`qoreseal:${Buffer.from(real).toString("base64")}`)), 400, "not_an_envelope"],
      ["kind=document", () => upload(from, "/api/upload?kind=document", real), 400, "bad_kind"],
      ["kind=envelope&x=1", () => upload(from, "/api/upload?kind=envelope&x=1", real), 400, "bad_kind"],
      ["no query", () => upload(from, "/api/upload", real), 400, "bad_kind"],
      [`${MAX_ENVELOPE_SIZE + 1} bytes with content-length`, () => devOrReset({ method: "POST", path: "/api/upload?kind=envelope", from, headers: OCTET, body: randomBytes(MAX_ENVELOPE_SIZE + 1) }), 413, "body_too_large"],
      ["120,000 bytes streamed, no length", () => devOrReset({ method: "POST", path: "/api/upload?kind=envelope", from, headers: OCTET, body: randomBytes(120_000), chunked: true }), 413, "body_too_large"],
      ["GET", () => dev({ method: "GET", path: "/api/upload?kind=envelope", from }), 405, "method_not_allowed"],
    ];
    const probes: Probe[] = [];
    for (const [label, send, status, error] of cases) {
      const a = await send();
      if (a === undefined) {
        probes.push({ ok: true, line: `${label} -> the server closed the connection after its cap, with no answer` });
        continue;
      }
      if (notConfigured(a)) return notRun(`the upload answers ${said(a)}`);
      probes.push({ ok: a.status === status && a.error === error && ownHeaders(a), line: `${label} -> ${said(a)}` });
    }
    const control = await upload(from, "/api/upload?kind=envelope", real);
    const j = control.json as { sha256?: unknown; size?: unknown; url?: unknown } | undefined;
    const stored = (control.status === 201 || control.status === 200) && j?.sha256 === sha && j.size === real.length && typeof j.url === "string";
    if (stored) ctx.state.envelope = { sha, url: j.url as string, bytes: real };
    probes.push({ ok: stored, line: `control, a real ${real.length}-byte envelope -> ${said(control)}, sha256 ${String(j?.sha256).slice(0, 16)}... (the server's hash of what it got: ${sha.slice(0, 16)}...)` });
    return verdict(probes, `from ${from}: `);
  },
};

const urlCheck: Attack = {
  id: "C30-url",
  claim: "Readers fetch only the expected location: the URL the upload returns is exactly BLOB_ORIGIN/envelope/<sha256>, and the bytes served there hash to that name.",
  costUqor: 0n,
  async run(ctx) {
    if (ctx.env.blobOrigin === undefined) return notRun("BLOB_ORIGIN is not set in security/.env");
    const e = ctx.state.envelope;
    if (e === undefined) return notRun("C28-not-envelope stored no control envelope");
    const expected = new URL(`${ctx.env.blobOrigin}/envelope/${e.sha}`).href;
    const read = await readBlob(e.url, MAX_ENVELOPE_SIZE);
    return verdict([
      { ok: new URL(e.url).href === expected, line: `returned URL ${e.url} ${new URL(e.url).href === expected ? "equals" : "DIFFERS FROM"} ${expected}` },
      { ok: read.status === 200 && read.bytes !== undefined && hexOf(read.bytes) === e.sha && sameBytes(read.bytes, e.bytes), line: `GET of it: ${read.status}, ${read.bytes?.length ?? 0} bytes, sha256 ${read.bytes === undefined ? "none" : hexOf(read.bytes).slice(0, 16)}...` },
    ]);
  },
};

const tokenPathname: Attack = {
  id: "C28-token-pathname",
  claim: "A document token allows exactly one pathname: our handler issues it for document/<sha256> only, octet-stream, 25 MiB, and the store refuses the same token for another pathname, which stays empty.",
  costUqor: 0n,
  async run(ctx) {
    if (ctx.env.blobOrigin === undefined) return notRun("BLOB_ORIGIN is not set in security/.env");
    const from = ctx.ips.fresh();
    const x = randomBytes(4_096);
    const sha = hexOf(x);
    const t = await token(from, sha);
    if (notConfigured(t)) return notRun(`the token endpoint answers ${said(t)}`);
    const value = issued(t, sha);
    if (value === undefined) return verdict([{ ok: false, line: `token request -> ${said(t)}, not a token for document/${sha.slice(0, 16)}...` }]);
    ctx.state.docToken = { token: value, x, sha };
    const y = randomBytes(4_096);
    const r = await put(`document/${hexOf(y)}`, y, value, DOCUMENT_CONTENT_TYPE);
    // Nothing was ever stored or read at this name before, so a 404 here is not a cached one.
    const read = await readBlob(new URL(`${ctx.env.blobOrigin}/document/${hexOf(y)}`).href, y.length + 1);
    return verdict([
      { ok: true, line: `token issued for document/${sha.slice(0, 16)}..., ${DOCUMENT_CONTENT_TYPE}, at most ${DOCUMENT_CAP} bytes` },
      { ok: refusedByStore(r), line: putLine("the same token for another pathname", r) },
      { ok: read.status === 404, line: `that other pathname read back: ${read.status}` },
    ]);
  },
};

const tokenType: Attack = {
  id: "C28-token-type",
  claim: "A document token allows only application/octet-stream: the store refuses the same token and pathname with text/html and with image/svg+xml.",
  costUqor: 0n,
  async run(ctx) {
    const d = ctx.state.docToken;
    if (d === undefined) return notRun("C28-token-pathname issued no token");
    const html = await put(`document/${d.sha}`, d.x, d.token, "text/html");
    const svg = await put(`document/${d.sha}`, d.x, d.token, "image/svg+xml");
    return verdict([
      { ok: refusedByStore(html), line: putLine("text/html", html) },
      { ok: refusedByStore(svg), line: putLine("image/svg+xml", svg) },
    ]);
  },
};

const tokenOverwrite: Attack = {
  id: "C28-token-overwrite",
  claim: "An existing name is never overwritten: the token's own upload is stored at BLOB_ORIGIN/document/<sha256>, a second upload of other bytes under that name with the same token is refused, and the stored bytes still hash to the name.",
  costUqor: 0n,
  async run(ctx) {
    if (ctx.env.blobOrigin === undefined) return notRun("BLOB_ORIGIN is not set in security/.env");
    const d = ctx.state.docToken;
    if (d === undefined) return notRun("C28-token-pathname issued no token");
    const first = await put(`document/${d.sha}`, d.x, d.token, DOCUMENT_CONTENT_TYPE);
    const uploadedAt = Date.now();
    const expected = new URL(`${ctx.env.blobOrigin}/document/${d.sha}`).href;
    const second = await put(`document/${d.sha}`, randomBytes(4_096), d.token, DOCUMENT_CONTENT_TYPE);
    const read = await readBlob(expected, d.x.length + 1);
    if (first.ok) ctx.state.upload = { sha: d.sha, url: expected, uploadedAt, bytes: d.x.length };
    return verdict([
      { ok: first.ok && new URL(first.url).href === expected, line: `control, the token's own upload: ${first.ok ? `stored at ${first.url}` : `REFUSED (${first.why})`}` },
      { ok: refusedByStore(second), line: putLine("other bytes under the same name", second) },
      { ok: read.status === 200 && sameBytes(read.bytes, d.x), line: `read back: ${read.status}, ${read.bytes?.length ?? 0} bytes, ${sameBytes(read.bytes, d.x) ? "the first upload's bytes" : "NOT THE FIRST UPLOAD'S BYTES"}` },
    ]);
  },
};

const headers: Attack = {
  id: "C29-headers",
  claim: "Blobs are served as plain bytes that cannot run: an envelope and a document come from a separate origin as application/octet-stream, attachment, nosniff, with Content-Security-Policy default-src 'none'.",
  costUqor: 0n,
  async run(ctx) {
    if (ctx.env.blobOrigin === undefined) return notRun("BLOB_ORIGIN is not set in security/.env");
    const urls = [ctx.state.envelope?.url, ctx.state.upload?.url].filter((u): u is string => u !== undefined);
    if (urls.length === 0) return notRun("no blob was stored earlier in this run");
    const host = new URL(ctx.env.blobOrigin).hostname;
    const probes: Probe[] = [{ ok: host !== "127.0.0.1" && host !== "localhost", line: `blobs come from ${host}, not the app's origin` }];
    for (const url of urls) {
      const r = await readBlob(url, MAX_ENVELOPE_SIZE);
      const h = (name: string): string => r.headers.get(name) ?? "none";
      const ok =
        r.status === 200 &&
        h("content-type") === "application/octet-stream" &&
        h("content-disposition").toLowerCase().startsWith("attachment") &&
        h("x-content-type-options").toLowerCase() === "nosniff" &&
        /default-src 'none'/.test(h("content-security-policy"));
      probes.push({ ok, line: `${new URL(url).pathname.slice(0, 26)}...: ${r.status}, content-type ${h("content-type")}, disposition ${h("content-disposition").split(";")[0]}, nosniff ${h("x-content-type-options")}, csp ${h("content-security-policy")}` });
    }
    return verdict(probes);
  },
};

const tokenSize: Attack = {
  id: "C28-token-size",
  claim: "A document token allows at most 25 MiB: the store refuses 26,214,401 bytes under the token's own pathname, and verify then finds nothing stored.",
  costUqor: 0n,
  costNote: "uploads 25 MiB of random bytes to our own store, which refuses them",
  async run(ctx) {
    const from = ctx.ips.fresh();
    const z = randomBytes(DOCUMENT_CAP + 1);
    const sha = hexOf(z);
    const t = await token(from, sha);
    if (notConfigured(t)) return notRun(`the token endpoint answers ${said(t)}`);
    const value = issued(t, sha);
    if (value === undefined) return verdict([{ ok: false, line: `token request -> ${said(t)}` }]);
    const r = await put(`document/${sha}`, z, value, DOCUMENT_CONTENT_TYPE);
    const v = await verify(from, sha);
    return verdict([
      { ok: refusedByStore(r), line: putLine(`${z.length} bytes`, r) },
      { ok: v.status === 409 && (v.error === "blob_missing" || v.error === "too_large"), line: `verify of that name -> ${said(v)}` },
    ]);
  },
};

const wrongBytes: Attack = {
  id: "C28-verify-wrong-bytes",
  claim: "Every stored document's name is the SHA-256 of what the store holds: other bytes uploaded under a token's pathname are refused at verify and deleted.",
  costUqor: 0n,
  async run(ctx) {
    if (ctx.env.blobOrigin === undefined) return notRun("BLOB_ORIGIN is not set in security/.env");
    const from = ctx.ips.fresh();
    const a = randomBytes(4_096);
    const sha = hexOf(a);
    const t = await token(from, sha);
    if (notConfigured(t)) return notRun(`the token endpoint answers ${said(t)}`);
    const value = issued(t, sha);
    if (value === undefined) return verdict([{ ok: false, line: `token request -> ${said(t)}` }]);
    const wrong = randomBytes(4_096);
    const r = await put(`document/${sha}`, wrong, value, DOCUMENT_CONTENT_TYPE);
    const v = await verify(from, sha);
    const url = new URL(`${ctx.env.blobOrigin}/document/${sha}`).href;
    let status = (await readBlob(url, 8_192)).status;
    for (const started = Date.now(); status !== 404 && Date.now() - started < DELETE_SEEN_WITHIN_MS; ) {
      await sleep(5_000);
      status = (await readBlob(url, 8_192)).status;
    }
    return verdict([
      { ok: true, line: putLine("other bytes under the token's own name", r) },
      { ok: v.status === 409 && v.error === (r.ok ? "hash_mismatch" : "blob_missing"), line: `verify -> ${said(v)}` },
      { ok: status === 404, line: `read back from the blob origin: ${status}` },
    ]);
  },
};

const verifiedKept: Attack = {
  id: "C44-verified-kept",
  claim: "A verified document is answered from its mark: verify of the document C28 stored answers 200, and again 200, and the bytes stay where they are.",
  costUqor: 0n,
  async run(ctx) {
    const u = ctx.state.upload;
    if (u === undefined) return notRun("C28-token-overwrite stored no document");
    const from = ctx.ips.fresh();
    const v1 = await verify(from, u.sha);
    const v2 = await verify(from, u.sha);
    const read = await readBlob(u.url, u.bytes + 1);
    const answered = (v: DevAnswer): boolean => v.status === 200 && (v.json as { sha256?: unknown; size?: unknown })?.sha256 === u.sha && (v.json as { size?: unknown }).size === u.bytes;
    return verdict([
      { ok: answered(v1), line: `first verify -> ${said(v1)}` },
      { ok: answered(v2), line: `second verify -> ${said(v2)}` },
      { ok: read.status === 200 && read.bytes !== undefined && hexOf(read.bytes) === u.sha, line: `read back: ${read.status}` },
    ]);
  },
};

const markOnly: Attack = {
  id: "C44-mark-only",
  claim: "A verified document blob is never deleted by a later read: more than 50 minutes after upload, when the read path would answer 409 too_old and delete it, verify still answers 200 from the mark and the blob is still served.",
  costUqor: 0n,
  costNote: "waits until 52 minutes after the C28 upload, so it runs last",
  async run(ctx) {
    const u = ctx.state.upload;
    if (u === undefined) return notRun("C28-token-overwrite stored no document");
    for (let left = u.uploadedAt + MARK_ONLY_AFTER_MS - Date.now(); left > 0; left = u.uploadedAt + MARK_ONLY_AFTER_MS - Date.now()) {
      ctx.log(`  C44-mark-only: ${Math.ceil(left / 60_000)} minutes until the document is past the verify window`);
      await sleep(Math.min(left, 300_000));
    }
    const age = Math.floor((Date.now() - u.uploadedAt) / 60_000);
    const v = await verify(ctx.ips.fresh(), u.sha);
    const read = await readBlob(u.url, u.bytes + 1);
    return verdict([
      { ok: v.status === 200, line: `verify at ${age} minutes after upload -> ${said(v)} (the read path answers 409 too_old past 50 minutes and deletes: handleDocumentVerify)` },
      { ok: read.status === 200 && read.bytes !== undefined && hexOf(read.bytes) === u.sha, line: `read back: ${read.status}, sha256 ${read.bytes === undefined ? "none" : hexOf(read.bytes).slice(0, 16)}...` },
    ]);
  },
};

export const attacks: readonly Attack[] = [notEnvelope, urlCheck, tokenPathname, tokenType, tokenOverwrite, headers, tokenSize, wrongBytes, verifiedKept];
/** Runs after every other area: it waits out the verify window. */
export const lateAttacks: readonly Attack[] = [markOnly];

