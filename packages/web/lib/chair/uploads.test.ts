// Covers what the chair's browser sends and accepts around an upload (threat model C28, C45): the
// hash and size it will sign are its own, each request has the shape the server takes, and an answer
// that names other bytes is refused. Does NOT cover our server's handlers or the blob store (the
// server's tests and the live run do), or the real network.
import { sha256 } from "@ava/core";
import { bytesToHex } from "viem";
import { beforeEach, describe, expect, it, vi } from "vitest";

const calls: { path: string; json?: unknown; bytes?: Uint8Array }[] = [];
let answers: Record<string, { status: number; body: unknown }> = {};
const puts: { pathname: string; size: number; options: Record<string, unknown> }[] = [];

vi.mock("../api", () => ({
  api: async (path: string, call: { json?: unknown; bytes?: Uint8Array }) => {
    calls.push({ path, json: call.json, bytes: call.bytes });
    const answer = answers[path] ?? { status: 500, body: {} };
    return new Response(JSON.stringify(answer.body), { status: answer.status });
  },
}));
vi.mock("@vercel/blob/client", () => ({
  put: async (pathname: string, body: Blob, options: Record<string, unknown>) => {
    puts.push({ pathname, size: body.size, options });
    return { url: `https://store.example/${pathname}` };
  },
}));

const { UploadRefused, uploadDocument, uploadEnvelope } = await import("./uploads");

const signal = new AbortController().signal;
const bytes = Uint8Array.from({ length: 118 }, (_, i) => (i * 7) % 251);
const hex = bytesToHex(sha256(bytes)).slice(2);
const token = { exists: false, pathname: `document/${hex}`, token: "one-time-token-for-the-test", contentType: "application/octet-stream", maxBytes: 118, validUntil: 1 };

beforeEach(() => {
  calls.length = 0;
  puts.length = 0;
  answers = {};
});

describe("uploadDocument", () => {
  it("asks for a token with the hash and size, uploads those bytes under that name, then asks for the check by hash alone", async () => {
    answers = { "/api/document/token": { status: 200, body: token }, "/api/document/verify": { status: 200, body: { sha256: hex, size: 118, url: "x" } } };
    const stored = await uploadDocument(bytes, signal);
    expect(stored).toEqual({ hash: `0x${hex}`, size: 118n });
    expect(calls.map((c) => [c.path, c.json])).toEqual([
      ["/api/document/token", { sha256: hex, size: 118 }],
      ["/api/document/verify", { sha256: hex }],
    ]);
    expect(puts).toHaveLength(1);
    expect(puts[0]).toMatchObject({ pathname: `document/${hex}`, size: 118, options: { access: "public", token: token.token, contentType: "application/octet-stream" } });
  });

  it("skips the upload when the store already holds these bytes, and still has them checked", async () => {
    answers = { "/api/document/token": { status: 200, body: { exists: true, url: "x" } }, "/api/document/verify": { status: 200, body: { sha256: hex, size: 118, url: "x" } } };
    await expect(uploadDocument(bytes, signal)).resolves.toEqual({ hash: `0x${hex}`, size: 118n });
    expect(puts).toHaveLength(0);
    expect(calls.map((c) => c.path)).toEqual(["/api/document/token", "/api/document/verify"]);
  });

  it("refuses a token for another name, another type or another size, and uploads nothing", async () => {
    for (const over of [{ pathname: `document/${"0".repeat(64)}` }, { contentType: "text/html" }, { maxBytes: 119 }, { token: undefined }]) {
      answers = { "/api/document/token": { status: 200, body: { ...token, ...over } } };
      await expect(uploadDocument(bytes, signal)).rejects.toThrow(/not for this ciphertext/);
    }
    expect(puts).toHaveLength(0);
  });

  it("refuses a check that names other bytes or another size", async () => {
    answers = { "/api/document/token": { status: 200, body: token }, "/api/document/verify": { status: 200, body: { sha256: "0".repeat(64), size: 118 } } };
    await expect(uploadDocument(bytes, signal)).rejects.toThrow(/does not name the ciphertext/);
    answers = { "/api/document/token": { status: 200, body: token }, "/api/document/verify": { status: 200, body: { sha256: hex, size: 119 } } };
    await expect(uploadDocument(bytes, signal)).rejects.toThrow(/does not name the ciphertext/);
  });

  it("passes on our server's own reason for a refusal, digits and all", async () => {
    answers = { "/api/document/token": { status: 429, body: { error: "upload_bytes" } } };
    await expect(uploadDocument(bytes, signal)).rejects.toMatchObject({ name: "UploadRefused", status: 429, reason: "upload_bytes" });
    answers = { "/api/document/token": { status: 200, body: token }, "/api/document/verify": { status: 400, body: { error: "bad_sha256" } } };
    const refused = await uploadDocument(bytes, signal).catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(UploadRefused);
    expect(refused).toMatchObject({ status: 400, reason: "bad_sha256" });
  });
});

describe("uploadEnvelope", () => {
  it("sends the raw bytes and returns its own hash and size once the store's answer names them", async () => {
    answers = { "/api/upload?kind=envelope": { status: 201, body: { sha256: hex, size: 118, url: "x" } } };
    await expect(uploadEnvelope(bytes, signal)).resolves.toEqual({ hash: `0x${hex}`, size: 118 });
    expect(calls).toHaveLength(1);
    expect(bytesToHex(calls[0]?.bytes ?? new Uint8Array())).toBe(bytesToHex(bytes));
  });

  it("refuses an answer that names another hash or size, so a hash the server supplied is never signed", async () => {
    answers = { "/api/upload?kind=envelope": { status: 200, body: { sha256: "0".repeat(64), size: 118 } } };
    await expect(uploadEnvelope(bytes, signal)).rejects.toThrow(/does not name the envelope/);
    answers = { "/api/upload?kind=envelope": { status: 200, body: { sha256: hex, size: 117 } } };
    await expect(uploadEnvelope(bytes, signal)).rejects.toThrow(/does not name the envelope/);
  });

  it("passes on a refusal", async () => {
    answers = { "/api/upload?kind=envelope": { status: 429, body: { error: "rate_limited" } } };
    await expect(uploadEnvelope(bytes, signal)).rejects.toMatchObject({ name: "UploadRefused", status: 429, reason: "rate_limited" });
  });
});
