import { sha256 } from "@ava/core";
import { put } from "@vercel/blob/client";
import { bytesToHex, type Hex } from "viem";
import { api } from "../api";
import { throwIfStopped } from "../guest/time";

const DOCUMENT_CONTENT_TYPE = "application/octet-stream";

/** Our server or the blob store refused an upload, with the server's own short reason where it gave one. */
export class UploadRefused extends Error {
  readonly status: number;
  readonly reason: string;

  constructor(what: string, status: number, reason: string) {
    super(`${what} was refused: HTTP ${status} ${reason}.`);
    this.name = "UploadRefused";
    this.status = status;
    this.reason = reason;
  }
}

type Json = Record<string, unknown>;

async function answerOf(response: Response): Promise<Json> {
  try {
    const body: unknown = await response.json();
    return body !== null && typeof body === "object" && !Array.isArray(body) ? (body as Json) : {};
  } catch {
    return {};
  }
}

const reasonOf = (body: Json): string => (typeof body.error === "string" && /^[A-Za-z0-9_]{1,64}$/.test(body.error) ? body.error : "unknown");

/** A copy with its own buffer, which is what fetch and Blob take. */
const owned = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => Uint8Array.from(bytes);

/**
 * Stores an epoch key envelope through our server and returns what the chair will sign: the
 * envelope's SHA-256 and size, both computed here from the bytes this browser sealed. The server's
 * answer is only checked against them, so a hash a server supplied is never signed (threat model C45).
 *
 * @throws UploadRefused for a refusal. Error when the store's answer does not name these very bytes.
 */
export async function uploadEnvelope(envelope: Uint8Array, signal: AbortSignal): Promise<{ hash: Hex; size: number }> {
  throwIfStopped(signal);
  const hash = bytesToHex(sha256(envelope));
  const response = await api("/api/upload?kind=envelope", { bytes: owned(envelope), signal });
  const body = await answerOf(response);
  if (response.status !== 200 && response.status !== 201) throw new UploadRefused("The envelope upload", response.status, reasonOf(body));
  if (body.sha256 !== hash.slice(2) || body.size !== envelope.length) throw new Error("The store's answer does not name the envelope this browser sealed.");
  return { hash, size: envelope.length };
}

/**
 * Stores an encrypted pack: asks our server for a one-time token for exactly this ciphertext's hash
 * and size, uploads the bytes straight to the blob store, then has our server read them back and
 * check them. Returns the SHA-256 and size computed here, which are what the chair signs.
 *
 * @param say Told what is happening, for the page's line.
 * @throws UploadRefused for a refusal by our server. Error when a token is not for these bytes, the
 *   store refuses the write, or the verify does not name these very bytes.
 */
export async function uploadDocument(ciphertext: Uint8Array, signal: AbortSignal, say: (what: string) => void = () => undefined): Promise<{ hash: Hex; size: bigint }> {
  throwIfStopped(signal);
  const hex = bytesToHex(sha256(ciphertext)).slice(2);
  const asked = { sha256: hex, size: ciphertext.length };

  say("Asking for a one-time upload token for this ciphertext's hash and size.");
  const tokenResponse = await api("/api/document/token", { json: asked, signal });
  const token = await answerOf(tokenResponse);
  if (tokenResponse.status !== 200) throw new UploadRefused("The upload token", tokenResponse.status, reasonOf(token));

  if (token.exists !== true) {
    if (token.pathname !== `document/${hex}` || token.contentType !== DOCUMENT_CONTENT_TYPE || token.maxBytes !== ciphertext.length || typeof token.token !== "string") {
      throw new Error("The upload token is not for this ciphertext's name, type and size.");
    }
    say(`Uploading ${ciphertext.length.toLocaleString("en-US")} encrypted bytes straight to the blob store.`);
    try {
      await put(token.pathname, new Blob([owned(ciphertext)], { type: DOCUMENT_CONTENT_TYPE }), { access: "public", token: token.token, contentType: DOCUMENT_CONTENT_TYPE, abortSignal: signal });
    } catch (error) {
      throwIfStopped(signal);
      throw new Error(`The blob store refused the upload${error instanceof Error && error.message !== "" ? `: ${error.message.replace(/\s+/g, " ").slice(0, 160)}` : "."}`);
    }
  }

  say("Our server is reading the stored bytes back and checking their hash.");
  const verifyResponse = await api("/api/document/verify", { json: { sha256: hex }, signal });
  const verified = await answerOf(verifyResponse);
  if (verifyResponse.status !== 200) throw new UploadRefused("The upload check", verifyResponse.status, reasonOf(verified));
  if (verified.sha256 !== hex || verified.size !== ciphertext.length) throw new Error("The store's check does not name the ciphertext this browser made.");
  return { hash: `0x${hex}`, size: BigInt(ciphertext.length) };
}
