import { validateMlkemPublicKey } from "@qorechain/qoreseal";
import { concatBytes, hexToBytes, type Hex } from "viem";
import { accountBytes, sameAccount, toHex } from "./address.ts";
import { EVM_RPC, ML_KEM_1024_PUBKEY } from "./constants.ts";

const ALGORITHM_ML_KEM_1024 = 2;
const REQUEST_ID = 1;
// A full answer is about 3.3 KB: the key as hex plus a few short fields.
const MAX_RESPONSE_BYTES = 16_384;

/** Why no key came back. Every one of them stops the seal. */
export type KemKeyFailure = "NOT_FOUND" | "WRONG_ACCOUNT" | "WRONG_ALGORITHM" | "INVALID_KEY" | "MALFORMED" | "TIMEOUT" | "NETWORK";

/** No usable ML-KEM key for the address. Sealing to it must stop (threat model C15). */
export class KemKeyUnavailable extends Error {
  readonly reason: KemKeyFailure;
  constructor(reason: KemKeyFailure, message: string) {
    super(message);
    this.name = "KemKeyUnavailable";
    this.reason = reason;
  }
}

type Json = Record<string, unknown>;

function isObject(value: unknown): value is Json {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function readCapped(res: Response): Promise<string> {
  const declared = res.headers.get("content-length");
  if (declared !== null && Number(declared) > MAX_RESPONSE_BYTES) throw new KemKeyUnavailable("MALFORMED", "The KEM lookup answer is too large.");
  if (res.body === null) throw new KemKeyUnavailable("MALFORMED", "The KEM lookup answer has no body.");
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => undefined);
      throw new KemKeyUnavailable("MALFORMED", "The KEM lookup answer is too large.");
    }
    chunks.push(value);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(concatBytes(chunks));
  } catch {
    throw new KemKeyUnavailable("MALFORMED", "The KEM lookup answer is not UTF-8 text.");
  }
}

function keyFrom(result: Json, requested: Uint8Array): Uint8Array {
  if (result.found === false) throw new KemKeyUnavailable("NOT_FOUND", "This account has not published an ML-KEM key.");
  if (result.found !== true) throw new KemKeyUnavailable("MALFORMED", "The KEM lookup answer has no boolean found field.");

  let answered: Uint8Array;
  try {
    answered = accountBytes(typeof result.address === "string" ? result.address : "");
  } catch {
    throw new KemKeyUnavailable("MALFORMED", "The KEM lookup answer names no valid address.");
  }
  if (!sameAccount(answered, requested)) throw new KemKeyUnavailable("WRONG_ACCOUNT", "The KEM lookup answered for a different account.");

  if (result.algorithm_id !== ALGORITHM_ML_KEM_1024) throw new KemKeyUnavailable("WRONG_ALGORITHM", "The published key is not ML-KEM-1024 (algorithm 2).");

  const hex = result.public_key;
  if (typeof hex !== "string" || !/^0x[0-9a-fA-F]*$/.test(hex)) throw new KemKeyUnavailable("MALFORMED", "The published key is not 0x hex.");
  if (hex.length !== 2 + 2 * ML_KEM_1024_PUBKEY) throw new KemKeyUnavailable("INVALID_KEY", `The published key is not ${ML_KEM_1024_PUBKEY} bytes.`);
  const key = hexToBytes(hex as Hex);
  try {
    validateMlkemPublicKey(key);
  } catch {
    throw new KemKeyUnavailable("INVALID_KEY", "The published key fails QoreSeal's ML-KEM-1024 key check.");
  }
  return key;
}

/**
 * Reads the ML-KEM-1024 key an account has published, straight from the chain's public EVM
 * JSON-RPC with `qor_getKEMKey`, never through a server we run (threat model C15, C16).
 *
 * Returns the key only when the answer names exactly the requested 20-byte account (decoded by
 * the shared address codec), carries algorithm id 2, holds 1,568 bytes and passes QoreSeal's
 * validateMlkemPublicKey. There is no fallback to any other route. Redirects are refused, the
 * answer is capped at 16 KB, and one timeout covers the request and the body.
 *
 * Covers a key served for another account, a wrong or malformed key, and a slow or broken
 * endpoint. Does not cover a genuine key that belongs to the wrong person (the address itself
 * must come from the right person).
 *
 * @param address The account in any form accountBytes accepts.
 * @param opts.rpc An https JSON-RPC endpoint. Defaults to EVM_RPC.
 * @param opts.timeoutMs Defaults to 8,000.
 * @throws KemKeyUnavailable for found false, any mismatch, a timeout, a network failure or a
 *   malformed answer. AddressError for a bad address. TypeError for a bad rpc or timeout.
 */
export async function fetchKemKey(address: string, opts: { rpc?: string; timeoutMs?: number } = {}): Promise<Uint8Array> {
  const requested = accountBytes(address);
  const timeoutMs = opts.timeoutMs ?? 8000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new TypeError("timeoutMs must be a positive whole number of milliseconds.");
  const url = new URL(opts.rpc ?? EVM_RPC);
  if (url.protocol !== "https:") throw new TypeError("The KEM lookup only goes to an https endpoint.");

  const signal = AbortSignal.timeout(timeoutMs);
  let text: string;
  try {
    const res = await globalThis.fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: REQUEST_ID, method: "qor_getKEMKey", params: [toHex(requested)] }),
      redirect: "error",
      signal,
    });
    if (!res.ok) throw new KemKeyUnavailable("NETWORK", `The KEM lookup answered HTTP ${res.status}.`);
    text = await readCapped(res);
  } catch (err) {
    if (err instanceof KemKeyUnavailable) throw err;
    if (signal.aborted) throw new KemKeyUnavailable("TIMEOUT", `The KEM lookup took longer than ${timeoutMs} ms.`);
    throw new KemKeyUnavailable("NETWORK", "The KEM lookup could not reach the chain.");
  }

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new KemKeyUnavailable("MALFORMED", "The KEM lookup answer is not JSON.");
  }
  if (!isObject(body) || body.jsonrpc !== "2.0" || body.id !== REQUEST_ID || body.error !== undefined || !isObject(body.result)) {
    throw new KemKeyUnavailable("MALFORMED", "The KEM lookup answer is not a JSON-RPC result for this request.");
  }
  return keyFrom(body.result, requested);
}
