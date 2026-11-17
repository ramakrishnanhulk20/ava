import { sha256 as sha256Digest } from "viem";
import { equalBytes, toBytes32, type Bytes32 } from "./values.ts";

/** Bytes whose SHA-256 is not the one recorded on chain. Nothing derived from them may be used. */
export class HashMismatch extends Error {
  constructor(message = "The bytes do not match the hash recorded on chain.") {
    super(message);
    this.name = "HashMismatch";
  }
}

/**
 * SHA-256 over the exact raw bytes (threat model C12): the bytes as uploaded, recorded and
 * downloaded, never a `qoreseal:` text form or any other re-encoding.
 */
export function sha256(bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("sha256 takes raw bytes.");
  return sha256Digest(bytes, "bytes");
}

/**
 * Whether two 32-byte hashes are equal, compared as bytes after one parser reads both sides, so
 * hex case or form can never decide the answer.
 *
 * @throws TypeError when either side is not exactly 32 bytes.
 */
export function sameHash(a: Bytes32, b: Bytes32): boolean {
  const x = toBytes32(a);
  const y = toBytes32(b);
  if (x === undefined || y === undefined) throw new TypeError("A hash is exactly 32 bytes.");
  return equalBytes(x, y);
}

/**
 * Refuses bytes unless their SHA-256 equals `expected`, the value read from chain (threat model C12).
 * Call it on every envelope before it is opened or resealed and on every ciphertext before it is
 * decrypted, in the chair's browser, a director's browser and the bot alike.
 *
 * @throws HashMismatch on any difference, and when `expected` is not a 32-byte value.
 */
export function assertHash(bytes: Uint8Array, expected: Bytes32): void {
  let matches = false;
  try {
    matches = sameHash(sha256(bytes), expected);
  } catch {
    matches = false;
  }
  if (!matches) throw new HashMismatch();
}
