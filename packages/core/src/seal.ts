import { kdfInfo, open, seal, validateMlkemPublicKey, type SealKeyPair } from "@qorechain/qoreseal";
import { bytesToBigInt, bytesToHex, concatBytes, numberToBytes, stringToBytes } from "viem";
import { accountBytes } from "./address.ts";
import { CHAIN_ID, MAX_CIPHER_SIZE, MAX_ENVELOPE_SIZE, MAX_MEMBERS } from "./constants.ts";
import { assertHash, sha256 } from "./hash.ts";
import { toBytes32, toUint, type Bytes32, type Uint } from "./values.ts";

const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const PAYLOAD_VERSION = 0x01;
const PAYLOAD_LENGTH = 1 + 8 + KEY_LENGTH;
const DOC_INFO_LABEL = stringToBytes("ava-doc-v1");

/** An epoch key envelope that cannot be built, or whose opened payload is not the one expected. */
export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvelopeError";
  }
}

/** A document that cannot be encrypted within the limits, or that fails to decrypt. */
export class DocumentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DocumentError";
  }
}

/** One person an epoch key is sealed to: their account and the ML-KEM-1024 key the chain holds for it. */
export interface SealRecipientAccount {
  address: string;
  kemPublicKey: Uint8Array;
}

type Refusal = typeof EnvelopeError | typeof DocumentError;

const isZero = (bytes: Uint8Array): boolean => bytes.every((b) => b === 0);

/** 32 bytes from the platform's cryptographic random source. All zero can only mean a broken source. */
function freshRandom(length: number): Uint8Array {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(length));
  if (isZero(bytes)) throw new Error("The random source returned only zero bytes. Refusing to use it.");
  return bytes;
}

/** WebCrypto takes buffers it owns outright; this copy gives it one. */
function owned(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

function nonZero32(value: Bytes32, what: string, Err: Refusal): Uint8Array {
  const bytes = toBytes32(value);
  if (bytes === undefined || isZero(bytes)) throw new Err(`${what} is 32 bytes and not zero.`);
  return bytes;
}

function epochOf(epoch: Uint, Err: Refusal): bigint {
  const n = toUint(epoch, 64);
  if (n === undefined) throw new Err("epoch must be an unsigned 64-bit integer.");
  return n;
}

function placeWith(registry: string, boardRef: Bytes32, Err: Refusal): Uint8Array {
  return sha256(concatBytes([accountBytes(registry), nonZero32(boardRef, "boardRef", Err)]));
}

/** `place (32) || epoch (8, big-endian)`, the one prefix shared by the HKDF info and the AAD. */
function placeEpoch(registry: string, boardRef: Bytes32, epoch: Uint, Err: Refusal): Uint8Array {
  return concatBytes([placeWith(registry, boardRef, Err), numberToBytes(epochOf(epoch, Err), { size: 8 })]);
}

/**
 * A new epoch key: 32 bytes from the platform's cryptographic random source (threat model C11).
 * Call once per epoch; never derive one key from another or reuse one across boards.
 */
export function newEpochKey(): Uint8Array {
  return freshRandom(KEY_LENGTH);
}

/** A new random 32-byte document reference, picked before a document is encrypted (C13, C14). */
export function newDocRef(): Uint8Array {
  return freshRandom(32);
}

/** A new random 32-byte board reference, picked before a board is created. Never zero. */
export function newBoardRef(): Uint8Array {
  return freshRandom(32);
}

/**
 * The board's identity for all encryption: `SHA-256(registry (20 bytes) || boardRef (32 bytes))`
 * (docs/spec/actions.md). Read boardRef from the registry's getBoard, never from a link or a request.
 *
 * @throws EnvelopeError for a zero or malformed boardRef. AddressError for a bad registry.
 */
export function placeOf(registry: string, boardRef: Bytes32): Uint8Array {
  return placeWith(registry, boardRef, EnvelopeError);
}

/**
 * The QoreSeal purpose of one epoch's envelopes: `ava/<place lowercase hex, 64 characters>/<epoch>`
 * (threat model C13). The one builder for sealing and opening.
 *
 * @throws EnvelopeError for a zero or malformed boardRef, an epoch outside uint64, or a purpose
 *   QoreSeal's own check refuses. AddressError for a bad registry.
 */
export function purposeFor(registry: string, boardRef: Bytes32, epoch: Uint): string {
  const purpose = `ava/${bytesToHex(placeOf(registry, boardRef)).slice(2)}/${epochOf(epoch, EnvelopeError)}`;
  try {
    kdfInfo(CHAIN_ID, purpose);
  } catch {
    throw new EnvelopeError("This board and epoch give a purpose outside QoreSeal's rules.");
  }
  return purpose;
}

/**
 * Seals an epoch key to every recipient (threat model C13): QoreSeal mode `mlkem`, never anonymous,
 * chain id `qorechain-diana`, purpose from {@link purposeFor}, payload `0x01 || epoch (8 bytes) || key`.
 *
 * Each `kemPublicKey` must come from fetchKemKey for that same address (C15).
 *
 * @returns The binary envelope: the exact bytes to upload, hash and record.
 * @throws EnvelopeError for a key that is not 32 bytes, no recipients, more than MAX_MEMBERS, the
 *   same account twice, a zero boardRef, or an envelope over MAX_ENVELOPE_SIZE. AddressError for a
 *   bad address. QoreSealError `INVALID_KEY` for a KEM key that fails validateMlkemPublicKey.
 */
export function sealEpochKey(p: { registry: string; boardRef: Bytes32; epoch: Uint; epochKey: Uint8Array; recipients: SealRecipientAccount[] }): Uint8Array {
  const purpose = purposeFor(p.registry, p.boardRef, p.epoch);
  const epoch = epochOf(p.epoch, EnvelopeError);
  if (!(p.epochKey instanceof Uint8Array) || p.epochKey.length !== KEY_LENGTH) throw new EnvelopeError("An epoch key is 32 bytes.");
  if (!Array.isArray(p.recipients) || p.recipients.length === 0 || p.recipients.length > MAX_MEMBERS) {
    throw new EnvelopeError(`An epoch key is sealed to 1 to ${MAX_MEMBERS} members.`);
  }
  const seen = new Set<string>();
  const recipients = p.recipients.map((r) => {
    const id = bytesToHex(accountBytes(r.address));
    if (seen.has(id)) throw new EnvelopeError("The same account is listed twice.");
    seen.add(id);
    validateMlkemPublicKey(r.kemPublicKey);
    return { mlkemPublicKey: r.kemPublicKey };
  });
  const plaintext = concatBytes([Uint8Array.of(PAYLOAD_VERSION), numberToBytes(epoch, { size: 8 }), p.epochKey]);
  const envelope = seal({ chainId: CHAIN_ID, purpose, recipients, plaintext, mode: "mlkem", anonymous: false });
  if (envelope.length > MAX_ENVELOPE_SIZE) throw new EnvelopeError(`The envelope is over ${MAX_ENVELOPE_SIZE} bytes.`);
  return envelope;
}

/**
 * Opens one epoch's envelope with a member's QoreSeal keys and returns the 32-byte epoch key.
 *
 * Checks come first, in this order, before any key is touched (threat model C12): the envelope is
 * exactly `expectedSize` bytes, then its SHA-256 equals `expectedHash`. Both values are the ones the
 * registry recorded for this board and epoch.
 *
 * @throws EnvelopeError for a size that differs from `expectedSize` or is over MAX_ENVELOPE_SIZE, or a
 *   payload whose version or epoch is not the one expected. HashMismatch when the bytes are not the
 *   recorded ones. QoreSealError `NOT_A_RECIPIENT` when the keys hold no entry, `DECRYPTION_FAILED`
 *   when the envelope belongs to another registry, board or epoch (C13).
 */
export function openEpochKey(p: {
  registry: string;
  boardRef: Bytes32;
  epoch: Uint;
  envelope: Uint8Array;
  expectedHash: Bytes32;
  expectedSize: Uint;
  sealKeys: SealKeyPair;
}): Uint8Array {
  const size = toUint(p.expectedSize, 32);
  if (size === undefined || size === 0n || size > BigInt(MAX_ENVELOPE_SIZE)) throw new EnvelopeError(`An envelope is 1 to ${MAX_ENVELOPE_SIZE} bytes.`);
  if (!(p.envelope instanceof Uint8Array) || BigInt(p.envelope.length) !== size) throw new EnvelopeError("The envelope is not the size the registry recorded.");
  assertHash(p.envelope, p.expectedHash);

  const purpose = purposeFor(p.registry, p.boardRef, p.epoch);
  const epoch = epochOf(p.epoch, EnvelopeError);
  const payload = open({ chainId: CHAIN_ID, purpose, envelope: p.envelope, keys: p.sealKeys });
  if (payload.length !== PAYLOAD_LENGTH || payload[0] !== PAYLOAD_VERSION) throw new EnvelopeError("The envelope does not carry a version 1 epoch key.");
  if (bytesToBigInt(payload.subarray(1, 9)) !== epoch) throw new EnvelopeError("The envelope carries the key of another epoch.");
  return payload.slice(9);
}

/**
 * The AES-256-GCM key of one document (threat model C14): HKDF-SHA-256 with the epoch key as input,
 * the docRef as salt and `"ava-doc-v1" || place (32) || epoch (8)` as info. Each document gets its
 * own key, so chair devices sharing one epoch key never share a key and nonce pair.
 *
 * @returns A non-extractable WebCrypto key usable only to encrypt and decrypt.
 * @throws DocumentError for an epoch key that is not 32 bytes, or a zero or malformed boardRef or docRef.
 */
export async function documentKey(epochKey: Uint8Array, registry: string, boardRef: Bytes32, epoch: Uint, docRef: Bytes32): Promise<CryptoKey> {
  if (!(epochKey instanceof Uint8Array) || epochKey.length !== KEY_LENGTH) throw new DocumentError("An epoch key is 32 bytes.");
  const info = concatBytes([DOC_INFO_LABEL, placeEpoch(registry, boardRef, epoch, DocumentError)]);
  const salt = nonZero32(docRef, "docRef", DocumentError);
  const subtle = globalThis.crypto.subtle;
  const base = await subtle.importKey("raw", owned(epochKey), "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: owned(salt), info: owned(info) }, base, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** The one AAD builder (C13): `place (32) || epoch (8) || docRef (32)`. */
function documentAad(registry: string, boardRef: Bytes32, epoch: Uint, docRef: Bytes32): Uint8Array<ArrayBuffer> {
  return owned(concatBytes([placeEpoch(registry, boardRef, epoch, DocumentError), nonZero32(docRef, "docRef", DocumentError)]));
}

interface DocumentPlace {
  epochKey: Uint8Array;
  registry: string;
  boardRef: Bytes32;
  epoch: Uint;
  docRef: Bytes32;
}

/**
 * Encrypts a document for one board and epoch: a fresh random 12-byte nonce, then the AES-256-GCM
 * ciphertext and its 16-byte tag, under the document's own key and the fixed AAD (C13, C14).
 *
 * @returns `nonce || ciphertext || tag`: the exact bytes to upload, hash and record.
 * @throws DocumentError when the result would be over MAX_CIPHER_SIZE, or for a bad key, boardRef or docRef.
 */
export async function encryptDocument(p: DocumentPlace & { plaintext: Uint8Array }): Promise<Uint8Array> {
  if (!(p.plaintext instanceof Uint8Array) || NONCE_LENGTH + p.plaintext.length + TAG_LENGTH > MAX_CIPHER_SIZE) {
    throw new DocumentError(`An encrypted document is at most ${MAX_CIPHER_SIZE} bytes.`);
  }
  const key = await documentKey(p.epochKey, p.registry, p.boardRef, p.epoch, p.docRef);
  const nonce = owned(freshRandom(NONCE_LENGTH));
  const additionalData = documentAad(p.registry, p.boardRef, p.epoch, p.docRef);
  const sealed = await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 }, key, owned(p.plaintext));
  return concatBytes([nonce, new Uint8Array(sealed)]);
}

/**
 * Decrypts a document.
 *
 * Checks come first, in this order, before any key is touched (threat model C12): the ciphertext is
 * exactly `expectedSize` bytes, then its SHA-256 equals `expectedHash`. Both values are the cipherSize
 * and cipherHash the registry recorded for this document.
 *
 * @throws DocumentError for a size that differs from `expectedSize` or is outside 28 to MAX_CIPHER_SIZE,
 *   or a ciphertext that fails to authenticate: a wrong key, or one moved to another docRef, epoch,
 *   board or registry. HashMismatch when the bytes are not the recorded ones.
 */
export async function decryptDocument(p: DocumentPlace & { ciphertext: Uint8Array; expectedHash: Bytes32; expectedSize: Uint }): Promise<Uint8Array> {
  const size = toUint(p.expectedSize, 64);
  if (size === undefined || size < BigInt(NONCE_LENGTH + TAG_LENGTH) || size > BigInt(MAX_CIPHER_SIZE)) {
    throw new DocumentError(`An encrypted document is ${NONCE_LENGTH + TAG_LENGTH} to ${MAX_CIPHER_SIZE} bytes.`);
  }
  if (!(p.ciphertext instanceof Uint8Array) || BigInt(p.ciphertext.length) !== size) throw new DocumentError("The ciphertext is not the size the registry recorded.");
  assertHash(p.ciphertext, p.expectedHash);

  const key = await documentKey(p.epochKey, p.registry, p.boardRef, p.epoch, p.docRef);
  const additionalData = documentAad(p.registry, p.boardRef, p.epoch, p.docRef);
  try {
    const plain = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: owned(p.ciphertext.subarray(0, NONCE_LENGTH)), additionalData, tagLength: 128 },
      key,
      owned(p.ciphertext.subarray(NONCE_LENGTH)),
    );
    return new Uint8Array(plain);
  } catch {
    throw new DocumentError("The document does not decrypt for this board, epoch and docRef.");
  }
}
