/**
 * The passphrase vault for a guest's recovery phrase (threat model C18): the phrase is written to
 * browser storage only as AES-256-GCM ciphertext under a key stretched from the guest's passphrase.
 * A wrong passphrase, a changed field or a malformed record all end the same way, locked. There is
 * no fallback and no reset.
 */

/** Passphrases are counted in characters after normalising, so a short one cannot hide behind spaces. */
export const MIN_PASSPHRASE_LENGTH = 10;
/** PBKDF2-SHA-256 rounds for every seal, and the least a stored record may claim (OWASP's 2023 figure). */
export const PBKDF2_ITERATIONS = 600_000;

// A record in storage is input: a cost far above ours would only make the page hang on opening.
const MAX_ITERATIONS = 5_000_000;
const KDF = "PBKDF2-SHA-256";
const VERSION = 1;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
// A 24-word phrase is at most 215 bytes; anything larger is not ours.
const MAX_CIPHERTEXT_BYTES = 512;
const FIELDS = ["ct", "iterations", "iv", "kdf", "qor1", "salt", "v"] as const;
const QOR1 = /^qor1[02-9ac-hj-np-z]{38}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** The passphrase did not open the vault, or what is stored is not a vault this code wrote. */
export class VaultLocked extends Error {
  constructor() {
    super("That passphrase does not open this identity.");
    this.name = "VaultLocked";
  }
}

/** A new passphrase below MIN_PASSPHRASE_LENGTH characters. */
export class PassphraseTooShort extends Error {
  constructor() {
    super(`Choose a passphrase of ${MIN_PASSPHRASE_LENGTH} characters or more.`);
    this.name = "PassphraseTooShort";
  }
}

interface VaultRecord {
  v: typeof VERSION;
  kdf: typeof KDF;
  iterations: number;
  salt: Uint8Array<ArrayBuffer>;
  iv: Uint8Array<ArrayBuffer>;
  ct: Uint8Array<ArrayBuffer>;
  qor1: string;
}

/**
 * The one form of a passphrase both sealing and opening read: NFKC, then trimmed. The same words
 * typed on another keyboard or pasted with a trailing space open the same vault.
 */
function normalised(passphrase: string): string {
  return passphrase.normalize("NFKC").trim();
}

/** Whether a passphrase is long enough to seal with, counted the way sealPhrase counts it. */
export function passphraseLongEnough(passphrase: string): boolean {
  return [...normalised(passphrase)].length >= MIN_PASSPHRASE_LENGTH;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(text: unknown, min: number, max: number): Uint8Array<ArrayBuffer> | undefined {
  if (typeof text !== "string" || text.length > 4 * Math.ceil(max / 3) || !BASE64.test(text)) return undefined;
  let binary: string;
  try {
    binary = atob(text);
  } catch {
    return undefined;
  }
  if (binary.length < min || binary.length > max) return undefined;
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Binds the ciphertext to everything else in the record, so no field can be swapped for another vault's. */
function associatedData(iterations: number, qor1: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`ava.guest.vault|${VERSION}|${KDF}|${iterations}|${qor1}`);
}

async function vaultKey(passphrase: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

function parse(stored: string): VaultRecord | undefined {
  let fields: unknown;
  try {
    fields = JSON.parse(stored);
  } catch {
    return undefined;
  }
  if (fields === null || typeof fields !== "object" || Array.isArray(fields)) return undefined;
  const record = fields as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.length !== FIELDS.length || keys.some((key, i) => key !== FIELDS[i])) return undefined;
  const { v, kdf, iterations, qor1 } = record;
  if (v !== VERSION || kdf !== KDF) return undefined;
  if (typeof iterations !== "number" || !Number.isInteger(iterations) || iterations < PBKDF2_ITERATIONS || iterations > MAX_ITERATIONS) return undefined;
  if (typeof qor1 !== "string" || !QOR1.test(qor1)) return undefined;
  const salt = fromBase64(record.salt, SALT_BYTES, SALT_BYTES);
  const iv = fromBase64(record.iv, NONCE_BYTES, NONCE_BYTES);
  const ct = fromBase64(record.ct, TAG_BYTES + 1, MAX_CIPHERTEXT_BYTES);
  if (salt === undefined || iv === undefined || ct === undefined) return undefined;
  return { v, kdf, iterations, salt, iv, ct, qor1 };
}

/**
 * The public address a stored vault names, for a welcome line shown before it is opened. The
 * address is public on chain; nothing secret is read.
 *
 * @returns The qor1 address, or undefined when `stored` is not a vault record.
 */
export function vaultAddress(stored: string): string | undefined {
  return parse(stored)?.qor1;
}

/**
 * Seals a recovery phrase under a passphrase: PBKDF2-SHA-256 at PBKDF2_ITERATIONS with a fresh
 * 16-byte salt, then AES-256-GCM with a fresh 96-bit nonce, bound to the account address.
 *
 * Covers reading the stored record without the passphrase. Does not cover a weak passphrase an
 * attacker can guess offline, or a device that is already compromised while the vault is open.
 *
 * @param qor1 The account the phrase derives, kept in the clear so a returning guest sees which
 *   identity is stored.
 * @returns The record to store, as JSON text. It holds no plaintext of the phrase or passphrase.
 * @throws PassphraseTooShort below MIN_PASSPHRASE_LENGTH characters. TypeError for a qor1 that is
 *   not a qor1 address.
 */
export async function sealPhrase(phrase: string, passphrase: string, qor1: string): Promise<string> {
  const secret = normalised(passphrase);
  if ([...secret].length < MIN_PASSPHRASE_LENGTH) throw new PassphraseTooShort();
  if (!QOR1.test(qor1)) throw new TypeError("The vault is sealed for a qor1 address.");
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const key = await vaultKey(secret, salt, PBKDF2_ITERATIONS);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: associatedData(PBKDF2_ITERATIONS, qor1) }, key, new TextEncoder().encode(phrase)),
  );
  return JSON.stringify({ v: VERSION, kdf: KDF, iterations: PBKDF2_ITERATIONS, salt: toBase64(salt), iv: toBase64(iv), ct: toBase64(ct), qor1 });
}

/**
 * Opens a stored vault. The record is treated as input: its shape, its cost and its sizes are
 * checked before any key is derived, so a changed record cannot lower the cost or hang the page.
 *
 * @returns The phrase and the account address the record was sealed for. The caller derives the
 *   account from the phrase and refuses unless it is that address.
 * @throws VaultLocked for a wrong passphrase, a changed or malformed record, or anything that is
 *   not a vault this code wrote. The reason is never told apart.
 */
export async function openVault(stored: string, passphrase: string): Promise<{ phrase: string; qor1: string }> {
  const record = parse(stored);
  const secret = normalised(passphrase);
  if (record === undefined || [...secret].length < MIN_PASSPHRASE_LENGTH) throw new VaultLocked();
  try {
    const key = await vaultKey(secret, record.salt, record.iterations);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: record.iv, additionalData: associatedData(record.iterations, record.qor1) }, key, record.ct);
    return { phrase: new TextDecoder("utf-8", { fatal: true }).decode(plain), qor1: record.qor1 };
  } catch {
    throw new VaultLocked();
  }
}
