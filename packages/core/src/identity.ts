import { derivePqcCanonical, deriveUnifiedAccount, generateMnemonic as sdkGenerateMnemonic, validateMnemonic, type PqcKeypair } from "@qorechain/sdk";
import { deriveSealKeys, type SealKeyPair } from "@qorechain/qoreseal";
import { hexToBytes, isHex, type Address } from "viem";
import { accountBytes, sameAccount, toHex, toQor1 } from "./address.ts";

/**
 * Every key one person has, rebuilt from their one recovery phrase.
 * Holds secrets: never log, print, send or serialise an instance of this.
 */
export interface Identity {
  /** The 20-byte account both address forms name. */
  account: Uint8Array;
  /** The Native-lane address, `qor1...`. */
  qor1: string;
  /** The same 20 bytes on the EVM lane, EIP-55 `0x...`. */
  evm: Address;
  /** The 32-byte secp256k1 private key of the account (m/44'/60'/0'/0/0). */
  privateKey: Uint8Array;
  /** The ML-DSA-87 key pair registered on chain, which signs board actions. */
  mldsa: PqcKeypair;
  /** The ML-KEM-1024 and X25519 key pair, index 0. Its ML-KEM public key is the one registered on chain. */
  seal: SealKeyPair;
}

/** A fresh 24-word English BIP-39 recovery phrase (256 bits of entropy). */
export function generateMnemonic(): string {
  return sdkGenerateMnemonic(256);
}

const PHRASE_WORDS = 24;

/**
 * The one form of a recovery phrase every derivation reads (threat model C16): NFKD, then trimmed,
 * then split on any run of Unicode whitespace and joined with one ASCII space. A phrase pasted with
 * a no-break or ideographic space, doubled spaces or full-width letters comes out identical to the
 * phrase as generated. The SDK hashes the raw string into the ML-DSA-87 seed, so without this one
 * pasted phrase would give the right address and a different signing key.
 *
 * Covers spacing, width and other compatibility forms. Does not cover case: `ABANDON` stays
 * uppercase and fails the checksum.
 *
 * @returns The phrase as 24 lowercase English BIP-39 words separated by single spaces.
 * @throws Error "The recovery phrase is not 24 valid words." for anything that is not a string of
 *   exactly 24 words with a valid English BIP-39 checksum. The message never repeats the input.
 */
export function canonicalPhrase(raw: string): string {
  const refusal = new Error("The recovery phrase is not 24 valid words.");
  if (typeof raw !== "string") throw refusal;
  const words = raw.normalize("NFKD").trim().split(/\s+/u);
  if (words.length !== PHRASE_WORDS) throw refusal;
  const phrase = words.join(" ");
  if (!validateMnemonic(phrase)) throw refusal;
  return phrase;
}

/**
 * Derives an identity the way the drill account is derived (ops/drill/src/account.ts, proven
 * on testnet): one eth_secp256k1 key on m/44'/60'/0'/0/0 so the qor1 address, the 0x address and
 * the private key are one account; the address-bound ML-DSA-87 key from derivePqcCanonical; and
 * the QoreSeal keys at index 0. Every derivation reads the phrase only after canonicalPhrase, so
 * one phrase always gives one account and one key set (threat model C16).
 *
 * @throws Error from canonicalPhrase when the phrase is not 24 valid words. Error when
 *   derivePqcCanonical and the SDK's unified account give different ML-DSA-87 keys, or when the
 *   two address forms are not the same 20 bytes.
 */
export async function identityFromMnemonic(mnemonic: string): Promise<Identity> {
  const phrase = canonicalPhrase(mnemonic);
  const unified = await deriveUnifiedAccount(phrase, 0);
  const mldsa = derivePqcCanonical(unified.cosmos, phrase);
  if (!sameBytes(mldsa.publicKey, unified.pqc.publicKey)) {
    throw new Error("derivePqcCanonical and deriveUnifiedAccount give different ML-DSA-87 keys. Refusing to continue.");
  }
  if (!sameAccount(unified.cosmos, unified.evm)) {
    throw new Error("The derived qor1 and 0x addresses are not the same 20 bytes. Refusing to continue.");
  }
  if (!isHex(unified.privateKey, { strict: true }) || unified.privateKey.length !== 66) {
    throw new Error("The derived private key is not 32 bytes of hex.");
  }
  const account = accountBytes(unified.cosmos);
  return {
    account,
    qor1: toQor1(account),
    evm: toHex(account),
    privateKey: hexToBytes(unified.privateKey),
    mldsa,
    seal: deriveSealKeys({ mnemonic: phrase, index: 0 }),
  };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
