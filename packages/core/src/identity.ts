import { derivePqcCanonical, deriveUnifiedAccount, generateMnemonic as sdkGenerateMnemonic, type PqcKeypair } from "@qorechain/sdk";
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

/**
 * Derives an identity the way the drill account is derived (ops/drill/src/account.ts, proven
 * on testnet): one eth_secp256k1 key on m/44'/60'/0'/0/0 so the qor1 address, the 0x address and
 * the private key are one account; the address-bound ML-DSA-87 key from derivePqcCanonical; and
 * the QoreSeal keys at index 0.
 *
 * @throws When the phrase is invalid, when derivePqcCanonical and the SDK's unified account give
 *   different ML-DSA-87 keys, or when the two address forms are not the same 20 bytes.
 */
export async function identityFromMnemonic(mnemonic: string): Promise<Identity> {
  const unified = await deriveUnifiedAccount(mnemonic, 0);
  const mldsa = derivePqcCanonical(unified.cosmos, mnemonic);
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
    seal: deriveSealKeys({ mnemonic, index: 0 }),
  };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
