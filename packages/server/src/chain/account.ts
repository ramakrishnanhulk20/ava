import { derivePqcCanonical, deriveUnifiedAccount, validateMnemonic, type PqcKeypair, type UnifiedAccount } from "@qorechain/sdk";
import { accountBytes, sameAccount, toHex, toQor1 } from "@ava/core";
import type { Hex } from "viem";

const MNEMONIC_WORDS = 24;

/**
 * Every key the relayer has, rebuilt from its one recovery phrase. Holds secrets: never log, print,
 * send or serialise an instance of this. Only src/chain/live.ts holds one; handlers see
 * RelayerAddress.
 */
export interface RelayerAccount {
  /** The Native-lane address, `qor1...`. */
  qor1: string;
  /** The same 20 bytes on the EVM lane, EIP-55 `0x...`. */
  evm: Hex;
  /** The 32-byte secp256k1 private key, `0x` hex, shared by both lanes. */
  privateKey: Hex;
  /** The ML-DSA-87 key that signs the relayer's native-lane transactions, window opens included. */
  pqc: PqcKeypair;
  /** The SDK's unified account, for the eth-native signer. */
  unified: UnifiedAccount;
}

/** The public half of the relayer: what handlers, logs and responses may carry. */
export interface RelayerAddress {
  qor1: string;
  evm: Hex;
}

/** The phrase with surrounding and repeated whitespace removed, the one form every reader derives from. */
export function normalizeMnemonic(raw: string): string {
  return raw.trim().split(/\s+/).join(" ");
}

/** Whether the value is a 24-word BIP-39 phrase with a valid checksum, once normalised. */
export function isRelayerMnemonic(raw: string): boolean {
  const mnemonic = normalizeMnemonic(raw);
  return mnemonic.split(" ").length === MNEMONIC_WORDS && validateMnemonic(mnemonic);
}

/**
 * Derives the relayer the way the deployer and the drill account are derived (proven on testnet):
 * one eth_secp256k1 key on m/44'/60'/0'/0/0, so the qor1 address, the 0x address and the key that
 * signs EVM transactions are one account (coin type 60), plus the address-bound ML-DSA-87 key.
 *
 * @throws When the phrase is not 24 valid words (the message never repeats it), when
 *   derivePqcCanonical and the unified account disagree on the ML-DSA-87 key, or when the two
 *   address forms are not the same 20 bytes.
 */
export async function relayerFromMnemonic(raw: string): Promise<RelayerAccount> {
  if (!isRelayerMnemonic(raw)) throw new Error(`The relayer phrase is not ${MNEMONIC_WORDS} valid BIP-39 words.`);
  const mnemonic = normalizeMnemonic(raw);
  const unified = await deriveUnifiedAccount(mnemonic, 0);
  const pqc = derivePqcCanonical(unified.cosmos, mnemonic);
  if (!sameBytes(pqc.publicKey, unified.pqc.publicKey)) {
    throw new Error("derivePqcCanonical and deriveUnifiedAccount give different ML-DSA-87 keys. Refusing to continue.");
  }
  if (!sameAccount(unified.cosmos, unified.evm)) throw new Error("The derived qor1 and 0x addresses are not the same 20 bytes. Refusing to continue.");
  if (!/^0x[0-9a-fA-F]{64}$/.test(unified.privateKey)) throw new Error("The derived private key is not 32 bytes of hex.");
  const account = accountBytes(unified.cosmos);
  return { qor1: toQor1(account), evm: toHex(account), privateKey: unified.privateKey as Hex, pqc, unified };
}

export function publicAddress(account: RelayerAccount): RelayerAddress {
  return { qor1: account.qor1, evm: account.evm };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
