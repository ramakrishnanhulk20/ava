import { deriveUnifiedAccount, derivePqcCanonical, type PqcKeypair, type UnifiedAccount } from "@qorechain/sdk";
import { deriveSealKeys, type SealKeyPair } from "@qorechain/qoreseal";

/**
 * Every key the drill account has, rebuilt from its one recovery phrase.
 * Holds secrets: never log, print or serialise an instance of this.
 */
export interface DrillAccount {
  /** The Native-lane address, `qor1...`. */
  qor1: string;
  /** The same 20 bytes on the EVM lane, EIP-55 `0x...`. */
  evm: string;
  /** The 32-byte secp256k1 private key. The classical half handed to the drill's attacker bot. */
  privateKey: Uint8Array;
  /** The 33-byte compressed secp256k1 public key. */
  publicKey: Uint8Array;
  /** The ML-DSA-87 signing key registered on chain. */
  pqc: PqcKeypair;
  /** The ML-KEM-1024 and X25519 encryption keys, index 0. */
  seal: SealKeyPair;
  /** The SDK's unified account, for the eth-native signer. */
  unified: UnifiedAccount;
}

function hexBytes(hex: string, length: number, what: string): Uint8Array {
  const body = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]*$/.test(body) || body.length !== length * 2) {
    throw new Error(`${what} is not ${length} bytes of hex`);
  }
  return Uint8Array.from(Buffer.from(body, "hex"));
}

/**
 * Derives the drill account the way the organisers' Workshop 1 example does:
 * one eth_secp256k1 key on m/44'/60'/0'/0/0, so the qor1 address, the 0x
 * address and the private key the attacker bot receives are one account.
 *
 * @throws When the phrase is invalid, or when the SDK's unified account and
 *   derivePqcCanonical disagree on the ML-DSA-87 key (QoreX could then not
 *   restore the key that gets registered).
 */
export async function deriveDrillAccount(mnemonic: string): Promise<DrillAccount> {
  const unified = await deriveUnifiedAccount(mnemonic, 0);
  const pqc = derivePqcCanonical(unified.cosmos, mnemonic);
  if (!Buffer.from(pqc.publicKey).equals(Buffer.from(unified.pqc.publicKey))) {
    throw new Error("derivePqcCanonical and deriveUnifiedAccount give different ML-DSA-87 keys. Refusing to continue.");
  }
  return {
    qor1: unified.cosmos,
    evm: unified.evm,
    privateKey: hexBytes(unified.privateKey, 32, "the derived private key"),
    publicKey: hexBytes(unified.publicKey, 33, "the derived public key"),
    pqc,
    seal: deriveSealKeys({ mnemonic, index: 0 }),
    unified,
  };
}
