import { canonicalPhrase } from "@ava/core";
import { deriveUnifiedAccount, derivePqcCanonical, bech32ToHex, isValidBech32, isValidEvmAddress, toChecksumAddress, type PqcKeypair, type UnifiedAccount } from "@qorechain/sdk";
import { deriveSealKeys, type SealKeyPair } from "@qorechain/qoreseal";

/**
 * Every key the deployer has, rebuilt from its one recovery phrase.
 * Holds secrets: never log, print or serialise an instance of this.
 */
export interface Deployer {
  /** The Native-lane address, `qor1...`. */
  qor1: string;
  /** The same 20 bytes on the EVM lane, EIP-55 `0x...`. */
  evm: `0x${string}`;
  /** The 32-byte secp256k1 private key, `0x` hex, shared by both lanes. */
  privateKey: `0x${string}`;
  /** The ML-DSA-87 signing key registered on chain. */
  pqc: PqcKeypair;
  /** The ML-KEM-1024 and X25519 encryption keys, index 0. */
  seal: SealKeyPair;
  /** The SDK's unified account, for the eth-native signer. */
  unified: UnifiedAccount;
}

function hex32(hex: string, what: string): `0x${string}` {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hex)) throw new Error(`${what} is not 32 bytes of 0x hex`);
  return hex as `0x${string}`;
}

/**
 * The one way every script turns an address into its account: a `qor1`
 * address with a valid bech32 checksum, or a `0x` address in its exact EIP-55
 * form, decoded to 20 bytes. Compare accounts with {@link sameAccount}, never
 * as strings.
 *
 * @throws When the input is neither form, fails its checksum, or is not 20 bytes.
 */
export function accountBytes(address: string): Uint8Array {
  let hex: string;
  if (address.startsWith("qor1")) {
    if (!isValidBech32(address, "qor")) throw new Error("Not a valid qor1 address (bech32 checksum or prefix).");
    hex = bech32ToHex(address);
  } else if (address.startsWith("0x")) {
    // Lowercase or uppercase hex carries no checksum, so a typo would go unnoticed.
    if (!isValidEvmAddress(address) || toChecksumAddress(address) !== address) {
      throw new Error("Not a 0x address in its EIP-55 checksum form.");
    }
    hex = address;
  } else {
    throw new Error("An address must start with qor1 or 0x.");
  }
  const bytes = Uint8Array.from(Buffer.from(hex.slice(2), "hex"));
  if (bytes.length !== 20) throw new Error(`An account is 20 bytes; this address decodes to ${bytes.length}.`);
  return bytes;
}

/** Whether two addresses, in either form, name the same 20-byte account. */
export function sameAccount(a: string, b: string): boolean {
  return Buffer.from(accountBytes(a)).equals(Buffer.from(accountBytes(b)));
}

/**
 * Derives the deployer the way the organisers' Workshop 1 example derives an
 * account: one eth_secp256k1 key on m/44'/60'/0'/0/0, so the qor1 address, the
 * 0x address and the key that signs EVM transactions are one account.
 *
 * Every derivation reads the phrase only after @ava/core's canonicalPhrase, the
 * rule the app uses (threat model C16). The SDK hashes the raw string into the
 * ML-DSA-87 seed, so a phrase pasted with a no-break space would otherwise give
 * the right address and a different signing key.
 *
 * @throws When the phrase is not 24 valid words (the message never repeats it),
 *   when derivePqcCanonical and the SDK's unified account disagree on the
 *   ML-DSA-87 key, or when the two address forms are not the same 20 bytes.
 */
export async function deriveDeployer(mnemonic: string): Promise<Deployer> {
  const phrase = canonicalPhrase(mnemonic);
  const unified = await deriveUnifiedAccount(phrase, 0);
  const pqc = derivePqcCanonical(unified.cosmos, phrase);
  if (!Buffer.from(pqc.publicKey).equals(Buffer.from(unified.pqc.publicKey))) {
    throw new Error("derivePqcCanonical and deriveUnifiedAccount give different ML-DSA-87 keys. Refusing to continue.");
  }
  if (!sameAccount(unified.cosmos, unified.evm)) {
    throw new Error("The derived qor1 and 0x addresses are not the same 20 bytes. Refusing to continue.");
  }
  return {
    qor1: unified.cosmos,
    evm: unified.evm as `0x${string}`,
    privateKey: hex32(unified.privateKey, "the derived private key"),
    pqc,
    seal: deriveSealKeys({ mnemonic: phrase, index: 0 }),
    unified,
  };
}
