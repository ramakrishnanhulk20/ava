import { bech32ToHex, bytesToBech32, isValidBech32 } from "@qorechain/sdk";
import { bytesToHex, getAddress, hexToBytes, isAddress, type Address } from "viem";

const ACCOUNT_LENGTH = 20;
const BECH32_PREFIX = "qor";

/** An address that is not one of the three accepted forms of a 20-byte account. */
export class AddressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AddressError";
  }
}

function requireAccount(bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== ACCOUNT_LENGTH) {
    throw new AddressError(`An account is ${ACCOUNT_LENGTH} bytes.`);
  }
  return bytes;
}

/**
 * The one way every part of Ava turns an address into its account (threat model C16).
 *
 * Accepts exactly three forms of one 20-byte account:
 * - `qor1...` bech32 (not bech32m), lowercase, with a valid checksum;
 * - `0x...` in its exact EIP-55 checksum form;
 * - `0x...` in all lowercase, the form the EVM JSON-RPC reports, which carries no checksum.
 *
 * Covers checksum typos in the bech32 and EIP-55 forms. Does not cover a valid address that
 * belongs to the wrong person, and a lowercase `0x` address has no checksum to catch a typo.
 *
 * @returns A fresh copy of the 20 account bytes.
 * @throws AddressError for anything else: another prefix, uppercase or mixed-case bech32,
 *   mixed case with a wrong checksum, all uppercase hex, `0X`, or a payload that is not 20 bytes.
 */
export function accountBytes(input: string): Uint8Array {
  if (typeof input !== "string") throw new AddressError("An address must be a string.");
  if (input.startsWith(`${BECH32_PREFIX}1`)) {
    let hex: string;
    try {
      if (!isValidBech32(input, BECH32_PREFIX)) throw new Error("invalid");
      hex = bech32ToHex(input);
    } catch {
      throw new AddressError("Not a valid qor1 address: the bech32 checksum or form is wrong.");
    }
    const bytes = hexToBytes(hex as Address);
    if (bytes.length !== ACCOUNT_LENGTH) {
      throw new AddressError(`This qor1 address holds ${bytes.length} bytes; an account is ${ACCOUNT_LENGTH}.`);
    }
    return bytes;
  }
  if (input.startsWith("0x")) {
    if (!isAddress(input, { strict: false })) throw new AddressError("Not a 0x address of 20 bytes.");
    const body = input.slice(2);
    if (body !== body.toLowerCase() && getAddress(input) !== input) {
      throw new AddressError("This 0x address is neither all lowercase nor in its EIP-55 checksum form.");
    }
    return hexToBytes(input);
  }
  throw new AddressError("An address must start with qor1 or 0x.");
}

/**
 * The decoder for every address that arrives in a request (threat model C16): `qor1...` with a
 * valid bech32 checksum, or `0x...` in its exact EIP-55 form. All-lowercase `0x` is refused,
 * because it carries no checksum, so a mistyped address cannot pass as a different account.
 * Values read from the chain, which reports lowercase hex, go through `accountBytes` instead.
 *
 * Covers checksum typos in both forms. Does not cover a valid address that belongs to the wrong
 * person. An address whose hex has no letters is its own EIP-55 form and is accepted.
 *
 * @returns A fresh copy of the 20 account bytes.
 * @throws AddressError for all-lowercase `0x` with letters in it, and for everything
 *   `accountBytes` refuses.
 */
export function accountBytesStrict(input: string): Uint8Array {
  if (typeof input === "string" && input.startsWith("0x")) {
    if (!isAddress(input, { strict: false }) || getAddress(input) !== input) {
      throw new AddressError("A 0x address in a request must be in its exact EIP-55 checksum form.");
    }
  }
  return accountBytes(input);
}

/** The `qor1...` form of a 20-byte account. */
export function toQor1(bytes: Uint8Array): string {
  return bytesToBech32(requireAccount(bytes), BECH32_PREFIX);
}

/** The EIP-55 `0x...` form of a 20-byte account. */
export function toHex(bytes: Uint8Array): Address {
  return getAddress(bytesToHex(requireAccount(bytes)));
}

/**
 * Whether two addresses, in any accepted form or as raw bytes, name the same account.
 * Compares the 20 bytes, never the strings.
 *
 * @throws AddressError when either side is not an accepted address.
 */
export function sameAccount(a: string | Uint8Array, b: string | Uint8Array): boolean {
  const x = typeof a === "string" ? accountBytes(a) : requireAccount(a);
  const y = typeof b === "string" ? accountBytes(b) : requireAccount(b);
  let diff = 0;
  for (let i = 0; i < ACCOUNT_LENGTH; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}
