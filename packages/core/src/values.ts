import { hexToBytes, type Hex } from "viem";

/** A 32-byte value as raw bytes or as `0x` hex in either case. */
export type Bytes32 = Uint8Array | Hex;
/** An unsigned integer as a bigint, or as a number when it is a safe integer. */
export type Uint = bigint | number;

const MAX_UINT = { 8: 0xffn, 32: 0xffff_ffffn, 64: 0xffff_ffff_ffff_ffffn, 256: (1n << 256n) - 1n } as const;

/** The value as a bigint, or undefined when it is not an unsigned integer that fits in `bits` bits. */
export function toUint(value: Uint, bits: keyof typeof MAX_UINT): bigint | undefined {
  const n = typeof value === "number" && Number.isSafeInteger(value) ? BigInt(value) : value;
  if (typeof n !== "bigint" || n < 0n || n > MAX_UINT[bits]) return undefined;
  return n;
}

/** A fresh copy of the 32 bytes, or undefined when the value is not exactly 32 bytes. */
export function toBytes32(value: Bytes32): Uint8Array | undefined {
  if (value instanceof Uint8Array) return value.length === 32 ? Uint8Array.from(value) : undefined;
  if (typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value)) return hexToBytes(value);
  return undefined;
}

/** Equal length and equal bytes, without stopping at the first difference. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
