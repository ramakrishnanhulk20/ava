// Not covered here: whether an address belongs to the person who claims it, and the
// chain's own conversion (pqcKeyStatus and the KEM lookup are checked live, not here).
import { bytesToBech32 } from "@qorechain/sdk";
import { hexToBytes, type Hex } from "viem";
import { describe, expect, it } from "vitest";
import { AddressError, accountBytes, accountBytesStrict, sameAccount, toHex, toQor1 } from "../src/address.ts";

// One account in both forms, as the testnet reported them for the deployer on 16 Nov.
const QOR1 = "qor13gmaduk6r79q0utnt3tgcfs3ypwe86tn8292fq";
const EIP55 = "0x8A37d6f2DA1F8a07f1735c568C2611205d93e973";
const LOWER = EIP55.toLowerCase() as Hex;
const BYTES = hexToBytes(LOWER);

function flipCaseAt(address: string, index: number): string {
  const ch = address[index]!;
  const flipped = ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase();
  return address.slice(0, index) + flipped + address.slice(index + 1);
}

describe("accountBytes", () => {
  it("decodes the qor1, EIP-55 and lowercase forms of one account to the same 20 bytes", () => {
    for (const form of [QOR1, EIP55, LOWER]) expect(accountBytes(form)).toEqual(BYTES);
  });

  it("encodes back to the exact qor1 and EIP-55 strings", () => {
    expect(toQor1(BYTES)).toBe(QOR1);
    expect(toHex(BYTES)).toBe(EIP55);
  });

  it("rejects a qor1 address with a wrong checksum", () => {
    const bad = QOR1.slice(0, -1) + (QOR1.endsWith("q") ? "p" : "q");
    expect(() => accountBytes(bad)).toThrow(AddressError);
  });

  it("rejects payloads that are not 20 bytes", () => {
    expect(() => accountBytes(EIP55.slice(0, -2))).toThrow(AddressError);
    expect(() => accountBytes(`${LOWER}00`)).toThrow(AddressError);
    expect(() => accountBytes(bytesToBech32(new Uint8Array(32).fill(7), "qor"))).toThrow(AddressError);
    expect(() => toQor1(new Uint8Array(19))).toThrow(AddressError);
    expect(() => toHex(new Uint8Array(21))).toThrow(AddressError);
  });

  it("rejects other prefixes", () => {
    expect(() => accountBytes(bytesToBech32(BYTES, "cosmos"))).toThrow(AddressError);
    expect(() => accountBytes(bytesToBech32(BYTES, "qorvaloper"))).toThrow(AddressError);
    expect(() => accountBytes(`0X${LOWER.slice(2)}`)).toThrow(AddressError);
    expect(() => accountBytes(LOWER.slice(2))).toThrow(AddressError);
    expect(() => accountBytes("")).toThrow(AddressError);
  });

  it("rejects mixed case with a bad checksum, all uppercase hex and non-lowercase bech32", () => {
    const letter = [...EIP55].findIndex((c, i) => i > 1 && /[a-fA-F]/.test(c));
    expect(() => accountBytes(flipCaseAt(EIP55, letter))).toThrow(AddressError);
    expect(() => accountBytes(`0x${EIP55.slice(2).toUpperCase()}`)).toThrow(AddressError);
    expect(() => accountBytes(QOR1.toUpperCase())).toThrow(AddressError);
    expect(() => accountBytes(flipCaseAt(QOR1, 10))).toThrow(AddressError);
  });
});

describe("accountBytesStrict", () => {
  it("decodes qor1 and the exact EIP-55 form to the same 20 bytes as the lenient codec", () => {
    for (const form of [QOR1, EIP55]) expect(accountBytesStrict(form)).toEqual(BYTES);
    const digitsOnly = "0x1111111111111111111111111111111111111111";
    expect(accountBytesStrict(digitsOnly)).toEqual(accountBytes(digitsOnly));
  });

  it("refuses all-lowercase 0x, which carries no checksum to catch a typo", () => {
    expect(() => accountBytesStrict(LOWER)).toThrow(AddressError);
  });

  it("refuses everything the lenient codec refuses", () => {
    const letter = [...EIP55].findIndex((c, i) => i > 1 && /[a-fA-F]/.test(c));
    const bad = [
      QOR1.slice(0, -1) + (QOR1.endsWith("q") ? "p" : "q"),
      QOR1.toUpperCase(),
      flipCaseAt(EIP55, letter),
      `0x${EIP55.slice(2).toUpperCase()}`,
      `0X${LOWER.slice(2)}`,
      EIP55.slice(0, -2),
      bytesToBech32(BYTES, "cosmos"),
      "",
    ];
    for (const input of bad) expect(() => accountBytesStrict(input)).toThrow(AddressError);
  });
});

describe("sameAccount", () => {
  it("compares the 20 bytes across forms", () => {
    expect(sameAccount(QOR1, EIP55)).toBe(true);
    expect(sameAccount(LOWER, BYTES)).toBe(true);
    expect(sameAccount(EIP55, "0x4786dCd1301432DDFaF65e0d089CbDEFA6ccEa24")).toBe(false);
  });

  it("throws instead of answering for a malformed address", () => {
    expect(() => sameAccount(EIP55, flipCaseAt(EIP55, 3))).toThrow(AddressError);
  });
});
