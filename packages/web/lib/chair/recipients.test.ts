// Covers who a new epoch's key is sealed to when the chair's browser rotates it (threat model C15, C17):
// exactly the members read at one block, less the one removed, plus the one added, each once, and
// never a shorter list because a key was missing. Does NOT cover the key lookups themselves
// (fetchKemKey's tests in core) or the seal (QoreSeal).
import type { KemRecipient } from "@ava/core";
import type { Hex } from "viem";
import { describe, expect, it } from "vitest";
import { rotationRecipients } from "./recipients";

const A: Hex = "0x1111111111111111111111111111111111111111";
const B: Hex = "0x2222222222222222222222222222222222222222";
const C: Hex = "0x3333333333333333333333333333333333333333";
const D: Hex = "0x4444444444444444444444444444444444444444";
const key = (address: Hex, byte: number): KemRecipient => Object.freeze({ address, kemPublicKey: new Uint8Array(1568).fill(byte) }) as KemRecipient;
const [ka, kb, kc, kd] = [key(A, 1), key(B, 2), key(C, 3), key(D, 4)];

describe("rotationRecipients", () => {
  it("seals a removal to every member but the one removed, each once", () => {
    expect(rotationRecipients([A, B, C], [kc, ka, kb], { remove: B })).toEqual([ka, kc]);
  });

  it("seals an add by rotation to every member and the new one", () => {
    expect(rotationRecipients([A, B], [ka, kb], { add: kc })).toEqual([ka, kb, kc]);
  });

  it("seals a plain rotation to everyone on the board", () => {
    expect(rotationRecipients([A, B, C], [ka, kb, kc], {})).toEqual([ka, kb, kc]);
  });

  it("stops rather than seal to fewer people when a member's key was not read", () => {
    expect(() => rotationRecipients([A, B, C], [ka, kc], { remove: C })).toThrow(/0x2222/);
    expect(() => rotationRecipients([A, B, C], [ka, kc], {})).toThrow(/0x2222/);
  });

  it("ignores a key that belongs to nobody on the board", () => {
    expect(rotationRecipients([A, B], [ka, kb, kd], {})).toEqual([ka, kb]);
  });

  it("refuses to remove someone who is not a member, or to add someone who already is", () => {
    expect(() => rotationRecipients([A, B], [ka, kb], { remove: D })).toThrow(/not a member/);
    expect(() => rotationRecipients([A, B], [ka, kb], { add: kb })).toThrow(/already a member/);
  });

  it("refuses a board read that lists one account twice", () => {
    expect(() => rotationRecipients([A, B, A], [ka, kb], {})).toThrow(/twice/);
  });
});
