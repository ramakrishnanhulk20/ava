// Covers the ledger's check of each key envelope against the people it should be sealed to (threat
// model C38, C39): who an epoch's envelope is expected to name, and the verdict when the envelope
// holds exactly them, someone extra, someone short, or cannot be judged. Envelopes here are real ones
// sealed with the project's own library. Does NOT cover the key lookups or downloads around the check.
import { newEpochKey, sealEpochKey, type KemRecipient } from "@ava/core";
import { generateSealKeys } from "@qorechain/qoreseal";
import { describe, expect, it } from "vitest";
import type { HistoryEvent } from "../boardRules";
import { checkEnvelope, expectedReaders } from "./ledger";

const REGISTRY = "0x2bB34f60B29C7bC10f7ECC0B5050329E808DAcBa";
const BOARD_REF = `0x${"a1".repeat(32)}` as const;
const CHAIR = "0x1111111111111111111111111111111111111111";
const ASHA = "0x2222222222222222222222222222222222222222";
const BEN = "0x3333333333333333333333333333333333333333";
const EVE = "0x4444444444444444444444444444444444444444";
const tx = (n: number): `0x${string}` => `0x${n.toString(16).padStart(64, "0")}`;

const keys = { chair: generateSealKeys(), asha: generateSealKeys(), ben: generateSealKeys(), eve: generateSealKeys() };
const recipient = (address: string, pair: ReturnType<typeof generateSealKeys>): KemRecipient => Object.freeze({ address, kemPublicKey: pair.mlkemPublicKey }) as KemRecipient;
const sealTo = (...to: KemRecipient[]): Uint8Array => sealEpochKey({ registry: REGISTRY, boardRef: BOARD_REF, epoch: 1n, epochKey: newEpochKey(), recipients: to });
const onChain = (address: string, pair: ReturnType<typeof generateSealKeys> | undefined) => ({ address, kemPublicKey: pair?.mlkemPublicKey });

describe("checkEnvelope", () => {
  it("is clean when the envelope holds exactly the expected readers", () => {
    const envelope = sealTo(recipient(CHAIR, keys.chair), recipient(ASHA, keys.asha));
    expect(checkEnvelope(envelope, [onChain(CHAIR, keys.chair), onChain(ASHA, keys.asha)])).toEqual({ state: "clean", recipients: 2 });
  });

  it("names an unknown reader when the envelope holds one more entry than the expected readers explain", () => {
    const envelope = sealTo(recipient(CHAIR, keys.chair), recipient(ASHA, keys.asha), recipient(EVE, keys.eve));
    expect(checkEnvelope(envelope, [onChain(CHAIR, keys.chair), onChain(ASHA, keys.asha)])).toEqual({ state: "unknown_reader", recipients: 3, unknown: 1 });
  });

  it("says who was left out when the envelope is short of an expected reader", () => {
    const envelope = sealTo(recipient(CHAIR, keys.chair));
    expect(checkEnvelope(envelope, [onChain(CHAIR, keys.chair), onChain(ASHA, keys.asha)])).toEqual({ state: "left_out", recipients: 1, leftOut: [ASHA] });
  });

  it("is unverified, never clean, when a reader's key on chain is no longer the one the envelope was sealed to", () => {
    const envelope = sealTo(recipient(CHAIR, keys.chair), recipient(ASHA, keys.asha));
    const replaced = generateSealKeys();
    expect(checkEnvelope(envelope, [onChain(CHAIR, keys.chair), onChain(ASHA, replaced)])).toEqual({ state: "unverified", recipients: 2, unexplained: 1, unmatched: [ASHA] });
    expect(checkEnvelope(envelope, [onChain(CHAIR, keys.chair), onChain(ASHA, undefined)])).toEqual({ state: "unverified", recipients: 2, unexplained: 1, unmatched: [ASHA] });
  });

  it("is unverified, not clean and not merely short, when a reader is left out and a stranger's entry sits in their place", () => {
    const envelope = sealTo(recipient(CHAIR, keys.chair), recipient(EVE, keys.eve));
    expect(checkEnvelope(envelope, [onChain(CHAIR, keys.chair), onChain(ASHA, keys.asha)])).toEqual({ state: "unverified", recipients: 2, unexplained: 1, unmatched: [ASHA] });
  });

  it("still names an unknown reader when a changed key cannot explain every extra entry", () => {
    const envelope = sealTo(recipient(CHAIR, keys.chair), recipient(ASHA, keys.asha), recipient(EVE, keys.eve));
    expect(checkEnvelope(envelope, [onChain(CHAIR, keys.chair), onChain(ASHA, undefined)])).toEqual({ state: "unknown_reader", recipients: 3, unknown: 1 });
  });

  it("is unverified for bytes that are not an envelope", () => {
    expect(checkEnvelope(new Uint8Array(40), [onChain(CHAIR, keys.chair)])).toEqual({ state: "unreadable" });
  });
});

const events: HistoryEvent[] = [
  { name: "BoardCreated", chair: CHAIR, tx: tx(1), block: 100, index: 0 },
  { name: "MemberAdded", member: ASHA, epoch: 0, mode: 0, tx: tx(2), block: 110, index: 0 },
  { name: "MemberAdded", member: BEN, epoch: 1, mode: 1, tx: tx(3), block: 120, index: 0 },
  { name: "MemberRemoved", member: ASHA, newEpoch: 2, tx: tx(4), block: 130, index: 0 },
];

describe("expectedReaders", () => {
  it("expects only the chair in the envelope that opened epoch 0", () => {
    expect(expectedReaders(events, { epoch: 0, mode: 1, member: "0x0000000000000000000000000000000000000000" })).toEqual([CHAIR]);
  });

  it("expects exactly the one member a seal-current envelope names", () => {
    expect(expectedReaders(events, { epoch: 0, mode: 0, member: ASHA })).toEqual([ASHA]);
  });

  it("expects everyone on the board when a rotation opened the epoch, the member it added included", () => {
    expect(expectedReaders(events, { epoch: 1, mode: 1, member: "0x0000000000000000000000000000000000000000" }).sort()).toEqual([CHAIR, ASHA, BEN].sort());
  });

  it("does not expect the member whose removal opened the epoch", () => {
    expect(expectedReaders(events, { epoch: 2, mode: 1, member: "0x0000000000000000000000000000000000000000" }).sort()).toEqual([CHAIR, BEN].sort());
  });
});
