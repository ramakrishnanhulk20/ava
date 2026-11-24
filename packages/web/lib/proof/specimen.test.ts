// Covers what the proof page builds before it asks the chain anything: the exact message a landed
// board action was signed over, rebuilt from that action's own calldata and nonce, and the changed
// messages it then tries the same signature on. Signatures here are real ML-DSA-87 ones. Does NOT
// cover the chain's answers (the page shows those live) or the log and transaction reads.
import { generateMnemonic, identityFromMnemonic, verifyAction, type Identity } from "@ava/core";
import { encodeErrorResult, encodeFunctionData, hexToBytes, type Hex } from "viem";
import { beforeAll, describe, expect, it } from "vitest";
import { signedRelayBody, type ChairAction } from "../chair/actions";
import { REGISTRY_ERRORS, REGISTRY_WRITES, decodeWrite, refusalName, trials, unsignedRotate } from "./specimen";

const REGISTRY = "0x2bB34f60B29C7bC10f7ECC0B5050329E808DAcBa";
const MEMBER: Hex = "0x1111111111111111111111111111111111111111";
const HASH = (byte: string): Hex => `0x${byte.repeat(32)}`;
const LATEST = 1_795_000_000n;
const NONCE = 7n;

let chair: Identity;
beforeAll(async () => {
  chair = await identityFromMnemonic(generateMnemonic());
});

type Body = { params: Record<string, string>; deadline: string; signature: Hex; boardId?: string };

/** The calldata our relay would send for a signed action, built the way the relay builds it. */
function calldata(a: ChairAction): Hex {
  const body = signedRelayBody(chair.mldsa.secretKey, a, { registry: REGISTRY, nonce: NONCE, latestBlockTimestamp: LATEST }) as Body;
  const p = body.params;
  const tail = [BigInt(body.deadline), body.signature] as const;
  switch (a.action) {
    case "remove":
      return encodeFunctionData({ abi: REGISTRY_WRITES, functionName: "removeMember", args: [a.boardId, a.member, p.envelopeHash as Hex, Number(p.envelopeSize), a.epochAfter, ...tail] });
    case "add":
      return encodeFunctionData({ abi: REGISTRY_WRITES, functionName: "addMember", args: [a.boardId, a.member, a.mode, p.envelopeHash as Hex, Number(p.envelopeSize), a.epochAfter, ...tail] });
    case "rotate":
      return encodeFunctionData({ abi: REGISTRY_WRITES, functionName: "rotateEpoch", args: [a.boardId, p.envelopeHash as Hex, Number(p.envelopeSize), a.epochAfter, ...tail] });
    case "post":
      return encodeFunctionData({ abi: REGISTRY_WRITES, functionName: "postDocument", args: [a.boardId, a.docRef, a.cipherHash, a.cipherSize, a.epoch, ...tail] });
    default:
      throw new Error("not used here");
  }
}

const actions: ChairAction[] = [
  { action: "remove", boardId: 15n, member: MEMBER, envelopeHash: HASH("b2"), envelopeSize: 1_700, epochAfter: 4n },
  { action: "add", boardId: 15n, member: MEMBER, mode: 0, envelopeHash: HASH("b2"), envelopeSize: 1_700, epochAfter: 3n },
  { action: "rotate", boardId: 15n, envelopeHash: HASH("b2"), envelopeSize: 1_700, epochAfter: 4n },
  { action: "post", boardId: 15n, docRef: HASH("c3"), cipherHash: HASH("d4"), cipherSize: 4_096n, epoch: 3n },
];

describe("decodeWrite and trials", () => {
  it("rebuilds, from a landed action's calldata and nonce alone, the very message its signature verifies over", () => {
    for (const a of actions) {
      const write = decodeWrite(calldata(a));
      expect(write?.boardId).toBe(15n);
      const [original] = trials(write!, { registry: REGISTRY, nonce: NONCE });
      expect(original?.what).toBe("original");
      expect(verifyAction(chair.mldsa.publicKey, original!.message, hexToBytes(write!.signature))).toBe(true);
    }
  });

  it("offers four changed tries that the same signature does not verify over: another board, the next nonce, another registry, one flipped signature bit", () => {
    const write = decodeWrite(calldata(actions[0]!))!;
    const all = trials(write, { registry: REGISTRY, nonce: NONCE });
    expect(all.map((t) => t.what)).toEqual(["original", "other_board", "next_nonce", "other_registry", "flipped_signature"]);
    for (const trial of all.slice(1)) {
      expect(verifyAction(chair.mldsa.publicKey, trial.message, trial.signature)).toBe(false);
    }
    expect(all.every((t) => t.message.length === 256)).toBe(true);
  });

  it("reads nothing out of calldata that is not one of the registry's signed changes", () => {
    expect(decodeWrite("0x")).toBeUndefined();
    expect(decodeWrite("0x12345678")).toBeUndefined();
    expect(decodeWrite(`0xa9059cbb${"00".repeat(64)}`)).toBeUndefined();
  });
});

describe("unsignedRotate", () => {
  it("is a well-formed rotation for the board's next epoch that carries no signature at all", () => {
    const data = unsignedRotate({ boardId: 15n, epoch: 4n, latestBlockTimestamp: LATEST });
    const write = decodeWrite(data);
    expect(write?.functionName).toBe("rotateEpoch");
    expect(write?.boardId).toBe(15n);
    expect(write?.deadline).toBe(LATEST + 600n);
    expect(hexToBytes(write!.signature)).toHaveLength(4_627);
    expect(hexToBytes(write!.signature).every((b) => b === 0)).toBe(true);
  });
});

describe("refusalName", () => {
  it("names the registry's own refusal from revert data", () => {
    expect(refusalName(encodeErrorResult({ abi: REGISTRY_ERRORS, errorName: "BadSignature", args: [MEMBER] }))).toBe("BadSignature");
    expect(refusalName(encodeErrorResult({ abi: REGISTRY_ERRORS, errorName: "DeadlineExpired", args: [1n, 2n] }))).toBe("DeadlineExpired");
  });

  it("claims no name for data that is none of the registry's errors, or for none", () => {
    expect(refusalName("0xdeadbeef")).toBeUndefined();
    expect(refusalName(undefined)).toBeUndefined();
    expect(refusalName("0x")).toBeUndefined();
  });
});
