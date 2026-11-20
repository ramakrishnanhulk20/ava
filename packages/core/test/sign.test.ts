// Not covered here: the chain's pqcVerify precompile accepting these signatures (proven live in the
// M1 probe, and again by the contract tests), and whether the key is registered or possession-proven.
import { generateMnemonic as sdkGenerateMnemonic } from "@qorechain/sdk";
import { beforeAll, describe, expect, it } from "vitest";
import { bytesToHex, type Hex } from "viem";
import {
  ActionError,
  actionMessage,
  challengeMessage,
  paramsAdd,
  paramsCreate,
  paramsPost,
  paramsRemove,
  paramsRotate,
  paramsTransfer,
  type BoardActionInput,
} from "../src/actions.ts";
import { sameAccount } from "../src/address.ts";
import { Action, MAX_DEADLINE_AHEAD, ML_DSA_87_PUBKEY, ML_DSA_87_SIG, ML_KEM_1024_PUBKEY, Mode } from "../src/constants.ts";
import { generateMnemonic, identityFromMnemonic, type Identity } from "../src/identity.ts";
import { signAction, signBoardAction, signChallenge, verifyAction } from "../src/sign.ts";

const REGISTRY = "0x00000000000000000000000000000000000a0a0a";
const LATEST = 1_795_000_000n;
const HASH = (byte: string): Hex => `0x${byte.repeat(32)}`;

let chair: Identity;
let other: Identity;
let message: Uint8Array;

beforeAll(async () => {
  chair = await identityFromMnemonic(generateMnemonic());
  other = await identityFromMnemonic(generateMnemonic());
  message = actionMessage({
    registry: REGISTRY,
    action: Action.TRANSFER,
    boardId: 7n,
    paramsHash: paramsTransfer({ newChair: other.evm }),
    nonce: 3n,
    deadline: 1_795_000_000n,
  });
});

describe("identity", () => {
  it("derives one account and its three key pairs from a 24-word phrase", async () => {
    const phrase = generateMnemonic();
    expect(phrase.split(" ")).toHaveLength(24);
    const a = await identityFromMnemonic(phrase);
    const b = await identityFromMnemonic(phrase);
    expect(sameAccount(a.qor1, a.evm)).toBe(true);
    expect(sameAccount(a.account, a.evm)).toBe(true);
    expect(a.privateKey).toHaveLength(32);
    expect(a.mldsa.publicKey).toHaveLength(ML_DSA_87_PUBKEY);
    expect(a.seal.mlkemPublicKey).toHaveLength(ML_KEM_1024_PUBKEY);
    expect(b.mldsa.publicKey).toEqual(a.mldsa.publicKey);
    expect(b.seal.mlkemPublicKey).toEqual(a.seal.mlkemPublicKey);
    expect(sameAccount(a.evm, chair.evm)).toBe(false);
  });

  it("refuses an invalid phrase", async () => {
    await expect(identityFromMnemonic("not a recovery phrase")).rejects.toThrow();
  });

  it("gives one account and one key set for every spacing and width of the same phrase (C16)", async () => {
    const phrase = generateMnemonic();
    const words = phrase.split(" ");
    const swapOneSpace = (space: string) => [words.slice(0, 5).join(" "), words.slice(5).join(" ")].join(space);
    const first = words[3]!;
    const fullWidth = String.fromCodePoint(0xff41 + first.charCodeAt(0) - 0x61) + first.slice(1);
    const pasted = [
      swapOneSpace(" "),
      swapOneSpace("　"),
      swapOneSpace(" "),
      swapOneSpace("  "),
      `  ${phrase} \n`,
      [...words.slice(0, 3), fullWidth, ...words.slice(4)].join(" "),
    ];
    const expected = await identityFromMnemonic(phrase);
    for (const raw of pasted) {
      expect(raw).not.toBe(phrase);
      const got = await identityFromMnemonic(raw);
      expect(got.evm).toBe(expected.evm);
      expect(got.seal.mlkemPublicKey).toEqual(expected.seal.mlkemPublicKey);
      expect(got.mldsa.publicKey).toEqual(expected.mldsa.publicKey);
    }
  });

  it("refuses a valid 12-word phrase", async () => {
    const twelve = sdkGenerateMnemonic(128);
    expect(twelve.split(" ")).toHaveLength(12);
    await expect(identityFromMnemonic(twelve)).rejects.toThrow("The recovery phrase is not 24 valid words.");
  });
});

describe("signAction and verifyAction", () => {
  it("sign then verify", () => {
    const signature = signAction(chair.mldsa.secretKey, message);
    expect(signature).toHaveLength(ML_DSA_87_SIG);
    expect(verifyAction(chair.mldsa.publicKey, message, signature)).toBe(true);
  });

  it("signs a guest challenge too", () => {
    const challenge = challengeMessage({ registry: REGISTRY, boardId: 7n, guest: chair.evm, botNonce: `0x${"b1".repeat(32)}`, expiry: 1_795_000_000n });
    expect(verifyAction(chair.mldsa.publicKey, challenge, signAction(chair.mldsa.secretKey, challenge))).toBe(true);
  });

  it("a tampered byte fails verify", () => {
    const signature = signAction(chair.mldsa.secretKey, message);
    for (const offset of [0, 100, 255]) {
      const changed = Uint8Array.from(message);
      changed[offset] = changed[offset]! ^ 0x01;
      expect(verifyAction(chair.mldsa.publicKey, changed, signature)).toBe(false);
    }
    const badSignature = Uint8Array.from(signature);
    badSignature[100] = badSignature[100]! ^ 0x01;
    expect(verifyAction(chair.mldsa.publicKey, message, badSignature)).toBe(false);
    expect(verifyAction(other.mldsa.publicKey, message, signature)).toBe(false);
    expect(verifyAction(chair.mldsa.publicKey, message, signature.subarray(1))).toBe(false);
  });

  it("refuses to sign bytes that are not an Ava message", () => {
    const reserved = new TextEncoder().encode("qorechain-msg-v1|hello");
    expect(() => signAction(chair.mldsa.secretKey, reserved)).toThrow(ActionError);
    const wrongTag = Uint8Array.from(message);
    wrongTag[1] = wrongTag[1]! ^ 0x01;
    expect(() => signAction(chair.mldsa.secretKey, wrongTag)).toThrow(ActionError);
    expect(() => signAction(chair.mldsa.secretKey, message.subarray(0, 224))).toThrow(ActionError);
  });
});

describe("signBoardAction", () => {
  const where = { registry: REGISTRY, nonce: 3n, latestBlockTimestamp: LATEST, deadline: LATEST + 600n };

  /** Every action kind, with the paramsHash its own params function gives for the same fields. */
  function kinds(): { input: BoardActionInput; paramsHash: Hex }[] {
    const envelope = { envelopeHash: HASH("e1"), envelopeSize: 1729 };
    return [
      { input: { action: Action.CREATE, chair: chair.evm, boardRef: HASH("a1"), ...envelope }, paramsHash: paramsCreate({ chair: chair.evm, boardRef: HASH("a1"), ...envelope }) },
      {
        input: { action: Action.ADD, member: other.evm, mode: Mode.ROTATE, ...envelope, epochAfter: 5n },
        paramsHash: paramsAdd({ member: other.evm, mode: Mode.ROTATE, ...envelope, epochAfter: 5n }),
      },
      { input: { action: Action.REMOVE, member: other.evm, ...envelope, epochAfter: 5n }, paramsHash: paramsRemove({ member: other.evm, ...envelope, epochAfter: 5n }) },
      { input: { action: Action.ROTATE, ...envelope, epochAfter: 5n }, paramsHash: paramsRotate({ ...envelope, epochAfter: 5n }) },
      {
        input: { action: Action.POST, docRef: HASH("d1"), cipherHash: HASH("c1"), cipherSize: 1_048_604n, epoch: 4n },
        paramsHash: paramsPost({ docRef: HASH("d1"), cipherHash: HASH("c1"), cipherSize: 1_048_604n, epoch: 4n }),
      },
      { input: { action: Action.TRANSFER, newChair: other.evm }, paramsHash: paramsTransfer({ newChair: other.evm }) },
    ];
  }

  it("builds the paramsHash and the message itself for every action kind, and signs exactly those bytes (C33 mirror)", () => {
    const list = kinds();
    expect(new Set(list.map((k) => k.input.action)).size).toBe(Object.keys(Action).length);
    for (const { input, paramsHash } of list) {
      const boardId = input.action === Action.CREATE ? 0n : 7n;
      const smuggled = { ...input, paramsHash: HASH("ff"), message: new Uint8Array(256) };
      const signed = signBoardAction(chair.mldsa.secretKey, { ...smuggled, ...where, boardId });
      expect(signed.paramsHash).toBe(paramsHash);
      const expected = actionMessage({ registry: REGISTRY, action: input.action, boardId, paramsHash, nonce: where.nonce, deadline: where.deadline });
      expect(bytesToHex(signed.message)).toBe(bytesToHex(expected));
      expect(signed.signature).toHaveLength(ML_DSA_87_SIG);
      expect(verifyAction(chair.mldsa.publicKey, expected, signed.signature)).toBe(true);
    }
  });

  it("refuses a deadline at the latest block, signs one exactly MAX_DEADLINE_AHEAD ahead, and refuses one second more (C2)", () => {
    const transfer: BoardActionInput = { action: Action.TRANSFER, newChair: other.evm };
    const sign = (deadline: bigint) => signBoardAction(chair.mldsa.secretKey, { ...transfer, ...where, boardId: 7n, deadline });
    expect(() => sign(LATEST)).toThrow(ActionError);
    const edge = sign(LATEST + BigInt(MAX_DEADLINE_AHEAD));
    expect(verifyAction(chair.mldsa.publicKey, edge.message, edge.signature)).toBe(true);
    expect(() => sign(LATEST + BigInt(MAX_DEADLINE_AHEAD) + 1n)).toThrow(ActionError);
  });
});

describe("signChallenge", () => {
  const fields = () => ({ registry: REGISTRY, boardId: 7n, guest: chair.evm, botNonce: HASH("b1") });

  it("builds the challenge bytes itself and signs exactly those (C33 mirror)", () => {
    const expiry = LATEST + 300n;
    const smuggled = { ...fields(), message: actionMessage({ ...fields(), action: Action.ROTATE, paramsHash: HASH("e1"), nonce: 3n, deadline: expiry }) };
    const signed = signChallenge(chair.mldsa.secretKey, { ...smuggled, expiry, latestBlockTimestamp: LATEST });
    const expected = challengeMessage({ ...fields(), expiry });
    expect(bytesToHex(signed.message)).toBe(bytesToHex(expected));
    expect(signed.signature).toHaveLength(ML_DSA_87_SIG);
    expect(verifyAction(chair.mldsa.publicKey, expected, signed.signature)).toBe(true);
  });

  it("refuses an expiry at the latest block, signs one exactly MAX_DEADLINE_AHEAD ahead, and refuses one second more (C2)", () => {
    const sign = (expiry: bigint) => signChallenge(chair.mldsa.secretKey, { ...fields(), expiry, latestBlockTimestamp: LATEST });
    expect(() => sign(LATEST)).toThrow(ActionError);
    const edge = sign(LATEST + BigInt(MAX_DEADLINE_AHEAD));
    expect(verifyAction(chair.mldsa.publicKey, edge.message, edge.signature)).toBe(true);
    expect(() => sign(LATEST + BigInt(MAX_DEADLINE_AHEAD) + 1n)).toThrow(ActionError);
  });
});
