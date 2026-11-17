// Not covered here: the chain's pqcVerify precompile accepting these signatures (proven live in the
// M1 probe, and again by the contract tests), and whether the key is registered or possession-proven.
import { beforeAll, describe, expect, it } from "vitest";
import { ActionError, actionMessage, challengeMessage, paramsTransfer } from "../src/actions.ts";
import { sameAccount } from "../src/address.ts";
import { Action, ML_DSA_87_PUBKEY, ML_DSA_87_SIG, ML_KEM_1024_PUBKEY } from "../src/constants.ts";
import { generateMnemonic, identityFromMnemonic, type Identity } from "../src/identity.ts";
import { signAction, verifyAction } from "../src/sign.ts";

const REGISTRY = "0x00000000000000000000000000000000000a0a0a";

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
