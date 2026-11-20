// Not covered here: that the Solidity registry builds the same bytes (the next contract order checks
// test-vectors/actions.json byte for byte), and nonce or epoch rules, which only the chain knows.
import { bytesToHex, concat, hexToBytes, keccak256, stringToBytes, type Hex } from "viem";
import { describe, expect, it } from "vitest";
import {
  ActionError,
  actionMessage,
  challengeMessage,
  deadlineFrom,
  paramsAdd,
  paramsCreate,
  paramsPost,
  paramsRemove,
  paramsRotate,
  paramsTransfer,
} from "../src/actions.ts";
import { AddressError, toQor1 } from "../src/address.ts";
import { Action, BOARD_TAG, CHALLENGE_TAG, MAX_DEADLINE_AHEAD, Mode } from "../src/constants.ts";

// abi.encode of static types is a run of 32-byte big-endian words. Built by hand here, apart from viem.
function word(value: bigint | number | Hex): Uint8Array {
  const out = new Uint8Array(32);
  if (typeof value === "string") {
    const bytes = hexToBytes(value);
    out.set(bytes, 32 - bytes.length);
    return out;
  }
  let n = BigInt(value);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}
const hashWords = (...words: Uint8Array[]): Hex => keccak256(concat(words));

const REGISTRY = "0x00000000000000000000000000000000000a0a0a";
const CHAIR = "0x1111111111111111111111111111111111111111";
const MEMBER = "0x2222222222222222222222222222222222222222";
const ENVELOPE_HASH = `0x${"e1".repeat(32)}` as Hex;
const DOC_REF = `0x${"d1".repeat(32)}` as Hex;
const CIPHER_HASH = `0x${"c1".repeat(32)}` as Hex;
const BOARD_REF = `0x${"a1".repeat(32)}` as Hex;

const base = { registry: REGISTRY, action: Action.ADD, boardId: 7n, paramsHash: ENVELOPE_HASH, nonce: 3n, deadline: 1_795_000_000n } as const;

describe("tags", () => {
  it("match the spec", () => {
    expect(BOARD_TAG).toBe("0x202301722596364529594a8773ff4f11aeb962e112437e042aa0166a90966a17");
    expect(CHALLENGE_TAG).toBe(keccak256(stringToBytes("ava.challenge.v1")));
    expect(hexToBytes(CHALLENGE_TAG)[0]).toBe(0x00);
  });
});

describe("params hashes", () => {
  it("CREATE", () => {
    const create = { chair: CHAIR, boardRef: BOARD_REF, envelopeHash: ENVELOPE_HASH, envelopeSize: 1729 };
    expect(paramsCreate(create)).toBe(hashWords(word(CHAIR), word(BOARD_REF), word(ENVELOPE_HASH), word(1729)));
    expect(paramsCreate({ ...create, boardRef: DOC_REF })).not.toBe(paramsCreate(create));
    expect(() => paramsCreate({ ...create, boardRef: `0x${"00".repeat(32)}` })).toThrow(ActionError);
  });

  it("ADD", () => {
    expect(paramsAdd({ member: MEMBER, mode: Mode.ROTATE, envelopeHash: ENVELOPE_HASH, envelopeSize: 3361, epochAfter: 5n })).toBe(
      hashWords(word(MEMBER), word(1), word(ENVELOPE_HASH), word(3361), word(5)),
    );
  });

  it("REMOVE", () => {
    expect(paramsRemove({ member: MEMBER, envelopeHash: ENVELOPE_HASH, envelopeSize: 1729, epochAfter: 5n })).toBe(
      hashWords(word(MEMBER), word(ENVELOPE_HASH), word(1729), word(5)),
    );
  });

  it("ROTATE", () => {
    expect(paramsRotate({ envelopeHash: ENVELOPE_HASH, envelopeSize: 3361, epochAfter: 5n })).toBe(hashWords(word(ENVELOPE_HASH), word(3361), word(5)));
  });

  it("POST", () => {
    expect(paramsPost({ docRef: DOC_REF, cipherHash: CIPHER_HASH, cipherSize: 1_048_604n, epoch: 4n })).toBe(
      hashWords(word(DOC_REF), word(CIPHER_HASH), word(1_048_604), word(4)),
    );
  });

  it("TRANSFER", () => {
    expect(paramsTransfer({ newChair: MEMBER })).toBe(hashWords(word(MEMBER)));
  });

  it("give the same hash for raw bytes, uppercase hex and the qor1 form of an address", () => {
    const a = paramsAdd({ member: MEMBER, mode: Mode.SEAL_CURRENT, envelopeHash: ENVELOPE_HASH, envelopeSize: 1729, epochAfter: 4n });
    const b = paramsAdd({ member: MEMBER, mode: Mode.SEAL_CURRENT, envelopeHash: hexToBytes(ENVELOPE_HASH), envelopeSize: 1729n, epochAfter: 4 });
    const c = paramsAdd({ member: MEMBER, mode: Mode.SEAL_CURRENT, envelopeHash: ENVELOPE_HASH.toUpperCase().replace("0X", "0x") as Hex, envelopeSize: 1729, epochAfter: 4n });
    const d = paramsAdd({ member: toQor1(hexToBytes(MEMBER)), mode: Mode.SEAL_CURRENT, envelopeHash: ENVELOPE_HASH, envelopeSize: 1729, epochAfter: 4n });
    expect(b).toBe(a);
    expect(c).toBe(a);
    expect(d).toBe(a);
  });

  it("decode chair, member and newChair strictly: all-lowercase 0x is refused, EIP-55 and qor1 give one hash (C16)", () => {
    const eip55 = "0x8A37d6f2DA1F8a07f1735c568C2611205d93e973";
    const qor1 = toQor1(hexToBytes(eip55));
    const lower = eip55.toLowerCase();
    const builders = [
      (who: string) => paramsCreate({ chair: who, boardRef: BOARD_REF, envelopeHash: ENVELOPE_HASH, envelopeSize: 1729 }),
      (who: string) => paramsAdd({ member: who, mode: Mode.SEAL_CURRENT, envelopeHash: ENVELOPE_HASH, envelopeSize: 1729, epochAfter: 4n }),
      (who: string) => paramsRemove({ member: who, envelopeHash: ENVELOPE_HASH, envelopeSize: 1729, epochAfter: 5n }),
      (who: string) => paramsTransfer({ newChair: who }),
    ];
    for (const build of builders) {
      expect(() => build(lower)).toThrow(AddressError);
      expect(build(qor1)).toBe(build(eip55));
    }
    expect(actionMessage({ ...base, registry: lower })).toHaveLength(256);
  });

  it("change when any single parameter changes", () => {
    const add = { member: MEMBER, mode: Mode.SEAL_CURRENT, envelopeHash: ENVELOPE_HASH, envelopeSize: 1729, epochAfter: 4n } as const;
    const original = paramsAdd(add);
    for (const changed of [
      { ...add, member: CHAIR },
      { ...add, mode: Mode.ROTATE },
      { ...add, envelopeHash: CIPHER_HASH },
      { ...add, envelopeSize: 1730 },
      { ...add, epochAfter: 5n },
    ]) {
      expect(paramsAdd(changed)).not.toBe(original);
    }
    const post = { docRef: DOC_REF, cipherHash: CIPHER_HASH, cipherSize: 1000n, epoch: 4n };
    expect(paramsPost({ ...post, docRef: ENVELOPE_HASH })).not.toBe(paramsPost(post));
    expect(paramsPost({ ...post, cipherSize: 1001n })).not.toBe(paramsPost(post));
  });

  it("refuse values the registry would refuse", () => {
    const create = { chair: CHAIR, boardRef: BOARD_REF, envelopeHash: ENVELOPE_HASH, envelopeSize: 1729 };
    expect(paramsCreate(create)).toMatch(/^0x[0-9a-f]{64}$/);
    expect(() => paramsCreate({ ...create, envelopeSize: 0 })).toThrow(ActionError);
    expect(() => paramsCreate({ ...create, envelopeSize: 110_001 })).toThrow(ActionError);
    expect(() => paramsCreate({ ...create, envelopeHash: `0x${"00".repeat(32)}` })).toThrow(ActionError);
    expect(() => paramsCreate({ ...create, chair: `0x${"00".repeat(20)}` })).toThrow(ActionError);
    expect(() => paramsAdd({ member: MEMBER, mode: 2 as Mode, envelopeHash: ENVELOPE_HASH, envelopeSize: 1729, epochAfter: 4n })).toThrow(ActionError);
    expect(() => paramsPost({ docRef: DOC_REF, cipherHash: CIPHER_HASH, cipherSize: 26_214_401n, epoch: 4n })).toThrow(ActionError);
    expect(() => paramsRotate({ envelopeHash: ENVELOPE_HASH, envelopeSize: 1729, epochAfter: 1n << 64n })).toThrow(ActionError);
  });
});

describe("actionMessage", () => {
  it("is the eight words of the spec: 256 bytes, first byte 0x20", () => {
    const message = actionMessage(base);
    const expected = concat([word(BOARD_TAG), word(9800), word(REGISTRY), word(Action.ADD), word(7), word(ENVELOPE_HASH), word(3), word(1_795_000_000)]);
    expect(message.length).toBe(256);
    expect(message[0]).toBe(0x20);
    expect(bytesToHex(message)).toBe(bytesToHex(expected));
  });

  it("changes when any single field changes", () => {
    const original = bytesToHex(actionMessage(base));
    for (const changed of [
      { ...base, registry: CHAIR },
      { ...base, action: Action.REMOVE },
      { ...base, boardId: 8n },
      { ...base, paramsHash: CIPHER_HASH },
      { ...base, nonce: 4n },
      { ...base, deadline: 1_795_000_001n },
    ]) {
      expect(bytesToHex(actionMessage(changed))).not.toBe(original);
    }
  });

  it("signs board 0 only for CREATE", () => {
    expect(actionMessage({ ...base, action: Action.CREATE, boardId: 0n }).length).toBe(256);
    expect(() => actionMessage({ ...base, action: Action.CREATE, boardId: 7n })).toThrow(ActionError);
    expect(() => actionMessage({ ...base, boardId: 0n })).toThrow(ActionError);
    expect(() => actionMessage({ ...base, action: 7 as Action })).toThrow(ActionError);
    expect(() => actionMessage({ ...base, deadline: 0n })).toThrow(ActionError);
  });
});

describe("challengeMessage", () => {
  it("is the seven words of the spec, first byte 0x00", () => {
    const p = { registry: REGISTRY, boardId: 7n, guest: MEMBER, botNonce: `0x${"b1".repeat(32)}` as Hex, expiry: 1_795_000_000n };
    const message = challengeMessage(p);
    const expected = concat([word(CHALLENGE_TAG), word(9800), word(REGISTRY), word(7), word(MEMBER), word(p.botNonce), word(1_795_000_000)]);
    expect(message.length).toBe(224);
    expect(message[0]).toBe(0x00);
    expect(bytesToHex(message)).toBe(bytesToHex(expected));
    expect(bytesToHex(challengeMessage({ ...p, guest: CHAIR }))).not.toBe(bytesToHex(message));
  });
});

describe("deadlineFrom", () => {
  it("adds up to one hour to the latest block time and refuses more", () => {
    expect(deadlineFrom(1_795_000_000n, 600)).toBe(1_795_000_600n);
    expect(deadlineFrom(1_795_000_000, MAX_DEADLINE_AHEAD)).toBe(1_795_003_600n);
    expect(() => deadlineFrom(1_795_000_000n, MAX_DEADLINE_AHEAD + 1)).toThrow(ActionError);
    expect(() => deadlineFrom(1_795_000_000n, 0)).toThrow(ActionError);
    expect(() => deadlineFrom(-1, 600)).toThrow(ActionError);
  });
});
