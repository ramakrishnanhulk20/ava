// Covers what the browser decides for itself around a leave (threat model C45, C47, C26): which leave
// request it will sign, and which receipt it takes as its own removal. Does NOT cover the bot, the
// network calls around these checks, or the signature itself (core's signLeave tests cover that).
import { challengeMessage, leaveMessage } from "@ava/core";
import { bytesToHex, encodeAbiParameters, encodeEventTopics, parseAbi, type Hex, type Log } from "viem";
import { describe, expect, it } from "vitest";
import { checkLeaveRequest, removalIn } from "./leave";

const REGISTRY = "0x2bB34f60B29C7bC10f7ECC0B5050329E808DAcBa";
const ELSEWHERE = "0x3333333333333333333333333333333333333333";
const GUEST: Hex = "0x1111111111111111111111111111111111111111";
const OTHER: Hex = "0x2222222222222222222222222222222222222222";
const NONCE: Hex = `0x${"b1".repeat(32)}`;
const fields = { registry: REGISTRY, boardId: 15n, guest: GUEST, botNonce: NONCE, expiry: 1_795_000_000n };
const expected = { registry: REGISTRY, boardId: 15n, guest: GUEST };

function answer(message: Uint8Array, over: Record<string, unknown> = {}): Record<string, unknown> {
  return { registry: REGISTRY, boardId: "15", botNonce: NONCE, expiry: "1795000000", message: bytesToHex(message), ...over };
}

describe("checkLeaveRequest", () => {
  it("takes the bot's request when its bytes are the spec's leave message for this guest, board and registry", () => {
    const request = checkLeaveRequest(answer(leaveMessage(fields)), expected);
    expect(request).toEqual({ registry: REGISTRY, boardId: 15n, botNonce: NONCE, expiry: 1_795_000_000n, message: bytesToHex(leaveMessage(fields)) });
  });

  it("refuses bytes under the join tag for the same fields", () => {
    expect(() => checkLeaveRequest(answer(challengeMessage(fields)), expected)).toThrow(/Refusing to sign/);
  });

  it("refuses a request built for another guest, another board or another registry", () => {
    expect(() => checkLeaveRequest(answer(leaveMessage({ ...fields, guest: OTHER })), expected)).toThrow(/Refusing to sign/);
    expect(() => checkLeaveRequest(answer(leaveMessage({ ...fields, boardId: 16n }), { boardId: "16" }), expected)).toThrow(/Refusing to sign/);
    expect(() => checkLeaveRequest(answer(leaveMessage({ ...fields, registry: ELSEWHERE }), { registry: ELSEWHERE }), expected)).toThrow(/Refusing to sign/);
  });

  it("refuses bytes that are not the encoding of the fields beside them", () => {
    const honest = leaveMessage(fields);
    const flipped = Uint8Array.from(honest);
    flipped[223] = (flipped[223] ?? 0) ^ 1;
    expect(() => checkLeaveRequest(answer(flipped), expected)).toThrow(/Refusing to sign/);
    expect(() => checkLeaveRequest(answer(Uint8Array.from([...honest, 0])), expected)).toThrow(/Refusing to sign/);
    expect(() => checkLeaveRequest(answer(honest, { expiry: "1795000001" }), expected)).toThrow(/Refusing to sign/);
  });

  it("refuses an answer that is not in the shape the bot sends", () => {
    const honest = leaveMessage(fields);
    for (const over of [{ botNonce: undefined }, { botNonce: "0x12" }, { expiry: "0" }, { expiry: 1_795_000_000 }, { boardId: "0" }, { message: "not hex" }, { registry: 7 }]) {
      expect(() => checkLeaveRequest(answer(honest, over), expected)).toThrow(/not in the shape/);
    }
  });
});

const events = parseAbi([
  "event MemberRemoved(uint256 indexed boardId, address indexed member, uint64 newEpoch, uint64 nonce)",
  "event MemberAdded(uint256 indexed boardId, address indexed member, uint64 epoch, uint8 mode, uint64 nonce)",
]);

function removedLog(address: string, boardId: bigint, member: Hex, newEpoch: bigint): Log {
  return {
    address,
    topics: encodeEventTopics({ abi: events, eventName: "MemberRemoved", args: { boardId, member } }),
    data: encodeAbiParameters([{ type: "uint64" }, { type: "uint64" }], [newEpoch, 99n]),
  } as unknown as Log;
}

describe("removalIn", () => {
  it("finds the registry's MemberRemoved for this board and this account, and gives the new epoch", () => {
    expect(removalIn([removedLog(REGISTRY, 15n, GUEST, 44n)], expected)).toEqual({ epoch: 44n });
  });

  it("does not count the same event from another contract", () => {
    expect(removalIn([removedLog(ELSEWHERE, 15n, GUEST, 44n)], expected)).toBeUndefined();
  });

  it("does not count another member's removal, or one on another board", () => {
    expect(removalIn([removedLog(REGISTRY, 15n, OTHER, 44n), removedLog(REGISTRY, 16n, GUEST, 44n)], expected)).toBeUndefined();
  });

  it("does not count this account's MemberAdded, or a receipt with no logs", () => {
    const added = {
      address: REGISTRY,
      topics: encodeEventTopics({ abi: events, eventName: "MemberAdded", args: { boardId: 15n, member: GUEST } }),
      data: encodeAbiParameters([{ type: "uint64" }, { type: "uint8" }, { type: "uint64" }], [43n, 1, 98n]),
    } as unknown as Log;
    expect(removalIn([added], expected)).toBeUndefined();
    expect(removalIn([], expected)).toBeUndefined();
  });
});
