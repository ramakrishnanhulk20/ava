// Covers what the chair's browser decides for itself around a board action (threat model C2, C26, C45):
// the body it sends is exactly what it signed, built from typed fields, and only the registry's own
// event for that action, matched on board and nonce, counts as landed. Does NOT cover the relay, the
// uploads, the chain reads around these checks, or the registry's own checks (the contract's tests).
import { Action, Mode, actionMessage, identityFromMnemonic, generateMnemonic, paramsAdd, paramsCreate, paramsPost, paramsRemove, paramsRotate, verifyAction, type Identity } from "@ava/core";
import { encodeAbiParameters, encodeEventTopics, hexToBytes, parseAbi, type Hex, type Log } from "viem";
import { beforeAll, describe, expect, it } from "vitest";
import { landed, signedRelayBody, type ChairAction } from "./actions";

const REGISTRY = "0x2bB34f60B29C7bC10f7ECC0B5050329E808DAcBa";
const ELSEWHERE = "0x3333333333333333333333333333333333333333";
const MEMBER: Hex = "0x1111111111111111111111111111111111111111";
const HASH = (byte: string): Hex => `0x${byte.repeat(32)}`;
const LATEST = 1_795_000_000n;

let chair: Identity;
beforeAll(async () => {
  chair = await identityFromMnemonic(generateMnemonic());
});

type Sent = { action: string; boardId?: string; params: Record<string, string>; deadline: string; signature: Hex };

function verifies(body: Sent, code: Action, boardId: bigint, paramsHash: Hex, nonce: bigint): boolean {
  const message = actionMessage({ registry: REGISTRY, action: code, boardId, paramsHash, nonce, deadline: BigInt(body.deadline) });
  return verifyAction(chair.mldsa.publicKey, message, hexToBytes(body.signature));
}

describe("signedRelayBody", () => {
  const at = { registry: REGISTRY, nonce: 7n, latestBlockTimestamp: LATEST };

  it("signs a create for the chair's own account and sends exactly those fields, with no board id", () => {
    const a: ChairAction = { action: "create", chair: chair.evm, boardRef: HASH("a1"), envelopeHash: HASH("b2"), envelopeSize: 1_700 };
    const body = signedRelayBody(chair.mldsa.secretKey, a, at) as Sent;
    expect(Object.keys(body).sort()).toEqual(["action", "deadline", "params", "signature"]);
    expect(body.params).toEqual({ chair: chair.evm, boardRef: HASH("a1"), envelopeHash: HASH("b2"), envelopeSize: "1700" });
    expect(verifies(body, Action.CREATE, 0n, paramsCreate({ chair: chair.evm, boardRef: HASH("a1"), envelopeHash: HASH("b2"), envelopeSize: 1_700 }), 7n)).toBe(true);
  });

  it("signs an add, a remove, a rotate and a post for one board, each body carrying only its own fields as decimal strings", () => {
    const add = signedRelayBody(chair.mldsa.secretKey, { action: "add", boardId: 15n, member: MEMBER, mode: Mode.SEAL_CURRENT, envelopeHash: HASH("b2"), envelopeSize: 1_700, epochAfter: 3n }, at) as Sent;
    expect(add.boardId).toBe("15");
    expect(add.params).toEqual({ member: MEMBER, mode: "0", envelopeHash: HASH("b2"), envelopeSize: "1700", epochAfter: "3" });
    expect(verifies(add, Action.ADD, 15n, paramsAdd({ member: MEMBER, mode: Mode.SEAL_CURRENT, envelopeHash: HASH("b2"), envelopeSize: 1_700, epochAfter: 3n }), 7n)).toBe(true);

    const remove = signedRelayBody(chair.mldsa.secretKey, { action: "remove", boardId: 15n, member: MEMBER, envelopeHash: HASH("b2"), envelopeSize: 1_700, epochAfter: 4n }, at) as Sent;
    expect(remove.params).toEqual({ member: MEMBER, envelopeHash: HASH("b2"), envelopeSize: "1700", epochAfter: "4" });
    expect(verifies(remove, Action.REMOVE, 15n, paramsRemove({ member: MEMBER, envelopeHash: HASH("b2"), envelopeSize: 1_700, epochAfter: 4n }), 7n)).toBe(true);

    const rotate = signedRelayBody(chair.mldsa.secretKey, { action: "rotate", boardId: 15n, envelopeHash: HASH("b2"), envelopeSize: 1_700, epochAfter: 4n }, at) as Sent;
    expect(rotate.params).toEqual({ envelopeHash: HASH("b2"), envelopeSize: "1700", epochAfter: "4" });
    expect(verifies(rotate, Action.ROTATE, 15n, paramsRotate({ envelopeHash: HASH("b2"), envelopeSize: 1_700, epochAfter: 4n }), 7n)).toBe(true);

    const post = signedRelayBody(chair.mldsa.secretKey, { action: "post", boardId: 15n, docRef: HASH("c3"), cipherHash: HASH("d4"), cipherSize: 4_096n, epoch: 3n }, at) as Sent;
    expect(post.params).toEqual({ docRef: HASH("c3"), cipherHash: HASH("d4"), cipherSize: "4096", epoch: "3" });
    expect(verifies(post, Action.POST, 15n, paramsPost({ docRef: HASH("c3"), cipherHash: HASH("d4"), cipherSize: 4_096n, epoch: 3n }), 7n)).toBe(true);
  });

  it("takes its deadline from the latest block, ten minutes ahead unless told otherwise, and never past the hour", () => {
    const a: ChairAction = { action: "rotate", boardId: 15n, envelopeHash: HASH("b2"), envelopeSize: 1_700, epochAfter: 4n };
    expect((signedRelayBody(chair.mldsa.secretKey, a, at) as Sent).deadline).toBe((LATEST + 600n).toString());
    expect((signedRelayBody(chair.mldsa.secretKey, a, { ...at, seconds: 3_600 }) as Sent).deadline).toBe((LATEST + 3_600n).toString());
    expect(() => signedRelayBody(chair.mldsa.secretKey, a, { ...at, seconds: 3_601 })).toThrow();
  });

  it("gives a signature that is no use for another board, another nonce or another registry", () => {
    const fields = { envelopeHash: HASH("b2"), envelopeSize: 1_700, epochAfter: 4n };
    const body = signedRelayBody(chair.mldsa.secretKey, { action: "rotate", boardId: 15n, ...fields }, at) as Sent;
    const hash = paramsRotate(fields);
    expect(verifies(body, Action.ROTATE, 16n, hash, 7n)).toBe(false);
    expect(verifies(body, Action.ROTATE, 15n, hash, 8n)).toBe(false);
    const elsewhere = actionMessage({ registry: ELSEWHERE, action: Action.ROTATE, boardId: 15n, paramsHash: hash, nonce: 7n, deadline: BigInt(body.deadline) });
    expect(verifyAction(chair.mldsa.publicKey, elsewhere, hexToBytes(body.signature))).toBe(false);
  });
});

const events = parseAbi([
  "event BoardCreated(uint256 indexed boardId, address indexed chair, bytes32 boardRef, uint64 createNonce)",
  "event EnvelopeGranted(uint256 indexed boardId, uint64 indexed epoch, bytes32 envelopeHash, uint32 envelopeSize, uint8 mode, address member, uint64 nonce)",
  "event MemberAdded(uint256 indexed boardId, address indexed member, uint64 epoch, uint8 mode, uint64 nonce)",
  "event MemberRemoved(uint256 indexed boardId, address indexed member, uint64 newEpoch, uint64 nonce)",
  "event EpochRotated(uint256 indexed boardId, uint64 indexed newEpoch, uint64 nonce)",
  "event DocumentPosted(uint256 indexed boardId, uint256 indexed docId, bytes32 docRef, uint64 epoch, bytes32 cipherHash, uint64 cipherSize, uint64 nonce)",
]);

const log = (address: string, topics: unknown, data: Hex): Log => ({ address, topics, data }) as unknown as Log;
const created = (address: string, boardId: bigint, who: Hex, boardRef: Hex, createNonce: bigint): Log =>
  log(address, encodeEventTopics({ abi: events, eventName: "BoardCreated", args: { boardId, chair: who } }), encodeAbiParameters([{ type: "bytes32" }, { type: "uint64" }], [boardRef, createNonce]));
const posted = (address: string, boardId: bigint, docId: bigint, docRef: Hex, nonce: bigint): Log =>
  log(
    address,
    encodeEventTopics({ abi: events, eventName: "DocumentPosted", args: { boardId, docId } }),
    encodeAbiParameters([{ type: "bytes32" }, { type: "uint64" }, { type: "bytes32" }, { type: "uint64" }, { type: "uint64" }], [docRef, 3n, HASH("d4"), 4_096n, nonce]),
  );
const granted = (address: string, boardId: bigint, nonce: bigint): Log =>
  log(
    address,
    encodeEventTopics({ abi: events, eventName: "EnvelopeGranted", args: { boardId, epoch: 0n } }),
    encodeAbiParameters([{ type: "bytes32" }, { type: "uint32" }, { type: "uint8" }, { type: "address" }, { type: "uint64" }], [HASH("b2"), 1_700, 1, "0x0000000000000000000000000000000000000000", nonce]),
  );
const removed = (address: string, boardId: bigint, member: Hex, nonce: bigint): Log =>
  log(address, encodeEventTopics({ abi: events, eventName: "MemberRemoved", args: { boardId, member } }), encodeAbiParameters([{ type: "uint64" }, { type: "uint64" }], [4n, nonce]));

describe("landed", () => {
  it("takes a create as landed only on the registry's BoardCreated for this chair, this boardRef and this create nonce, and reads the new board id from it", () => {
    const want = { registry: REGISTRY, action: "create" as const, chair: MEMBER, boardRef: HASH("a1"), nonce: 2n };
    expect(landed([created(REGISTRY, 41n, MEMBER, HASH("a1"), 2n), granted(REGISTRY, 41n, 2n)], want)).toEqual({ boardId: 41n });
    expect(landed([created(ELSEWHERE, 41n, MEMBER, HASH("a1"), 2n)], want)).toBeUndefined();
    expect(landed([created(REGISTRY, 41n, MEMBER, HASH("a1"), 3n)], want)).toBeUndefined();
    expect(landed([created(REGISTRY, 41n, MEMBER, HASH("ff"), 2n)], want)).toBeUndefined();
    expect(landed([created(REGISTRY, 41n, "0x2222222222222222222222222222222222222222", HASH("a1"), 2n)], want)).toBeUndefined();
  });

  it("never takes EnvelopeGranted as proof of anything", () => {
    expect(landed([granted(REGISTRY, 41n, 2n)], { registry: REGISTRY, action: "create", chair: MEMBER, boardRef: HASH("a1"), nonce: 2n })).toBeUndefined();
    expect(landed([granted(REGISTRY, 15n, 7n)], { registry: REGISTRY, action: "rotate", boardId: 15n, nonce: 7n })).toBeUndefined();
  });

  it("takes a post as landed only on DocumentPosted for this board, this docRef and this board nonce, and reads the document id from it", () => {
    const want = { registry: REGISTRY, action: "post" as const, boardId: 15n, docRef: HASH("c3"), nonce: 7n };
    expect(landed([posted(REGISTRY, 15n, 5n, HASH("c3"), 7n)], want)).toEqual({ boardId: 15n, docId: 5n });
    expect(landed([posted(REGISTRY, 16n, 5n, HASH("c3"), 7n)], want)).toBeUndefined();
    expect(landed([posted(REGISTRY, 15n, 5n, HASH("c3"), 8n)], want)).toBeUndefined();
    expect(landed([posted(REGISTRY, 15n, 5n, HASH("ee"), 7n)], want)).toBeUndefined();
    expect(landed([posted(ELSEWHERE, 15n, 5n, HASH("c3"), 7n)], want)).toBeUndefined();
  });

  it("takes a removal as landed only on MemberRemoved for this board, this member and this board nonce", () => {
    const want = { registry: REGISTRY, action: "remove" as const, boardId: 15n, member: MEMBER, nonce: 7n };
    expect(landed([removed(REGISTRY, 15n, MEMBER, 7n)], want)).toEqual({ boardId: 15n });
    expect(landed([removed(REGISTRY, 15n, MEMBER, 6n)], want)).toBeUndefined();
    expect(landed([removed(REGISTRY, 15n, "0x2222222222222222222222222222222222222222", 7n)], want)).toBeUndefined();
    expect(landed([], want)).toBeUndefined();
  });
});
