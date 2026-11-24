import { Action, actionMessage, paramsAdd, paramsPost, paramsRemove, paramsRotate, type Mode } from "@ava/core";
import { bytesToHex, decodeErrorResult, decodeFunctionData, encodeFunctionData, hexToBytes, parseAbi, type Hex } from "viem";

/** The registry's signed changes to an existing board, as the deployed contract declares them. */
export const REGISTRY_WRITES = parseAbi([
  "function addMember(uint256 boardId, address member, uint8 mode, bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter, uint64 deadline, bytes signature)",
  "function removeMember(uint256 boardId, address member, bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter, uint64 deadline, bytes signature)",
  "function rotateEpoch(uint256 boardId, bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter, uint64 deadline, bytes signature)",
  "function postDocument(uint256 boardId, bytes32 docRef, bytes32 cipherHash, uint64 cipherSize, uint64 epoch, uint64 deadline, bytes signature)",
]);

/** Every refusal the registry can give, copied from the deployed contract's ABI. */
export const REGISTRY_ERRORS = parseAbi([
  "error AlreadyMember(uint256 boardId, address account)",
  "error BadCipherSize(uint64 size)",
  "error BadEnvelopeSize(uint32 size)",
  "error BadKeyLength(address account, uint256 length)",
  "error BadMode(uint8 mode)",
  "error BadSignature(address signer)",
  "error BoardFull(uint256 boardId, uint256 maxMembers)",
  "error BoardRefUsed(bytes32 boardRef)",
  "error ChairCannotLeave(uint256 boardId, address chair)",
  "error DeadlineExpired(uint64 deadline, uint256 timestamp)",
  "error DeadlineTooFar(uint64 deadline, uint256 latestAllowed)",
  "error DocRefUsed(uint256 boardId, bytes32 docRef)",
  "error NoPqcKey(address account)",
  "error NotMember(uint256 boardId, address account)",
  "error PossessionNotProven(address account)",
  "error PrecompileUnavailable(address precompile)",
  "error SameChair(uint256 boardId, address chair)",
  "error UnknownBoard(uint256 boardId)",
  "error UnknownDocument(uint256 boardId, uint256 docId)",
  "error WrongAlgorithm(address account, uint8 algorithmId)",
  "error WrongEpoch(uint64 expected, uint64 given)",
  "error ZeroAddress()",
  "error ZeroHash()",
]);

const ML_DSA_87_SIGNATURE_BYTES = 4_627;
/** A registry address that is not ours, for the "another registry" try. */
const ELSEWHERE = "0x00000000000000000000000000000000000a7a00";

/** One landed change to a board, read back out of its transaction's calldata. */
export interface Write {
  functionName: "addMember" | "removeMember" | "rotateEpoch" | "postDocument";
  boardId: bigint;
  action: Action;
  /** The hash of the action's own parameters, rebuilt from the calldata with the library's params function. */
  paramsHash: Hex;
  deadline: bigint;
  signature: Hex;
}

/** Reads a signed change out of calldata, or undefined when the bytes are not one of the four the page knows. */
export function decodeWrite(data: Hex): Write | undefined {
  let decoded;
  try {
    decoded = decodeFunctionData({ abi: REGISTRY_WRITES, data });
  } catch {
    return undefined;
  }
  switch (decoded.functionName) {
    case "addMember": {
      const [boardId, member, mode, envelopeHash, envelopeSize, epochAfter, deadline, signature] = decoded.args;
      return { functionName: "addMember", boardId, action: Action.ADD, paramsHash: paramsAdd({ member, mode: mode as Mode, envelopeHash, envelopeSize, epochAfter }), deadline, signature };
    }
    case "removeMember": {
      const [boardId, member, envelopeHash, envelopeSize, epochAfter, deadline, signature] = decoded.args;
      return { functionName: "removeMember", boardId, action: Action.REMOVE, paramsHash: paramsRemove({ member, envelopeHash, envelopeSize, epochAfter }), deadline, signature };
    }
    case "rotateEpoch": {
      const [boardId, envelopeHash, envelopeSize, epochAfter, deadline, signature] = decoded.args;
      return { functionName: "rotateEpoch", boardId, action: Action.ROTATE, paramsHash: paramsRotate({ envelopeHash, envelopeSize, epochAfter }), deadline, signature };
    }
    case "postDocument": {
      const [boardId, docRef, cipherHash, cipherSize, epoch, deadline, signature] = decoded.args;
      return { functionName: "postDocument", boardId, action: Action.POST, paramsHash: paramsPost({ docRef, cipherHash, cipherSize, epoch }), deadline, signature };
    }
  }
}

export type TrialKind = "original" | "other_board" | "next_nonce" | "other_registry" | "flipped_signature";

/** One message and signature the page hands to the chain's ML-DSA-87 check and to its own. */
export interface Trial {
  what: TrialKind;
  message: Uint8Array;
  signature: Uint8Array;
}

/**
 * The five tries of the proof page's signature table, all on one real signature: the message it was
 * made over, then the same action stated for the next board, at the next nonce and under another
 * registry address, and last the true message with one bit of the signature flipped. Only the
 * first should verify, on the chain and in this browser.
 *
 * @param at.nonce The board nonce the action landed at, from the registry's own event for it.
 */
export function trials(write: Write, at: { registry: string; nonce: bigint }): Trial[] {
  const message = (over: { registry?: string; boardId?: bigint; nonce?: bigint } = {}): Uint8Array =>
    actionMessage({ registry: over.registry ?? at.registry, action: write.action, boardId: over.boardId ?? write.boardId, paramsHash: write.paramsHash, nonce: over.nonce ?? at.nonce, deadline: write.deadline });
  const signature = hexToBytes(write.signature);
  const flipped = Uint8Array.from(signature);
  flipped[0] = (flipped[0] ?? 0) ^ 1;
  return [
    { what: "original", message: message(), signature },
    { what: "other_board", message: message({ boardId: write.boardId + 1n }), signature },
    { what: "next_nonce", message: message({ nonce: at.nonce + 1n }), signature },
    { what: "other_registry", message: message({ registry: ELSEWHERE }), signature },
    { what: "flipped_signature", message: message(), signature: flipped },
  ];
}

/**
 * Calldata for a rotation of a board to its next epoch that is right in every field and carries a
 * signature of zeros: what someone holding only the chair's classical key could send.
 */
export function unsignedRotate(board: { boardId: bigint; epoch: bigint; latestBlockTimestamp: bigint }): Hex {
  return encodeFunctionData({
    abi: REGISTRY_WRITES,
    functionName: "rotateEpoch",
    args: [board.boardId, `0x${"11".repeat(32)}`, 1_729, board.epoch + 1n, board.latestBlockTimestamp + 600n, bytesToHex(new Uint8Array(ML_DSA_87_SIGNATURE_BYTES))],
  });
}

/** The registry's own name for a refusal, from revert data; undefined when the data is none of its errors. */
export function refusalName(data: Hex | undefined): string | undefined {
  if (data === undefined || data === "0x") return undefined;
  try {
    return decodeErrorResult({ abi: REGISTRY_ERRORS, data }).errorName;
  } catch {
    return undefined;
  }
}
