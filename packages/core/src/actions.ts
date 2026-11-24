import { bytesToHex, encodeAbiParameters, hexToBytes, keccak256, type Address, type Hex } from "viem";
import { accountBytes, accountBytesStrict, toHex } from "./address.ts";
import { Action, BOARD_TAG, CHALLENGE_TAG, EVM_CHAIN_ID, LEAVE_TAG, MAX_CIPHER_SIZE, MAX_DEADLINE_AHEAD, MAX_ENVELOPE_SIZE, Mode } from "./constants.ts";
import { toBytes32, toUint, type Bytes32, type Uint } from "./values.ts";

/** Eight 32-byte words. */
export const ACTION_MESSAGE_LENGTH = 256;
/** Seven 32-byte words. */
export const CHALLENGE_MESSAGE_LENGTH = 224;
export const LEAVE_MESSAGE_LENGTH = 224;

/** An input that cannot go into a signed action or challenge. */
export class ActionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ActionError";
  }
}

function uint(value: Uint, bits: 8 | 32 | 64 | 256, what: string): bigint {
  const n = toUint(value, bits);
  if (n === undefined) throw new ActionError(`${what} must be an unsigned ${bits}-bit integer.`);
  return n;
}

function bytes32(value: Bytes32, what: string): Hex {
  const bytes = toBytes32(value);
  if (bytes === undefined) throw new ActionError(`${what} must be 32 bytes.`);
  if (bytes.every((b) => b === 0)) throw new ActionError(`${what} must not be zero.`);
  return bytesToHex(bytes);
}

/** Decodes through the shared address codec and refuses the zero account, which no one can sign for. */
function account(input: string, what: string, decode: (input: string) => Uint8Array = accountBytes): Address {
  const bytes = decode(input);
  if (bytes.every((b) => b === 0)) throw new ActionError(`${what} must not be the zero address.`);
  return toHex(bytes);
}

/**
 * A person a chair names in a signed action (threat model C16). Strict, because an all-lowercase
 * 0x address carries no checksum and a typo in it would grant a board to an account nobody holds.
 */
function person(input: string, what: string): Address {
  return account(input, what, accountBytesStrict);
}

function envelopeSize(value: Uint): number {
  const n = uint(value, 32, "envelopeSize");
  if (n === 0n || n > BigInt(MAX_ENVELOPE_SIZE)) throw new ActionError(`envelopeSize must be from 1 to ${MAX_ENVELOPE_SIZE} bytes.`);
  return Number(n);
}

function cipherSize(value: Uint): bigint {
  const n = uint(value, 64, "cipherSize");
  if (n === 0n || n > BigInt(MAX_CIPHER_SIZE)) throw new ActionError(`cipherSize must be from 1 to ${MAX_CIPHER_SIZE} bytes.`);
  return n;
}

function mode(value: Mode): number {
  if (value !== Mode.SEAL_CURRENT && value !== Mode.ROTATE) throw new ActionError("mode must be SEAL_CURRENT (0) or ROTATE (1).");
  return value;
}

/**
 * CREATE: `keccak256(abi.encode(address chair, bytes32 boardRef, bytes32 envelopeHash, uint32 envelopeSize))`.
 * boardRef comes from newBoardRef and is the board's identity for all encryption.
 *
 * @param p.chair `qor1...` or exact EIP-55 `0x...`; all-lowercase `0x` is refused (threat model C16).
 * @throws AddressError for a chair in any other form. ActionError for the zero chair, a zero or
 *   malformed boardRef or envelopeHash, or an envelopeSize outside 1 to MAX_ENVELOPE_SIZE.
 */
export function paramsCreate(p: { chair: string; boardRef: Bytes32; envelopeHash: Bytes32; envelopeSize: Uint }): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint32" }],
      [person(p.chair, "chair"), bytes32(p.boardRef, "boardRef"), bytes32(p.envelopeHash, "envelopeHash"), envelopeSize(p.envelopeSize)],
    ),
  );
}

/**
 * ADD: `keccak256(abi.encode(address member, uint8 mode, bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter))`.
 *
 * @param p.member `qor1...` or exact EIP-55 `0x...`; all-lowercase `0x` is refused (threat model C16).
 * @throws AddressError for a member in any other form. ActionError for the zero member, a mode
 *   other than SEAL_CURRENT or ROTATE, a zero or malformed envelopeHash, an envelopeSize outside 1
 *   to MAX_ENVELOPE_SIZE, or an epochAfter outside uint64.
 */
export function paramsAdd(p: { member: string; mode: Mode; envelopeHash: Bytes32; envelopeSize: Uint; epochAfter: Uint }): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "uint8" }, { type: "bytes32" }, { type: "uint32" }, { type: "uint64" }],
      [person(p.member, "member"), mode(p.mode), bytes32(p.envelopeHash, "envelopeHash"), envelopeSize(p.envelopeSize), uint(p.epochAfter, 64, "epochAfter")],
    ),
  );
}

/**
 * REMOVE: `keccak256(abi.encode(address member, bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter))`.
 *
 * @param p.member `qor1...` or exact EIP-55 `0x...`; all-lowercase `0x` is refused (threat model C16).
 * @throws AddressError for a member in any other form. ActionError for the zero member, a zero or
 *   malformed envelopeHash, an envelopeSize outside 1 to MAX_ENVELOPE_SIZE, or an epochAfter
 *   outside uint64.
 */
export function paramsRemove(p: { member: string; envelopeHash: Bytes32; envelopeSize: Uint; epochAfter: Uint }): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "bytes32" }, { type: "uint32" }, { type: "uint64" }],
      [person(p.member, "member"), bytes32(p.envelopeHash, "envelopeHash"), envelopeSize(p.envelopeSize), uint(p.epochAfter, 64, "epochAfter")],
    ),
  );
}

/** ROTATE: `keccak256(abi.encode(bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter))`. */
export function paramsRotate(p: { envelopeHash: Bytes32; envelopeSize: Uint; epochAfter: Uint }): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint32" }, { type: "uint64" }],
      [bytes32(p.envelopeHash, "envelopeHash"), envelopeSize(p.envelopeSize), uint(p.epochAfter, 64, "epochAfter")],
    ),
  );
}

/** POST: `keccak256(abi.encode(bytes32 docRef, bytes32 cipherHash, uint64 cipherSize, uint64 epoch))`. */
export function paramsPost(p: { docRef: Bytes32; cipherHash: Bytes32; cipherSize: Uint; epoch: Uint }): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "uint64" }, { type: "uint64" }],
      [bytes32(p.docRef, "docRef"), bytes32(p.cipherHash, "cipherHash"), cipherSize(p.cipherSize), uint(p.epoch, 64, "epoch")],
    ),
  );
}

/**
 * TRANSFER: `keccak256(abi.encode(address newChair))`.
 *
 * @param p.newChair `qor1...` or exact EIP-55 `0x...`; all-lowercase `0x` is refused (threat model C16).
 * @throws AddressError for a newChair in any other form. ActionError for the zero address.
 */
export function paramsTransfer(p: { newChair: string }): Hex {
  return keccak256(encodeAbiParameters([{ type: "address" }], [person(p.newChair, "newChair")]));
}

/**
 * The typed fields of one board action, keyed by its action code. signBoardAction turns these into
 * the paramsHash and the message itself, so application code never hands over bytes to sign.
 */
export type BoardActionInput =
  | ({ action: typeof Action.CREATE } & Parameters<typeof paramsCreate>[0])
  | ({ action: typeof Action.ADD } & Parameters<typeof paramsAdd>[0])
  | ({ action: typeof Action.REMOVE } & Parameters<typeof paramsRemove>[0])
  | ({ action: typeof Action.ROTATE } & Parameters<typeof paramsRotate>[0])
  | ({ action: typeof Action.POST } & Parameters<typeof paramsPost>[0])
  | ({ action: typeof Action.TRANSFER } & Parameters<typeof paramsTransfer>[0]);

/**
 * The exact 256 bytes a chair signs for one board action (docs/spec/actions.md, threat model C2, C4):
 * `abi.encode(BOARD_TAG, 9800, registry, action, boardId, paramsHash, nonce, deadline)`.
 *
 * @param p.boardId 0 for CREATE, 1 or more for every other action.
 * @param p.nonce CREATE: the chair's creation nonce; otherwise the board's nonce.
 * @param p.deadline Unix seconds, from {@link deadlineFrom}.
 * @throws ActionError for an unknown action, a board id that does not fit the action, a zero
 *   paramsHash or deadline, or a value outside its Solidity type. AddressError for a bad registry.
 */
export function actionMessage(p: { registry: string; action: Action; boardId: Uint; paramsHash: Bytes32; nonce: Uint; deadline: Uint }): Uint8Array {
  if (!Object.values(Action).includes(p.action)) throw new ActionError("Unknown action code.");
  const boardId = uint(p.boardId, 256, "boardId");
  if (p.action === Action.CREATE ? boardId !== 0n : boardId === 0n) {
    throw new ActionError("CREATE signs board id 0; every other action signs an existing board id.");
  }
  const deadline = uint(p.deadline, 64, "deadline");
  if (deadline === 0n) throw new ActionError("deadline must not be zero.");
  const message = hexToBytes(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "uint8" }, { type: "uint256" }, { type: "bytes32" }, { type: "uint64" }, { type: "uint64" }],
      [BOARD_TAG, BigInt(EVM_CHAIN_ID), account(p.registry, "registry"), p.action, boardId, bytes32(p.paramsHash, "paramsHash"), uint(p.nonce, 64, "nonce"), deadline],
    ),
  );
  if (message.length !== ACTION_MESSAGE_LENGTH || message[0] !== 0x20) throw new ActionError("The action message did not come out as 256 bytes starting 0x20.");
  return message;
}

/**
 * The bytes a guest signs before the demo bot admits it (docs/spec/actions.md, threat model C33):
 * `abi.encode(CHALLENGE_TAG, 9800, registry, boardId, guest, botNonce, expiry)`, 224 bytes, first byte 0x00.
 *
 * @throws ActionError for board id 0, a zero botNonce or expiry, or a value outside its type.
 */
export function challengeMessage(p: { registry: string; boardId: Uint; guest: string; botNonce: Bytes32; expiry: Uint }): Uint8Array {
  const boardId = uint(p.boardId, 256, "boardId");
  if (boardId === 0n) throw new ActionError("A challenge names an existing board.");
  const expiry = uint(p.expiry, 64, "expiry");
  if (expiry === 0n) throw new ActionError("expiry must not be zero.");
  const message = hexToBytes(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "uint256" }, { type: "address" }, { type: "bytes32" }, { type: "uint64" }],
      [CHALLENGE_TAG, BigInt(EVM_CHAIN_ID), account(p.registry, "registry"), boardId, account(p.guest, "guest"), bytes32(p.botNonce, "botNonce"), expiry],
    ),
  );
  if (message.length !== CHALLENGE_MESSAGE_LENGTH || message[0] !== 0x00) throw new ActionError("The challenge did not come out as 224 bytes starting 0x00.");
  return message;
}

/**
 * The bytes a guest signs to leave the demo board (docs/spec/actions.md, threat model C47):
 * `abi.encode(LEAVE_TAG, 9800, registry, boardId, guest, botNonce, expiry)`, 224 bytes, first bytes
 * 0xe6 0x6f. The same seven words as the challenge under another tag, so the two can never stand in
 * for each other.
 *
 * @throws ActionError for board id 0, a zero botNonce or expiry, or a value outside its type.
 */
export function leaveMessage(p: { registry: string; boardId: Uint; guest: string; botNonce: Bytes32; expiry: Uint }): Uint8Array {
  const boardId = uint(p.boardId, 256, "boardId");
  if (boardId === 0n) throw new ActionError("A leave request names an existing board.");
  const expiry = uint(p.expiry, 64, "expiry");
  if (expiry === 0n) throw new ActionError("expiry must not be zero.");
  const message = hexToBytes(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "uint256" }, { type: "address" }, { type: "bytes32" }, { type: "uint64" }],
      [LEAVE_TAG, BigInt(EVM_CHAIN_ID), account(p.registry, "registry"), boardId, account(p.guest, "guest"), bytes32(p.botNonce, "botNonce"), expiry],
    ),
  );
  if (message.length !== LEAVE_MESSAGE_LENGTH || message[0] !== 0xe6) throw new ActionError("The leave request did not come out as 224 bytes starting 0xe6.");
  return message;
}

/**
 * A deadline `seconds` after the latest block's timestamp. Taking the time from the chain, not
 * the device clock, keeps a deadline inside the registry's one-hour limit (threat model C2).
 *
 * @throws ActionError when `seconds` is not from 1 to MAX_DEADLINE_AHEAD, or the timestamp is not a uint64.
 */
export function deadlineFrom(latestBlockTimestamp: Uint, seconds: Uint): bigint {
  const now = uint(latestBlockTimestamp, 64, "latestBlockTimestamp");
  const ahead = uint(seconds, 64, "seconds");
  if (ahead === 0n || ahead > BigInt(MAX_DEADLINE_AHEAD)) throw new ActionError(`A deadline is 1 to ${MAX_DEADLINE_AHEAD} seconds ahead of the latest block.`);
  return uint(now + ahead, 64, "deadline");
}
