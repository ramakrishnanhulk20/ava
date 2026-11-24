import { mldsa87 } from "@qorechain/pqc";
import { hexToBytes, type Hex } from "viem";
import {
  ACTION_MESSAGE_LENGTH,
  ActionError,
  CHALLENGE_MESSAGE_LENGTH,
  actionMessage,
  challengeMessage,
  leaveMessage,
  paramsAdd,
  paramsCreate,
  paramsPost,
  paramsRemove,
  paramsRotate,
  paramsTransfer,
  type BoardActionInput,
} from "./actions.ts";
import { Action, BOARD_TAG, CHALLENGE_TAG, MAX_DEADLINE_AHEAD, ML_DSA_87_SIG } from "./constants.ts";
import { toUint, type Bytes32, type Uint } from "./values.ts";

const BOARD_TAG_BYTES = hexToBytes(BOARD_TAG);
const CHALLENGE_TAG_BYTES = hexToBytes(CHALLENGE_TAG);

function startsWith(message: Uint8Array, tag: Uint8Array): boolean {
  for (let i = 0; i < tag.length; i++) if (message[i] !== tag[i]) return false;
  return true;
}

function mldsaSign(mldsaSecretKey: Uint8Array, message: Uint8Array): Uint8Array {
  const signature = mldsa87.sign(mldsaSecretKey, message);
  if (signature.length !== ML_DSA_87_SIG) throw new Error(`ML-DSA-87 gave a ${signature.length}-byte signature, not ${ML_DSA_87_SIG}.`);
  return signature;
}

/**
 * The registry accepts a deadline up to block.timestamp itself, but a transaction signed at the
 * latest block lands in a later one, so a deadline equal to it is refused here.
 */
function requireWindow(until: Uint, latestBlockTimestamp: Uint, what: string): void {
  const latest = toUint(latestBlockTimestamp, 64);
  if (latest === undefined) throw new ActionError("latestBlockTimestamp must be an unsigned 64-bit integer.");
  const end = toUint(until, 64);
  if (end === undefined) throw new ActionError(`${what} must be an unsigned 64-bit integer.`);
  if (end <= latest || end > latest + BigInt(MAX_DEADLINE_AHEAD)) {
    throw new ActionError(`${what} must be 1 to ${MAX_DEADLINE_AHEAD} seconds after the latest block.`);
  }
}

function paramsHashOf(p: BoardActionInput): Hex {
  switch (p.action) {
    case Action.CREATE:
      return paramsCreate(p);
    case Action.ADD:
      return paramsAdd(p);
    case Action.REMOVE:
      return paramsRemove(p);
    case Action.ROTATE:
      return paramsRotate(p);
    case Action.POST:
      return paramsPost(p);
    case Action.TRANSFER:
      return paramsTransfer(p);
    default:
      throw new ActionError("Unknown action code.");
  }
}

/**
 * Signs one Ava message with pure ML-DSA-87 (FIPS 204), empty context, no prehash: the form the
 * chain's pqcVerify precompile checks (threat model C4).
 *
 * For scripts and the attack suite. Application code signs only through signBoardAction and
 * signChallenge, which rebuild the bytes from typed fields (threat model C33 mirror): this function
 * signs any bytes that merely look like an Ava message, so a server that handed it a ROTATE for
 * another board would get that signed.
 *
 * Signs only bytes that are an Ava message: 256 bytes under BOARD_TAG (from actionMessage) or 224
 * bytes under CHALLENGE_TAG (from challengeMessage). The account key also signs chain transactions,
 * so this refuses anything else rather than sign bytes that could mean something to the chain.
 *
 * @throws ActionError when the message is not one of the two Ava forms. Error when the secret key
 *   is not a 4,896-byte ML-DSA-87 key.
 */
export function signAction(mldsaSecretKey: Uint8Array, message: Uint8Array): Uint8Array {
  const isAction = message.length === ACTION_MESSAGE_LENGTH && startsWith(message, BOARD_TAG_BYTES);
  const isChallenge = message.length === CHALLENGE_MESSAGE_LENGTH && startsWith(message, CHALLENGE_TAG_BYTES);
  if (!isAction && !isChallenge) throw new ActionError("Refusing to sign bytes that are not an Ava action or challenge message.");
  return mldsaSign(mldsaSecretKey, message);
}

/**
 * Signs one board action from its typed fields (threat model C2, C33 mirror). Builds the paramsHash
 * with the params function of `p.action` and the 256-byte message with actionMessage, then signs
 * those bytes. Nothing the caller passes is signed as bytes: a `paramsHash` or `message` field on
 * `p` is ignored.
 *
 * Covers a deadline in the past or more than MAX_DEADLINE_AHEAD (one hour) past the latest block, so
 * no signature from here outlives that hour. Does not cover a wrong `latestBlockTimestamp`: read it
 * from the chain's latest block, never from the device clock or a request.
 *
 * @param p.boardId 0 for CREATE, 1 or more for every other action.
 * @param p.nonce CREATE: the chair's creation nonce; otherwise the board's nonce.
 * @param p.deadline Unix seconds, more than `latestBlockTimestamp` and at most MAX_DEADLINE_AHEAD past it.
 * @param p.latestBlockTimestamp The timestamp of the chain's latest block, in Unix seconds.
 * @returns The signed message, its paramsHash, and the 4,627-byte signature.
 * @throws ActionError for a deadline outside that window, an unknown action, a board id that does
 *   not fit the action, or any field the params function or actionMessage refuses. AddressError
 *   for an account field that is not qor1 or exact EIP-55, or a bad registry. Error when the secret
 *   key is not a 4,896-byte ML-DSA-87 key.
 */
export function signBoardAction(
  mldsaSecretKey: Uint8Array,
  p: BoardActionInput & { registry: string; boardId: Uint; nonce: Uint; deadline: Uint; latestBlockTimestamp: Uint },
): { message: Uint8Array; paramsHash: Hex; signature: Uint8Array } {
  requireWindow(p.deadline, p.latestBlockTimestamp, "deadline");
  const paramsHash = paramsHashOf(p);
  const message = actionMessage({ registry: p.registry, action: p.action, boardId: p.boardId, paramsHash, nonce: p.nonce, deadline: p.deadline });
  return { message, paramsHash, signature: mldsaSign(mldsaSecretKey, message) };
}

/**
 * Signs a demo-board guest challenge from its typed fields (threat model C2, C33 mirror). Builds the
 * 224 bytes with challengeMessage and signs those; a `message` field on `p` is ignored, so a
 * challenge endpoint can only choose the values that go into a challenge, never the bytes signed.
 *
 * Covers an expiry in the past or more than MAX_DEADLINE_AHEAD (one hour) past the latest block.
 * Does not cover a wrong `latestBlockTimestamp` (read it from the chain), and does not check that
 * `boardId` is the demo board the guest meant to join: show the guest what they are signing.
 *
 * @param p.expiry Unix seconds, more than `latestBlockTimestamp` and at most MAX_DEADLINE_AHEAD past it.
 * @param p.latestBlockTimestamp The timestamp of the chain's latest block, in Unix seconds.
 * @returns The signed challenge and the 4,627-byte signature.
 * @throws ActionError for an expiry outside that window, board id 0, a zero botNonce, or a value
 *   outside its type. AddressError for a bad registry or guest. Error when the secret key is not a
 *   4,896-byte ML-DSA-87 key.
 */
export function signChallenge(
  mldsaSecretKey: Uint8Array,
  p: { registry: string; boardId: Uint; guest: string; botNonce: Bytes32; expiry: Uint; latestBlockTimestamp: Uint },
): { message: Uint8Array; signature: Uint8Array } {
  requireWindow(p.expiry, p.latestBlockTimestamp, "expiry");
  const message = challengeMessage({ registry: p.registry, boardId: p.boardId, guest: p.guest, botNonce: p.botNonce, expiry: p.expiry });
  return { message, signature: mldsaSign(mldsaSecretKey, message) };
}

/**
 * Signs a guest's request to leave the demo board from its typed fields (threat model C2, C45, C47).
 * Builds the 224 bytes with leaveMessage and signs those; a `message` field on `p` is ignored. This
 * is the only signer for a leave: signAction refuses those bytes, so a page that signs raw bytes a
 * server supplied can never be made to sign a removal.
 *
 * Covers an expiry in the past or more than MAX_DEADLINE_AHEAD (one hour) past the latest block.
 * Does not cover a wrong `latestBlockTimestamp` (read it from the chain), and does not check that
 * the guest meant to leave: sign only after a control that says what it does.
 *
 * @param p.expiry Unix seconds, more than `latestBlockTimestamp` and at most MAX_DEADLINE_AHEAD past it.
 * @param p.latestBlockTimestamp The timestamp of the chain's latest block, in Unix seconds.
 * @returns The signed leave request and the 4,627-byte signature.
 * @throws ActionError for an expiry outside that window, board id 0, a zero botNonce, or a value
 *   outside its type. AddressError for a bad registry or guest. Error when the secret key is not a
 *   4,896-byte ML-DSA-87 key.
 */
export function signLeave(
  mldsaSecretKey: Uint8Array,
  p: { registry: string; boardId: Uint; guest: string; botNonce: Bytes32; expiry: Uint; latestBlockTimestamp: Uint },
): { message: Uint8Array; signature: Uint8Array } {
  requireWindow(p.expiry, p.latestBlockTimestamp, "expiry");
  const message = leaveMessage({ registry: p.registry, boardId: p.boardId, guest: p.guest, botNonce: p.botNonce, expiry: p.expiry });
  return { message, signature: mldsaSign(mldsaSecretKey, message) };
}

/** Whether `signature` is a valid pure ML-DSA-87 signature (empty context) over `message`. Never throws. */
export function verifyAction(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  return mldsa87.verify(publicKey, message, signature);
}
