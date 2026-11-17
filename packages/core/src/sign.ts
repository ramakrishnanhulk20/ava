import { mldsa87 } from "@qorechain/pqc";
import { hexToBytes } from "viem";
import { ACTION_MESSAGE_LENGTH, ActionError, CHALLENGE_MESSAGE_LENGTH } from "./actions.ts";
import { BOARD_TAG, CHALLENGE_TAG, ML_DSA_87_SIG } from "./constants.ts";

const BOARD_TAG_BYTES = hexToBytes(BOARD_TAG);
const CHALLENGE_TAG_BYTES = hexToBytes(CHALLENGE_TAG);

function startsWith(message: Uint8Array, tag: Uint8Array): boolean {
  for (let i = 0; i < tag.length; i++) if (message[i] !== tag[i]) return false;
  return true;
}

/**
 * Signs one Ava message with pure ML-DSA-87 (FIPS 204), empty context, no prehash: the form the
 * chain's pqcVerify precompile checks (threat model C4).
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
  const signature = mldsa87.sign(mldsaSecretKey, message);
  if (signature.length !== ML_DSA_87_SIG) throw new Error(`ML-DSA-87 gave a ${signature.length}-byte signature, not ${ML_DSA_87_SIG}.`);
  return signature;
}

/** Whether `signature` is a valid pure ML-DSA-87 signature (empty context) over `message`. Never throws. */
export function verifyAction(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  return mldsa87.verify(publicKey, message, signature);
}
