import { keccak256, stringToBytes, type Hex } from "viem";

/** QoreChain testnet, as the Native lane and QoreSeal name it. */
export const CHAIN_ID = "qorechain-diana";
/** The same testnet as the EVM lane names it (`block.chainid`). */
export const EVM_CHAIN_ID = 9800;
export const EVM_RPC = "https://evm-testnet.qore.host";
export const REST = "https://api-testnet.qore.host";

/** First word of every board action message. Its first byte is 0x20, so no message starts with "q". */
export const BOARD_TAG: Hex = keccak256(stringToBytes("ava.board.v1"));
/** First word of every guest challenge. Its first byte is 0x00. */
export const CHALLENGE_TAG: Hex = keccak256(stringToBytes("ava.challenge.v1"));
/** The first word of a guest's request to leave the demo board. Its own tag, so a signature that admits can never remove (threat model C47). */
export const LEAVE_TAG: Hex = keccak256(stringToBytes("ava.leave.v1"));

/** The action codes the registry accepts, as signed in the message. */
export const Action = {
  CREATE: 1,
  ADD: 2,
  REMOVE: 3,
  ROTATE: 4,
  POST: 5,
  TRANSFER: 6,
} as const;
export type Action = (typeof Action)[keyof typeof Action];

/** How an added member receives the epoch key. */
export const Mode = {
  /** The member joins the current epoch; the envelope is appended to it. */
  SEAL_CURRENT: 0,
  /** The board moves to a new epoch sealed to every member, the new one included. */
  ROTATE: 1,
} as const;
export type Mode = (typeof Mode)[keyof typeof Mode];

export const MAX_MEMBERS = 64;
/** Largest envelope the registry records, in bytes. 64 recipients in mlkem mode need 104,545. */
export const MAX_ENVELOPE_SIZE = 110_000;
/** Largest document ciphertext the registry records: 25 MiB. */
export const MAX_CIPHER_SIZE = 26_214_400;
/** A signed action may not be valid for more than one hour from the latest block. */
export const MAX_DEADLINE_AHEAD = 3600;

export const ML_DSA_87_PUBKEY = 2592;
export const ML_DSA_87_SIG = 4627;
export const ML_KEM_1024_PUBKEY = 1568;
