// Writes test-vectors/actions.json: fixed inputs, the paramsHash and the full signed message for
// every board action and the guest challenge. The Solidity tests rebuild each message from the same
// inputs and must match it byte for byte (threat model C4).
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { bytesToHex, type Hex } from "viem";
import {
  actionMessage,
  challengeMessage,
  leaveMessage,
  paramsAdd,
  paramsCreate,
  paramsPost,
  paramsRemove,
  paramsRotate,
  paramsTransfer,
} from "../src/actions.ts";
import { Action, BOARD_TAG, CHALLENGE_TAG, EVM_CHAIN_ID, LEAVE_TAG, Mode } from "../src/constants.ts";

const OUT = resolve(dirname(fileURLToPath(import.meta.url)), "../test-vectors/actions.json");

const REGISTRY = "0x00000000000000000000000000000000000a0a0a";
const BOARD_ID = 7n;
const NONCE = 3n;
const DEADLINE = 1_795_000_000n;

const CHAIR = "0x1111111111111111111111111111111111111111";
const MEMBER = "0x2222222222222222222222222222222222222222";
const NEW_CHAIR = "0x3333333333333333333333333333333333333333";
const GUEST = "0x4444444444444444444444444444444444444444";
const BOARD_REF: Hex = `0x${"a1".repeat(32)}`;
const ENVELOPE_HASH: Hex = `0x${"e1".repeat(32)}`;
const DOC_REF: Hex = `0x${"d1".repeat(32)}`;
const CIPHER_HASH: Hex = `0x${"c1".repeat(32)}`;
const BOT_NONCE: Hex = `0x${"b1".repeat(32)}`;
// Sizes of real mlkem envelopes carrying the 41-byte epoch key payload: 97 + 1,632 per recipient.
const ONE_RECIPIENT = 1729;
const TWO_RECIPIENTS = 3361;

type Params = Record<string, string | number>;

function vector(name: keyof typeof Action, boardId: bigint, paramsTypes: string, params: Params, paramsHash: Hex) {
  const message = actionMessage({ registry: REGISTRY, action: Action[name], boardId, paramsHash, nonce: NONCE, deadline: DEADLINE });
  return {
    name,
    action: Action[name],
    boardId: boardId.toString(),
    nonce: NONCE.toString(),
    deadline: DEADLINE.toString(),
    paramsTypes,
    params,
    paramsHash,
    message: bytesToHex(message),
  };
}

const vectors = [
  vector(
    "CREATE",
    0n,
    "address chair, bytes32 boardRef, bytes32 envelopeHash, uint32 envelopeSize",
    { chair: CHAIR, boardRef: BOARD_REF, envelopeHash: ENVELOPE_HASH, envelopeSize: ONE_RECIPIENT },
    paramsCreate({ chair: CHAIR, boardRef: BOARD_REF, envelopeHash: ENVELOPE_HASH, envelopeSize: ONE_RECIPIENT }),
  ),
  vector(
    "ADD",
    BOARD_ID,
    "address member, uint8 mode, bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter",
    { member: MEMBER, mode: Mode.ROTATE, envelopeHash: ENVELOPE_HASH, envelopeSize: TWO_RECIPIENTS, epochAfter: "5" },
    paramsAdd({ member: MEMBER, mode: Mode.ROTATE, envelopeHash: ENVELOPE_HASH, envelopeSize: TWO_RECIPIENTS, epochAfter: 5n }),
  ),
  vector(
    "REMOVE",
    BOARD_ID,
    "address member, bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter",
    { member: MEMBER, envelopeHash: ENVELOPE_HASH, envelopeSize: ONE_RECIPIENT, epochAfter: "5" },
    paramsRemove({ member: MEMBER, envelopeHash: ENVELOPE_HASH, envelopeSize: ONE_RECIPIENT, epochAfter: 5n }),
  ),
  vector(
    "ROTATE",
    BOARD_ID,
    "bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter",
    { envelopeHash: ENVELOPE_HASH, envelopeSize: TWO_RECIPIENTS, epochAfter: "5" },
    paramsRotate({ envelopeHash: ENVELOPE_HASH, envelopeSize: TWO_RECIPIENTS, epochAfter: 5n }),
  ),
  vector(
    "POST",
    BOARD_ID,
    "bytes32 docRef, bytes32 cipherHash, uint64 cipherSize, uint64 epoch",
    { docRef: DOC_REF, cipherHash: CIPHER_HASH, cipherSize: "1048604", epoch: "4" },
    paramsPost({ docRef: DOC_REF, cipherHash: CIPHER_HASH, cipherSize: 1_048_604n, epoch: 4n }),
  ),
  vector("TRANSFER", BOARD_ID, "address newChair", { newChair: NEW_CHAIR }, paramsTransfer({ newChair: NEW_CHAIR })),
];

const challenge = {
  registry: REGISTRY,
  boardId: BOARD_ID.toString(),
  guest: GUEST,
  botNonce: BOT_NONCE,
  expiry: DEADLINE.toString(),
  message: bytesToHex(challengeMessage({ registry: REGISTRY, boardId: BOARD_ID, guest: GUEST, botNonce: BOT_NONCE, expiry: DEADLINE })),
};

// The leave request has the challenge's shape under its own tag, so one check covers both and proves the tags differ.
const leave = {
  registry: REGISTRY,
  boardId: BOARD_ID.toString(),
  guest: GUEST,
  botNonce: BOT_NONCE,
  expiry: DEADLINE.toString(),
  message: bytesToHex(leaveMessage({ registry: REGISTRY, boardId: BOARD_ID, guest: GUEST, botNonce: BOT_NONCE, expiry: DEADLINE })),
};

const file = {
  spec: "docs/spec/actions.md",
  note: "uint64 and uint256 values are decimal strings. message = abi.encode(domainTag, chainId, registry, action, boardId, paramsHash, nonce, deadline).",
  chainId: EVM_CHAIN_ID,
  registry: REGISTRY,
  domainTag: BOARD_TAG,
  challengeTag: CHALLENGE_TAG,
  leaveTag: LEAVE_TAG,
  vectors,
  challenge,
  leave,
};

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, `${JSON.stringify(file, null, 2)}\n`, "utf8");
console.log(`Wrote ${vectors.length} action vectors, the challenge and the leave request to ${OUT}`);
for (const v of vectors) console.log(`  ${v.name.padEnd(8)} paramsHash ${v.paramsHash}  message ${(v.message.length - 2) / 2} bytes`);
console.log(`  CHALLENGE message ${(challenge.message.length - 2) / 2} bytes`);
console.log(`  LEAVE     message ${(leave.message.length - 2) / 2} bytes`);
