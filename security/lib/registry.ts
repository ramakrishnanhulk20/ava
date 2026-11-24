import { Action, actionMessage, sealEpochKey, sha256, signAction, type FreshEpochKey, type KemRecipient, type OpenedEpochKey } from "@ava/core";
import { bytesToHex, encodeFunctionData, type Hex, type PublicClient } from "viem";
import { boardRegistryAbi } from "../../packages/server/src/abi/boardRegistry.ts";
import { REGISTRY } from "./guard.ts";
import type { Person } from "./identities.ts";
import { kemOf } from "./people.ts";

export const abi = boardRegistryAbi;
export { Action };

/** An epoch key this suite made for a new epoch, or one it opened back from an envelope the chain recorded. */
export type EpochKey = FreshEpochKey | OpenedEpochKey;

/** Our signed actions live this long after the latest block, so a later probe in the same run still sees a live deadline. */
export const DEADLINE_SECONDS = 1800;
/** A signature of the right length that no key made. */
export const ZERO_SIGNATURE: Hex = `0x${"00".repeat(4627)}`;

export interface Board {
  id: bigint;
  blockNumber: bigint;
  timestamp: bigint;
  chair: Hex;
  boardRef: Hex;
  epoch: bigint;
  nonce: bigint;
  memberCount: number;
  documentCount: number;
  members: readonly Hex[];
}

export interface Grant {
  envelopeHash: Hex;
  envelopeSize: number;
  mode: number;
  member: Hex;
}

/** A board and its members at one block, the latest, so nonce, epoch and members describe one moment (C17). */
export async function boardAt(client: PublicClient, id: bigint): Promise<Board> {
  const block = await client.getBlock({ blockTag: "latest" });
  const at = { address: REGISTRY, abi, blockNumber: block.number } as const;
  const [board, members] = await Promise.all([
    client.readContract({ ...at, functionName: "getBoard", args: [id] }),
    client.readContract({ ...at, functionName: "getMembers", args: [id] }),
  ]);
  return {
    id,
    blockNumber: block.number,
    timestamp: block.timestamp,
    chair: board.chair,
    boardRef: board.boardRef,
    epoch: board.epoch,
    nonce: board.nonce,
    memberCount: board.memberCount,
    documentCount: board.documentCount,
    members,
  };
}

/** The epoch of a board's newest pack, or undefined for a board with none. */
export async function newestPackEpoch(client: PublicClient, board: Board): Promise<bigint | undefined> {
  if (board.documentCount === 0) return undefined;
  const doc = await client.readContract({ address: REGISTRY, abi, functionName: "getDocument", args: [board.id, BigInt(board.documentCount - 1)], blockNumber: board.blockNumber });
  return doc.epoch;
}

export async function grantsOf(client: PublicClient, id: bigint, epoch: bigint): Promise<Grant[]> {
  const list = await client.readContract({ address: REGISTRY, abi, functionName: "getGrants", args: [id, epoch] });
  return list.map((g) => ({ envelopeHash: g.envelopeHash, envelopeSize: g.envelopeSize, mode: g.mode, member: g.member }));
}

export async function createNonceOf(client: PublicClient, chair: Hex): Promise<bigint> {
  return client.readContract({ address: REGISTRY, abi, functionName: "createNonces", args: [chair] });
}

export async function boardCount(client: PublicClient): Promise<bigint> {
  return client.readContract({ address: REGISTRY, abi, functionName: "boardCount" });
}

/** The exact 256 bytes from @ava/core, signed with the person's ML-DSA-87 key. */
export function sign(person: Person, a: { action: Action; boardId: bigint; paramsHash: Hex; nonce: bigint; deadline: bigint }): Hex {
  return bytesToHex(signAction(person.pqc.secretKey, actionMessage({ registry: REGISTRY, ...a })));
}

/** Calldata for each registry write, typed against the deployed ABI. */
export const calldata = {
  createBoard: (a: { chair: Hex; boardRef: Hex; envelopeHash: Hex; envelopeSize: number; deadline: bigint; signature: Hex }): Hex =>
    encodeFunctionData({ abi, functionName: "createBoard", args: [a.chair, a.boardRef, a.envelopeHash, a.envelopeSize, a.deadline, a.signature] }),
  addMember: (a: { boardId: bigint; member: Hex; mode: number; envelopeHash: Hex; envelopeSize: number; epochAfter: bigint; deadline: bigint; signature: Hex }): Hex =>
    encodeFunctionData({ abi, functionName: "addMember", args: [a.boardId, a.member, a.mode, a.envelopeHash, a.envelopeSize, a.epochAfter, a.deadline, a.signature] }),
  removeMember: (a: { boardId: bigint; member: Hex; envelopeHash: Hex; envelopeSize: number; epochAfter: bigint; deadline: bigint; signature: Hex }): Hex =>
    encodeFunctionData({ abi, functionName: "removeMember", args: [a.boardId, a.member, a.envelopeHash, a.envelopeSize, a.epochAfter, a.deadline, a.signature] }),
  rotateEpoch: (a: { boardId: bigint; envelopeHash: Hex; envelopeSize: number; epochAfter: bigint; deadline: bigint; signature: Hex }): Hex =>
    encodeFunctionData({ abi, functionName: "rotateEpoch", args: [a.boardId, a.envelopeHash, a.envelopeSize, a.epochAfter, a.deadline, a.signature] }),
  postDocument: (a: { boardId: bigint; docRef: Hex; cipherHash: Hex; cipherSize: bigint; epoch: bigint; deadline: bigint; signature: Hex }): Hex =>
    encodeFunctionData({ abi, functionName: "postDocument", args: [a.boardId, a.docRef, a.cipherHash, a.cipherSize, a.epoch, a.deadline, a.signature] }),
  transferChair: (a: { boardId: bigint; newChair: Hex; deadline: bigint; signature: Hex }): Hex =>
    encodeFunctionData({ abi, functionName: "transferChair", args: [a.boardId, a.newChair, a.deadline, a.signature] }),
};

/**
 * Our own test boards' envelopes and ciphertexts, kept in memory and found only by the SHA-256 the
 * chain records, the way readers find them in the blob store.
 */
export class LocalBlobs {
  readonly #blobs = new Map<string, Uint8Array>();

  put(bytes: Uint8Array): Hex {
    const hash = bytesToHex(sha256(bytes));
    this.#blobs.set(hash, Uint8Array.from(bytes));
    return hash;
  }

  get(onChainHash: Hex): Uint8Array {
    const bytes = this.#blobs.get(onChainHash.toLowerCase());
    if (bytes === undefined) throw new Error(`No local blob for ${onChainHash}: an earlier step did not keep it.`);
    return Uint8Array.from(bytes);
  }
}

/** Seals an epoch key to each address as the KemRecipient pair qor_getKEMKey returns for that address (C15). */
export async function sealTo(addresses: readonly Hex[], boardRef: Hex, epoch: bigint, epochKey: EpochKey): Promise<Uint8Array> {
  const recipients: KemRecipient[] = [];
  for (const address of addresses) {
    const recipient = await kemOf(address);
    if (recipient === undefined) throw new Error(`${address} publishes no ML-KEM key; refusing to seal to it.`);
    recipients.push(recipient);
  }
  return sealEpochKey({ registry: REGISTRY, boardRef, epoch, epochKey, recipients });
}

/** A fresh non-zero 32-byte value as 0x hex. */
export function random32(): Hex {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
  bytes[0] = bytes[0]! | 0x01;
  return bytesToHex(bytes);
}

export function flipByte(hex: Hex, at: number): Hex {
  const bytes = Buffer.from(hex.slice(2), "hex");
  bytes[at] = bytes[at]! ^ 0x01;
  return `0x${bytes.toString("hex")}`;
}
