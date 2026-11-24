import { Mode, decryptDocument, openEpochKey, sameAccount, type OpenedEpochKey } from "@ava/core";
import type { Hex } from "viem";
import { REGISTRY, client } from "../chain";
import type { GuestAccount } from "./identity";
import { pause, startDeadline, throwIfStopped } from "./time";

/** The reads the app makes, copied from packages/server/src/abi/boardRegistry.ts (generated from the deployed BoardRegistry). */
const REGISTRY_ABI = [
  {
    type: "function",
    name: "createNonces",
    stateMutability: "view",
    inputs: [{ name: "chair", type: "address" }],
    outputs: [{ name: "", type: "uint64" }],
  },
  {
    type: "function",
    name: "getBoard",
    stateMutability: "view",
    inputs: [{ name: "boardId", type: "uint256" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "chair", type: "address" },
          { name: "boardRef", type: "bytes32" },
          { name: "epoch", type: "uint64" },
          { name: "nonce", type: "uint64" },
          { name: "memberCount", type: "uint32" },
          { name: "documentCount", type: "uint32" },
        ],
      },
    ],
  },
  {
    type: "function",
    name: "getMembers",
    stateMutability: "view",
    inputs: [{ name: "boardId", type: "uint256" }],
    outputs: [{ name: "", type: "address[]" }],
  },
  {
    type: "function",
    name: "getGrants",
    stateMutability: "view",
    inputs: [
      { name: "boardId", type: "uint256" },
      { name: "epoch", type: "uint64" },
    ],
    outputs: [
      {
        name: "",
        type: "tuple[]",
        components: [
          { name: "envelopeHash", type: "bytes32" },
          { name: "envelopeSize", type: "uint32" },
          { name: "mode", type: "uint8" },
          { name: "member", type: "address" },
        ],
      },
    ],
  },
  {
    type: "function",
    name: "getDocument",
    stateMutability: "view",
    inputs: [
      { name: "boardId", type: "uint256" },
      { name: "docId", type: "uint256" },
    ],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "docRef", type: "bytes32" },
          { name: "cipherHash", type: "bytes32" },
          { name: "cipherSize", type: "uint64" },
          { name: "epoch", type: "uint64" },
          { name: "postedAt", type: "uint64" },
        ],
      },
    ],
  },
] as const;

/** One ROTATE grant starts every epoch, plus one per guest admitted in it; this bounds the envelopes tried. */
const MAX_ENVELOPES_TRIED = 4;
const PACK_POLL_MS = 5_000;
const PACK_WAIT_MS = 180_000;

export interface Grant {
  envelopeHash: Hex;
  envelopeSize: number;
  mode: number;
  member: Hex;
}

export interface LatestDocument {
  docId: bigint;
  docRef: Hex;
  cipherHash: Hex;
  cipherSize: bigint;
  epoch: bigint;
}

/** The board as the registry held it at one block, every read pinned to that block's number. */
export interface BoardSnapshot {
  boardId: bigint;
  blockNumber: bigint;
  /** That block's timestamp, the only clock a signature's deadline is taken from. */
  blockTimestamp: bigint;
  chair: Hex;
  boardRef: Hex;
  epoch: bigint;
  /** The nonce the chair's next signature must cover. */
  nonce: bigint;
  members: readonly Hex[];
  grants: readonly Grant[];
  latest: LatestDocument | undefined;
}

export async function readBoard(boardId: bigint): Promise<BoardSnapshot> {
  const block = await client.getBlock({ blockTag: "latest" });
  const at = { address: REGISTRY, abi: REGISTRY_ABI, blockNumber: block.number } as const;
  const [board, members] = await Promise.all([
    client.readContract({ ...at, functionName: "getBoard", args: [boardId] }),
    client.readContract({ ...at, functionName: "getMembers", args: [boardId] }),
  ]);
  const docId = board.documentCount > 0 ? BigInt(board.documentCount - 1) : undefined;
  const [grants, doc] = await Promise.all([
    client.readContract({ ...at, functionName: "getGrants", args: [boardId, board.epoch] }),
    docId === undefined ? undefined : client.readContract({ ...at, functionName: "getDocument", args: [boardId, docId] }),
  ]);
  return {
    boardId,
    blockNumber: block.number,
    blockTimestamp: block.timestamp,
    chair: board.chair,
    boardRef: board.boardRef,
    epoch: board.epoch,
    nonce: board.nonce,
    members,
    grants: grants.map((g) => ({ envelopeHash: g.envelopeHash, envelopeSize: g.envelopeSize, mode: g.mode, member: g.member })),
    latest: doc === undefined || docId === undefined ? undefined : { docId, docRef: doc.docRef, cipherHash: doc.cipherHash, cipherSize: doc.cipherSize, epoch: doc.epoch },
  };
}

/** The nonce a chair's next createBoard signature must cover, with the latest block's timestamp read beside it. */
export async function readCreateNonce(chair: Hex): Promise<{ nonce: bigint; blockTimestamp: bigint }> {
  const block = await client.getBlock({ blockTag: "latest" });
  const nonce = await client.readContract({ address: REGISTRY, abi: REGISTRY_ABI, functionName: "createNonces", args: [chair], blockNumber: block.number });
  return { nonce, blockTimestamp: block.timestamp };
}

/** One posted pack's record: what the registry holds for it, never its content. */
export async function readDocument(boardId: bigint, docId: bigint): Promise<LatestDocument> {
  const doc = await client.readContract({ address: REGISTRY, abi: REGISTRY_ABI, functionName: "getDocument", args: [boardId, docId] });
  return { docId, docRef: doc.docRef, cipherHash: doc.cipherHash, cipherSize: doc.cipherSize, epoch: doc.epoch };
}

/** The grants the registry holds for one epoch of a board, at the latest block: the current epoch's, or an earlier one's. */
export async function readGrants(boardId: bigint, epoch: bigint): Promise<Grant[]> {
  const grants = await client.readContract({ address: REGISTRY, abi: REGISTRY_ABI, functionName: "getGrants", args: [boardId, epoch] });
  return grants.map((g) => ({ envelopeHash: g.envelopeHash, envelopeSize: g.envelopeSize, mode: g.mode, member: g.member }));
}

/**
 * The blob store's public origin, as the server's BLOB_ORIGIN, and only when it is exactly an https
 * origin in the URL parser's own form, so every URL built from it keeps that origin.
 *
 * @throws Error when NEXT_PUBLIC_BLOB_ORIGIN is unset or is not such an origin.
 */
export function blobOrigin(): string {
  const value = process.env.NEXT_PUBLIC_BLOB_ORIGIN ?? "";
  let url: URL | undefined;
  try {
    url = new URL(value);
  } catch {
    url = undefined;
  }
  if (url === undefined || url.protocol !== "https:" || url.origin !== value) throw new Error("NEXT_PUBLIC_BLOB_ORIGIN is not set to the blob store's https origin.");
  return value;
}

/** Where a blob with this on-chain hash is stored: always built from the hash and the origin, never from an answer (C30). */
export function blobUrl(kind: "envelope" | "document", hash: Hex): URL {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error("A blob hash is 32 bytes of hex.");
  const origin = blobOrigin();
  const url = new URL(`${origin}/${kind}/${hash.slice(2).toLowerCase()}`);
  if (url.origin !== origin) throw new Error("A blob URL left the blob store's origin.");
  return url;
}

/**
 * Downloads a public blob without credentials, refusing redirects and stopping the moment more than
 * the on-chain `size` arrives; the caller's open or decrypt checks the exact size and SHA-256.
 *
 * @throws Error when the blob is missing, the store answers anything but 200, or it is over `size`.
 */
export async function readBlob(url: URL, size: number, signal: AbortSignal): Promise<Uint8Array> {
  const response = await fetch(url, { credentials: "omit", redirect: "error", signal });
  if (response.status === 404) throw new Error("The blob the registry recorded is not in the blob store.");
  if (response.status !== 200 || response.body === null) throw new Error(`The blob store answered ${response.status}.`);
  const reader = response.body.getReader();
  const out = new Uint8Array(size);
  let filled = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (filled + value.length > size) {
      await reader.cancel().catch(() => undefined);
      throw new Error("The blob is larger than the size the registry recorded.");
    }
    out.set(value, filled);
    filled += value.length;
  }
  return out.subarray(0, filled);
}

/** Whether QoreSeal refused the keys because the envelope holds no entry for them, and for no other reason. */
export function isNotRecipient(error: unknown): boolean {
  return error instanceof Error && (error as { code?: unknown }).code === "NOT_A_RECIPIENT";
}

/**
 * Opens the snapshot's epoch key with the guest's own seal keys. The envelopes tried are the ones
 * the guest can hold: a grant naming the guest first (the bot's SEAL_CURRENT on join), then ROTATE
 * grants, sealed to every member at the time. Each is downloaded by its on-chain hash, and
 * openEpochKey refuses it unless its size and SHA-256 equal the registry's record.
 *
 * @returns The opened key and the grant that held it.
 * @throws Error when no grant opens for this guest, or an envelope is not the recorded bytes.
 */
export async function openGuestEpochKey(snapshot: BoardSnapshot, guest: GuestAccount, signal: AbortSignal): Promise<{ epochKey: OpenedEpochKey; grant: Grant }> {
  const named = snapshot.grants.filter((g) => sameAccount(g.member, guest.identity.evm));
  const rotations = snapshot.grants.filter((g) => g.mode === Mode.ROTATE);
  const candidates = [...named, ...rotations].slice(0, MAX_ENVELOPES_TRIED);
  for (const grant of candidates) {
    const envelope = await readBlob(blobUrl("envelope", grant.envelopeHash), grant.envelopeSize, signal);
    try {
      const epochKey = openEpochKey({
        registry: REGISTRY,
        boardRef: snapshot.boardRef,
        epoch: snapshot.epoch,
        envelope,
        expectedHash: grant.envelopeHash,
        expectedSize: grant.envelopeSize,
        sealKeys: guest.identity.seal,
      });
      return { epochKey, grant };
    } catch (error) {
      if (isNotRecipient(error)) continue;
      throw error;
    }
  }
  throw new Error(`No envelope of epoch ${snapshot.epoch} is sealed to this guest.`);
}

export interface Pack {
  docId: bigint;
  epoch: bigint;
  size: bigint;
  text: string;
}

/**
 * Waits, reading the board every 5 s for up to three minutes, until its latest document is in the
 * board's current epoch, then fetches that ciphertext by its on-chain hash and decrypts it on this
 * device. The bot posts the pack after a join, and a pressure pass can move the epoch first, so the
 * epoch key is opened again whenever the epoch read is not the one already open.
 *
 * @param opened The key opened right after the join, for its epoch.
 * @param onEpoch Told each time a later epoch's key is opened.
 * @throws Error when no pack of the current epoch shows within three minutes, or one fails to open.
 */
export async function waitAndOpenPack(
  boardId: bigint,
  guest: GuestAccount,
  opened: { epoch: bigint; epochKey: OpenedEpochKey },
  signal: AbortSignal,
  onEpoch: (epoch: bigint) => void,
): Promise<Pack> {
  const deadline = startDeadline(PACK_WAIT_MS);
  let current = opened;
  try {
    for (;;) {
      throwIfStopped(signal);
      let snapshot: BoardSnapshot | undefined;
      try {
        snapshot = await readBoard(boardId);
      } catch {
        // One failed read is the network; the deadline decides when to give up.
        snapshot = undefined;
      }
      const doc = snapshot?.latest;
      if (snapshot !== undefined && doc !== undefined && doc.epoch === snapshot.epoch) {
        if (current.epoch !== snapshot.epoch) {
          const next = await openGuestEpochKey(snapshot, guest, signal);
          current.epochKey.fill(0);
          current = { epoch: snapshot.epoch, epochKey: next.epochKey };
          onEpoch(snapshot.epoch);
        }
        const ciphertext = await readBlob(blobUrl("document", doc.cipherHash), Number(doc.cipherSize), signal);
        const plain = await decryptDocument({
          epochKey: current.epochKey,
          registry: REGISTRY,
          boardRef: snapshot.boardRef,
          epoch: doc.epoch,
          docRef: doc.docRef,
          ciphertext,
          expectedHash: doc.cipherHash,
          expectedSize: doc.cipherSize,
        });
        return { docId: doc.docId, epoch: doc.epoch, size: doc.cipherSize, text: new TextDecoder("utf-8", { fatal: true }).decode(plain) };
      }
      if (performance.now() + PACK_POLL_MS > deadline.endsAt) throw new Error("No pack of the board's current epoch showed within three minutes.");
      await pause(PACK_POLL_MS, signal);
    }
  } finally {
    current.epochKey.fill(0);
  }
}
