import { assertHash, decryptDocument, openEpochKey, sameAccount } from "@ava/core";
import type { Hex } from "viem";
import { REGISTRY } from "../chain";
import { blobUrl, isNotRecipient, openGuestEpochKey, readBlob, readBoard, readGrants, type BoardSnapshot, type Grant } from "./board";
import type { GuestAccount } from "./identity";
import { Stopped, pause, startDeadline, throwIfStopped } from "./time";

const POLL_MS = 5_000;
/** The bot posts the next pack once the board's lock is free; a pass freeing seats can hold it a few minutes. */
const WAIT_MS = 240_000;
/** A board holds at most 40 members: one envelope for all of them, and one more for each guest admitted in the epoch. */
const MAX_ENVELOPES = 48;
/** Nine rows of seventeen bytes: what the stage prints of the pack as stored. */
export const SHOWN_ROWS = 9;
export const SHOWN_BYTES_PER_ROW = 17;

/** Something the page said would stay shut opened with the keys in this browser. Shown as it is, never as a lock. */
export class PackOpened extends Error {
  constructor(message: string) {
    super(`${message} This should not happen: the pack is not shut to this browser.`);
    this.name = "PackOpened";
  }
}

/** The board's next pack, found on chain with its stored bytes checked against the registry's size and hash. */
export interface FoundPack {
  docId: bigint;
  epoch: bigint;
  size: bigint;
  /** The first bytes of the pack as the blob store holds them. */
  firstBytes: Uint8Array;
}

/** A pack this browser tried to open and could not, with what it tried. */
export interface ShutPack {
  docId: bigint;
  epoch: bigint;
  size: bigint;
  cipherHash: Hex;
  /** The first bytes of the pack as the blob store holds them, checked against the registry's hash. */
  firstBytes: Uint8Array;
  /** How many envelopes of the pack's epoch were tried with this guest's keys; every one refused them. */
  envelopesTried: number;
  /** The earlier epoch whose key was tried on the pack and refused; absent when that key could not be opened again to try. */
  oldEpoch?: bigint;
  /** The board as it stood when the envelopes were read. */
  members: number;
  blockNumber: bigint;
}

/**
 * Tries the guest's keys on every envelope of an epoch, in order, and counts the refusals (threat
 * model C38, C39). The only outcome that counts as shut is every envelope refusing the keys as not
 * a recipient. An envelope that cannot be read, or that fails for any other reason, ends the check
 * with that error, so a network failure is never shown as a lock.
 *
 * @returns How many envelopes refused the keys: all of them.
 * @throws PackOpened the moment an envelope opens. Error for an epoch with no envelope, or as `load` or `open` threw.
 */
export async function tryEveryEnvelope<G extends Pick<Grant, "envelopeHash">>(grants: readonly G[], load: (grant: G) => Promise<Uint8Array>, open: (grant: G, envelope: Uint8Array) => unknown): Promise<number> {
  if (grants.length === 0) throw new Error("The epoch has no envelope on chain to try.");
  let refused = 0;
  for (const grant of grants) {
    const envelope = await load(grant);
    let opened: unknown;
    try {
      opened = open(grant, envelope);
    } catch (error) {
      if (!isNotRecipient(error)) throw error;
      refused += 1;
      continue;
    }
    if (opened instanceof Uint8Array) opened.fill(0);
    throw new PackOpened(`The envelope ${grant.envelopeHash.slice(0, 10)}... opened with the keys in this browser.`);
  }
  return refused;
}

/**
 * Tries a key from an earlier epoch on a pack whose size and hash are already checked.
 *
 * @returns "refused" when the pack fails to authenticate under it, "unknown" when the attempt failed for another reason.
 * @throws PackOpened if the earlier key opens the pack.
 */
export async function tryOldKey(decrypt: () => Promise<Uint8Array>): Promise<"refused" | "unknown"> {
  try {
    await decrypt();
  } catch (error) {
    return error instanceof Error && error.name === "DocumentError" ? "refused" : "unknown";
  }
  throw new PackOpened("A key from before the removal opened the new pack.");
}

/** Bytes as rows of lowercase hex pairs, `perRow` bytes to a row, for as many rows as the bytes fill. */
export function hexRowsOf(bytes: Uint8Array, rows: number, perRow: number): string[] {
  const out: string[] = [];
  for (let r = 0; r < rows && r * perRow < bytes.length; r += 1) {
    out.push(Array.from(bytes.subarray(r * perRow, (r + 1) * perRow), (b) => b.toString(16).padStart(2, "0")).join(" "));
  }
  return out;
}

/** The earlier epoch's key, opened again from its own envelope, tried on the new pack. Claims nothing when that key cannot be opened again. */
async function refusedByOldKey(snapshot: BoardSnapshot, doc: NonNullable<BoardSnapshot["latest"]>, ciphertext: Uint8Array, heldEpoch: bigint, guest: GuestAccount, signal: AbortSignal): Promise<boolean> {
  try {
    const grants = await readGrants(snapshot.boardId, heldEpoch);
    const old = await openGuestEpochKey({ ...snapshot, epoch: heldEpoch, grants }, guest, signal);
    try {
      const verdict = await tryOldKey(() =>
        decryptDocument({ epochKey: old.epochKey, registry: REGISTRY, boardRef: snapshot.boardRef, epoch: doc.epoch, docRef: doc.docRef, ciphertext, expectedHash: doc.cipherHash, expectedSize: doc.cipherSize }),
      );
      return verdict === "refused";
    } finally {
      old.epochKey.fill(0);
    }
  } catch (error) {
    if (error instanceof PackOpened || error instanceof Stopped) throw error;
    return false;
  }
}

/**
 * Waits, reading the board every 5 s for up to four minutes, until the board's latest pack is in
 * its current epoch and that epoch is `fromEpoch` or later, then tries to open it as this guest
 * would. The pack's stored bytes are fetched by their on-chain hash and checked against the
 * registry's size and SHA-256, every envelope of the epoch is downloaded and tried with the guest's
 * own seal keys (tryEveryEnvelope), and the key of `heldEpoch`, when the guest held one, is opened
 * again and tried on the pack. Nothing here is taken from our own server.
 *
 * @param p.fromEpoch The epoch the removal moved the board to, or the board's epoch when the removal was not seen.
 * @param p.heldEpoch The last epoch whose key this guest opened, if any.
 * @param onPack Told once the pack is found and its stored bytes are checked.
 * @returns What was tried and refused.
 * @throws PackOpened if anything opens. Error when the account is on the board, no such pack shows
 *   in time, or a read fails so that no verdict can be given.
 */
export async function waitForShutPack(
  boardId: bigint,
  guest: GuestAccount,
  p: { fromEpoch: bigint; heldEpoch?: bigint },
  signal: AbortSignal,
  onPack: (found: FoundPack) => void,
): Promise<ShutPack> {
  const deadline = startDeadline(WAIT_MS);
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
    if (snapshot !== undefined && doc !== undefined && doc.epoch === snapshot.epoch && snapshot.epoch >= p.fromEpoch) {
      if (snapshot.members.some((m) => sameAccount(m, guest.identity.evm))) throw new Error("This account is on the board, so its packs are not shut to it.");
      if (snapshot.grants.length > MAX_ENVELOPES) throw new Error(`Epoch ${snapshot.epoch} has ${snapshot.grants.length} envelopes, more than this page tries.`);
      const ciphertext = await readBlob(blobUrl("document", doc.cipherHash), Number(doc.cipherSize), signal);
      if (BigInt(ciphertext.length) !== doc.cipherSize) throw new Error("The stored pack is not the size the registry recorded.");
      assertHash(ciphertext, doc.cipherHash);
      const firstBytes = ciphertext.slice(0, SHOWN_ROWS * SHOWN_BYTES_PER_ROW);
      onPack({ docId: doc.docId, epoch: doc.epoch, size: doc.cipherSize, firstBytes });

      const at = snapshot;
      const envelopesTried = await tryEveryEnvelope(
        at.grants,
        (grant) => readBlob(blobUrl("envelope", grant.envelopeHash), grant.envelopeSize, signal),
        (grant, envelope) => openEpochKey({ registry: REGISTRY, boardRef: at.boardRef, epoch: at.epoch, envelope, expectedHash: grant.envelopeHash, expectedSize: grant.envelopeSize, sealKeys: guest.identity.seal }),
      );
      const oldRefused = p.heldEpoch !== undefined && p.heldEpoch < at.epoch && (await refusedByOldKey(at, doc, ciphertext, p.heldEpoch, guest, signal));
      return {
        docId: doc.docId,
        epoch: doc.epoch,
        size: doc.cipherSize,
        cipherHash: doc.cipherHash,
        firstBytes,
        envelopesTried,
        ...(oldRefused ? { oldEpoch: p.heldEpoch } : {}),
        members: at.members.length,
        blockNumber: at.blockNumber,
      };
    }
    if (performance.now() + POLL_MS > deadline.endsAt) throw new Error("No pack of the board's new epoch showed within four minutes.");
    await pause(POLL_MS, signal);
  }
}
