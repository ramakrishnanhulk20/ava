import { KemKeyUnavailable, Mode, decryptDocument, encryptDocument, fetchKemKey, newBoardRef, newDocRef, newEpochKey, sameAccount, sealEpochKey, type KemRecipient } from "@ava/core";
import { bytesToHex, type Hex } from "viem";
import { REGISTRY } from "../chain";
import { blobUrl, openGuestEpochKey, readBlob, readBoard, readCreateNonce, readDocument, readGrants } from "../guest/board";
import type { GuestAccount } from "../guest/identity";
import { throwIfStopped } from "../guest/time";
import { confirm, relay, signedRelayBody } from "./actions";
import { rotationRecipients } from "./recipients";
import { uploadDocument, uploadEnvelope } from "./uploads";

/** What one board action is doing, for the page's line, and its transaction once the relay has answered. */
export type Say = (line: { text: string; hash?: Hex }) => void;

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

export interface CreatedBoard {
  boardId: bigint;
  boardRef: Hex;
  txHash: Hex;
  block: bigint;
}

/**
 * Creates a board chaired by this identity, from this browser. It makes the board's first key
 * here, seals it to the chair's own ML-KEM-1024 key as the chain publishes it (threat model C15),
 * stores the envelope, signs `create` with the chair's ML-DSA-87 key over fields built here, hands
 * the signed action to the relay, and takes the board as made only from the registry's own
 * BoardCreated event for this chair, this boardRef and this create nonce (C26).
 *
 * @throws Error when the chain publishes another ML-KEM key for this account, or as the upload,
 *   the relay or the confirmation fail.
 */
export async function createBoard(chair: GuestAccount, signal: AbortSignal, say: Say): Promise<CreatedBoard> {
  const me = chair.identity.evm;
  say({ text: "Reading this account's ML-KEM-1024 key from the chain's registry." });
  const recipient = await fetchKemKey(me);
  if (!sameBytes(recipient.kemPublicKey, chair.identity.seal.mlkemPublicKey)) throw new Error("The chain publishes another ML-KEM key for this account, so this browser could not open its own board.");

  const boardRef = bytesToHex(newBoardRef());
  const epochKey = newEpochKey();
  let envelope: Uint8Array;
  try {
    envelope = sealEpochKey({ registry: REGISTRY, boardRef, epoch: 0n, epochKey, recipients: [recipient] });
  } finally {
    epochKey.fill(0);
  }
  say({ text: `Sealed the board's first key to the chair alone: a ${envelope.length.toLocaleString("en-US")}-byte envelope. Storing it.` });
  const stored = await uploadEnvelope(envelope, signal);

  throwIfStopped(signal);
  const at = await readCreateNonce(me);
  const body = signedRelayBody(chair.identity.mldsa.secretKey, { action: "create", chair: me, boardRef, envelopeHash: stored.hash, envelopeSize: stored.size }, { registry: REGISTRY, nonce: at.nonce, latestBlockTimestamp: at.blockTimestamp });
  say({ text: "Signed the create with ML-DSA-87. Handing it to the relay." });
  const txHash = await relay(body, signal);
  say({ text: "The relay sent it. Waiting for its receipt on the public EVM RPC.", hash: txHash });
  const done = await confirm(txHash, { registry: REGISTRY, action: "create", chair: me, boardRef, nonce: at.nonce });
  return { boardId: done.boardId, boardRef, txHash, block: done.block };
}

/** How many key lookups run at once: enough to read a full board in a few seconds without leaning on the public RPC. */
const LOOKUPS_AT_ONCE = 4;

/** Every listed account's ML-KEM-1024 key, read from the chain's registry on the public EVM RPC (threat model C15). */
async function kemKeysOf(accounts: readonly Hex[], signal: AbortSignal): Promise<KemRecipient[]> {
  const out: KemRecipient[] = [];
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(LOOKUPS_AT_ONCE, accounts.length) }, async () => {
      while (next < accounts.length) {
        const account = accounts[next++] as Hex;
        throwIfStopped(signal);
        try {
          out.push(await fetchKemKey(account));
        } catch (error) {
          const why = error instanceof KemKeyUnavailable ? error.reason : "an error";
          throw new Error(`The ML-KEM key of ${account} could not be read from the chain (${why}).`);
        }
      }
    }),
  );
  return out;
}

export interface MemberChange {
  txHash: Hex;
  block: bigint;
  /** The epoch the board is in once the change has landed. */
  epoch: bigint;
}

/**
 * Adds a director to a board this identity chairs. The director's ML-KEM-1024 key comes from the
 * chain's registry, never from our server (threat model C15). With SEAL_CURRENT the board's current
 * key, opened from its on-chain envelope, is sealed to the director alone, so they can read this
 * epoch's packs. With ROTATE a new key is made and sealed to every member read at the same block
 * plus the director (C17), so they read only what is posted from now on.
 *
 * @throws Error when this identity is not the chair, the director is already a member, a key cannot be read, or a step fails.
 */
export async function addDirector(chair: GuestAccount, boardId: bigint, director: Hex, mode: Mode, signal: AbortSignal, say: Say): Promise<MemberChange> {
  say({ text: "Reading the board and the director's ML-KEM-1024 key from the chain's registry." });
  const snapshot = await readBoard(boardId);
  if (!sameAccount(snapshot.chair, chair.identity.evm)) throw new Error(`This account does not chair board ${boardId}.`);
  const [theirs] = await kemKeysOf([director], signal);
  if (theirs === undefined) throw new Error("The director's key was not read.");
  if (snapshot.members.some((m) => sameAccount(m, director))) throw new Error(`${director} is already a member of this board.`);

  let envelope: Uint8Array;
  let epoch: bigint;
  if (mode === Mode.SEAL_CURRENT) {
    epoch = snapshot.epoch;
    const opened = await openGuestEpochKey(snapshot, chair, signal);
    try {
      envelope = sealEpochKey({ registry: REGISTRY, boardRef: snapshot.boardRef, epoch, epochKey: opened.epochKey, recipients: [theirs] });
    } finally {
      opened.epochKey.fill(0);
    }
    say({ text: `Sealed the key of epoch ${epoch} to the director alone. Storing the envelope.` });
  } else {
    epoch = snapshot.epoch + 1n;
    const recipients = rotationRecipients(snapshot.members, await kemKeysOf(snapshot.members, signal), { add: theirs });
    const fresh = newEpochKey();
    try {
      envelope = sealEpochKey({ registry: REGISTRY, boardRef: snapshot.boardRef, epoch, epochKey: fresh, recipients });
    } finally {
      fresh.fill(0);
    }
    say({ text: `Made a new key for epoch ${epoch} and sealed it to ${recipients.length} members, the director included. Storing the envelope.` });
  }
  const stored = await uploadEnvelope(envelope, signal);

  throwIfStopped(signal);
  const body = signedRelayBody(
    chair.identity.mldsa.secretKey,
    { action: "add", boardId, member: director, mode, envelopeHash: stored.hash, envelopeSize: stored.size, epochAfter: epoch },
    { registry: REGISTRY, nonce: snapshot.nonce, latestBlockTimestamp: snapshot.blockTimestamp },
  );
  say({ text: "Signed the add with ML-DSA-87. Handing it to the relay." });
  const txHash = await relay(body, signal);
  say({ text: "The relay sent it. Waiting for its receipt on the public EVM RPC.", hash: txHash });
  const done = await confirm(txHash, { registry: REGISTRY, action: "add", boardId, member: director, nonce: snapshot.nonce });
  return { txHash, block: done.block, epoch };
}

/**
 * Removes a director from a board this identity chairs. A new key is made in this browser and
 * sealed to every other member read at the same block (threat model C17), so the next pack is shut
 * to the one removed. They keep what they could already open; the ledger says so.
 *
 * @throws Error when this identity is not the chair, the director is not a member, a remaining
 *   member's key cannot be read, or a step fails.
 */
export async function removeDirector(chair: GuestAccount, boardId: bigint, director: Hex, signal: AbortSignal, say: Say): Promise<MemberChange> {
  say({ text: "Reading the board and every remaining member's ML-KEM-1024 key from the chain's registry." });
  const snapshot = await readBoard(boardId);
  if (!sameAccount(snapshot.chair, chair.identity.evm)) throw new Error(`This account does not chair board ${boardId}.`);
  if (sameAccount(director, snapshot.chair)) throw new Error("The chair cannot be removed. Hand the chair over first.");
  const staying = snapshot.members.filter((m) => !sameAccount(m, director));
  const recipients = rotationRecipients(snapshot.members, await kemKeysOf(staying, signal), { remove: director });
  const epoch = snapshot.epoch + 1n;
  const fresh = newEpochKey();
  let envelope: Uint8Array;
  try {
    envelope = sealEpochKey({ registry: REGISTRY, boardRef: snapshot.boardRef, epoch, epochKey: fresh, recipients });
  } finally {
    fresh.fill(0);
  }
  say({ text: `Made a new key for epoch ${epoch} and sealed it to the ${recipients.length} members who stay. Storing the envelope.` });
  const stored = await uploadEnvelope(envelope, signal);

  throwIfStopped(signal);
  const body = signedRelayBody(
    chair.identity.mldsa.secretKey,
    { action: "remove", boardId, member: director, envelopeHash: stored.hash, envelopeSize: stored.size, epochAfter: epoch },
    { registry: REGISTRY, nonce: snapshot.nonce, latestBlockTimestamp: snapshot.blockTimestamp },
  );
  say({ text: "Signed the removal with ML-DSA-87. Handing it to the relay." });
  const txHash = await relay(body, signal);
  say({ text: "The relay sent it. Waiting for its receipt on the public EVM RPC.", hash: txHash });
  const done = await confirm(txHash, { registry: REGISTRY, action: "remove", boardId, member: director, nonce: snapshot.nonce });
  return { txHash, block: done.block, epoch };
}

export interface PostedPack {
  docId: bigint;
  epoch: bigint;
  cipherHash: Hex;
  cipherSize: bigint;
  txHash: Hex;
  block: bigint;
}

/**
 * Posts one pack to a board this identity chairs. The pack is encrypted in this browser under the
 * board's current epoch key, opened from the envelope the registry recorded and never from memory
 * (threat model C12). Only the ciphertext leaves the device: it goes straight to the blob store,
 * our server checks the stored bytes, and the chair signs `post` over the hash and size computed
 * here. The pack counts as posted only on the registry's DocumentPosted for this docRef and nonce.
 *
 * @throws Error when this identity is not the board's chair, or as a step fails.
 */
export async function postPack(chair: GuestAccount, boardId: bigint, plaintext: Uint8Array, signal: AbortSignal, say: Say): Promise<PostedPack> {
  say({ text: "Reading the board and opening its current key from the on-chain envelope." });
  const snapshot = await readBoard(boardId);
  if (!sameAccount(snapshot.chair, chair.identity.evm)) throw new Error(`This account does not chair board ${boardId}.`);
  const opened = await openGuestEpochKey(snapshot, chair, signal);
  const docRef = bytesToHex(newDocRef());
  let ciphertext: Uint8Array;
  try {
    ciphertext = await encryptDocument({ epochKey: opened.epochKey, registry: REGISTRY, boardRef: snapshot.boardRef, epoch: snapshot.epoch, docRef, plaintext });
  } finally {
    opened.epochKey.fill(0);
  }
  say({ text: `Encrypted ${plaintext.length.toLocaleString("en-US")} bytes on this device under the key of epoch ${snapshot.epoch}.` });
  const stored = await uploadDocument(ciphertext, signal, (text) => say({ text }));

  throwIfStopped(signal);
  const body = signedRelayBody(
    chair.identity.mldsa.secretKey,
    { action: "post", boardId, docRef, cipherHash: stored.hash, cipherSize: stored.size, epoch: snapshot.epoch },
    { registry: REGISTRY, nonce: snapshot.nonce, latestBlockTimestamp: snapshot.blockTimestamp },
  );
  say({ text: "Signed the post with ML-DSA-87. Handing it to the relay." });
  const txHash = await relay(body, signal);
  say({ text: "The relay sent it. Waiting for its receipt on the public EVM RPC.", hash: txHash });
  const done = await confirm(txHash, { registry: REGISTRY, action: "post", boardId, docRef, nonce: snapshot.nonce });
  if (done.docId === undefined) throw new Error("The post landed without a document id.");
  return { docId: done.docId, epoch: snapshot.epoch, cipherHash: stored.hash, cipherSize: stored.size, txHash, block: done.block };
}

/**
 * Opens one pack of a board as a member would: the pack's record and its epoch's grants from the
 * registry, the envelope and the ciphertext from the blob store by their on-chain hashes, the size
 * and SHA-256 of each checked before any key touches them, decrypted on this device.
 *
 * @throws Error when no envelope of that epoch is sealed to this identity, or a blob is not the recorded bytes.
 */
export async function openPack(member: GuestAccount, boardId: bigint, docId: bigint, signal: AbortSignal): Promise<{ plaintext: Uint8Array; epoch: bigint; cipherHash: Hex }> {
  const [snapshot, doc] = await Promise.all([readBoard(boardId), readDocument(boardId, docId)]);
  const grants = doc.epoch === snapshot.epoch ? snapshot.grants : await readGrants(boardId, doc.epoch);
  const opened = await openGuestEpochKey({ ...snapshot, epoch: doc.epoch, grants }, member, signal);
  try {
    const ciphertext = await readBlob(blobUrl("document", doc.cipherHash), Number(doc.cipherSize), signal);
    const plaintext = await decryptDocument({ epochKey: opened.epochKey, registry: REGISTRY, boardRef: snapshot.boardRef, epoch: doc.epoch, docRef: doc.docRef, ciphertext, expectedHash: doc.cipherHash, expectedSize: doc.cipherSize });
    return { plaintext, epoch: doc.epoch, cipherHash: doc.cipherHash };
  } finally {
    opened.epochKey.fill(0);
  }
}
