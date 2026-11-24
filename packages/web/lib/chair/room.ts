import { KemKeyUnavailable, assertHash, fetchKemKey } from "@ava/core";
import type { HistoryEvent } from "../boardRules";
import { blobUrl, readBlob, readBoard, readGrants, type BoardSnapshot } from "../guest/board";
import { throwIfStopped } from "../guest/time";
import { forgetHistory, membersFromEvents, readHistory, readPackRecords, rememberHistory, rememberedHistory, sameMembers, type PackRecord } from "./history";
import { checkEnvelope, expectedReaders, type EnvelopeVerdict } from "./ledger";

/** One board as the room shows it: its live record, its whole history and its packs, all as of one block. */
export interface Room {
  snapshot: BoardSnapshot;
  events: HistoryEvent[];
  packs: PackRecord[];
  /**
   * False when the members the events rebuild are not the registry's own member list at the block
   * read. The room then says its history is incomplete instead of drawing a ledger from it (C38).
   */
  complete: boolean;
}

/**
 * Reads a board for the room: the registry's record at the latest block, then every event of the
 * board up to that same block, then each pack's record at that block. The members the events add up
 * to must equal the registry's own list; a remembered history that fails that test is thrown away
 * and read again from the start once.
 *
 * @throws Error when the board does not exist or a read fails.
 */
export async function readRoom(boardId: bigint, signal: AbortSignal, onPage: (done: number, total: number) => void = () => undefined): Promise<Room> {
  const snapshot = await readBoard(boardId);
  const known = rememberedHistory(boardId);
  let history = await readHistory(boardId, snapshot.blockNumber, known, signal, onPage);
  let complete = sameMembers(membersFromEvents(history.events), snapshot.members);
  if (!complete && known !== undefined) {
    forgetHistory(boardId);
    history = await readHistory(boardId, snapshot.blockNumber, undefined, signal, onPage);
    complete = sameMembers(membersFromEvents(history.events), snapshot.members);
  }
  if (complete) rememberHistory(boardId, history);
  const count = snapshot.latest === undefined ? 0 : Number(snapshot.latest.docId) + 1;
  const packs = await readPackRecords(boardId, count, snapshot.blockNumber);
  return { snapshot, events: history.events, packs, complete };
}

/** What the ledger found for one envelope of one epoch. */
export interface EnvelopeAudit {
  epoch: number;
  /** ROTATE for the envelope that opened the epoch, SEAL_CURRENT for one member admitted in it. */
  mode: number;
  expected: number;
  verdict: EnvelopeVerdict;
}

/**
 * Checks every key envelope the board has ever recorded against the readers its history says each
 * should hold (threat model C38, C39). Each envelope is downloaded by its on-chain hash and must be
 * the recorded bytes; each expected reader's ML-KEM key is read from the chain's registry. A reader
 * whose key the chain no longer holds counts as unknown to the check, never as a match. A lookup
 * or a download that fails outright fails the audit: a partial audit is not shown as a clean one.
 *
 * @param onStep Told as each epoch is finished: how many are done, of how many.
 */
export async function auditEnvelopes(room: Room, signal: AbortSignal, onStep: (done: number, total: number) => void = () => undefined): Promise<EnvelopeAudit[]> {
  const { snapshot, events } = room;
  const epochs = Number(snapshot.epoch) + 1;
  const keys = new Map<string, Uint8Array | undefined>();
  const keyOf = async (address: string): Promise<Uint8Array | undefined> => {
    const id = address.toLowerCase();
    if (keys.has(id)) return keys.get(id);
    let key: Uint8Array | undefined;
    try {
      key = (await fetchKemKey(address)).kemPublicKey;
    } catch (error) {
      // No key, or a key that is not a valid ML-KEM-1024 key, is a fact about the reader. Anything else is a failed read.
      if (!(error instanceof KemKeyUnavailable) || !["NOT_FOUND", "WRONG_ALGORITHM", "INVALID_KEY"].includes(error.reason)) throw error;
      key = undefined;
    }
    keys.set(id, key);
    return key;
  };

  const out: EnvelopeAudit[] = [];
  onStep(0, epochs);
  for (let epoch = 0; epoch < epochs; epoch++) {
    throwIfStopped(signal);
    const grants = BigInt(epoch) === snapshot.epoch ? snapshot.grants : await readGrants(snapshot.boardId, BigInt(epoch));
    for (const grant of grants) {
      const expected = expectedReaders(events, { epoch, mode: grant.mode, member: grant.member });
      let verdict: EnvelopeVerdict;
      try {
        const envelope = await readBlob(blobUrl("envelope", grant.envelopeHash), grant.envelopeSize, signal);
        if (envelope.length !== grant.envelopeSize) throw new Error("size");
        assertHash(envelope, grant.envelopeHash);
        const readers = await Promise.all(expected.map(async (address) => ({ address, kemPublicKey: await keyOf(address) })));
        verdict = checkEnvelope(envelope, readers);
      } catch (error) {
        if (signal.aborted) throw error;
        if (error instanceof KemKeyUnavailable) throw error;
        verdict = { state: "unreadable" };
      }
      out.push({ epoch, mode: grant.mode, expected: expected.length, verdict });
    }
    onStep(epoch + 1, epochs);
  }
  return out;
}
