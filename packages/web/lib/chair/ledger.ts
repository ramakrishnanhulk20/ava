import { parseEnvelope, recipientHint } from "@qorechain/qoreseal";
import { MODE_ROTATE, tenuresByMember, type HistoryEvent } from "../boardRules";

/** What the ledger found when it laid one envelope's entries against the readers the board's history says it should hold. */
export type EnvelopeVerdict =
  /** Every entry belongs to an expected reader, and every expected reader has one. */
  | { state: "clean"; recipients: number }
  /** More entries than the expected readers can account for, even granting each reader whose key has changed one entry. */
  | { state: "unknown_reader"; recipients: number; unknown: number }
  /** An expected reader whose key is on chain has no entry: the epoch's key was not sealed to them. */
  | { state: "left_out"; recipients: number; leftOut: string[] }
  /**
   * Entries that no current key explains, and as many readers with no entry under the key the chain holds now. Either
   * those readers changed or withdrew a key since, or they were left out and the entries are someone else's. The two
   * cannot be told apart from the chain's present state, so this is never shown as clean and never explained away.
   */
  | { state: "unverified"; recipients: number; unexplained: number; unmatched: string[] }
  | { state: "unreadable" };

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((v, i) => v === b[i]);

/**
 * Lays an envelope's recipient entries against the readers it should hold (threat model C39). Each
 * entry carries a hint anyone can compute from a public ML-KEM key, so no secret is needed. An
 * entry that no expected reader's on-chain key explains is an unknown reader, unless a reader's
 * key has changed or gone since, in which case the envelope is unverified: never clean.
 *
 * @param expected The accounts the board's history says the envelope was sealed to, each with the ML-KEM key the chain holds for it now, or undefined when it holds none.
 */
export function checkEnvelope(envelope: Uint8Array, expected: readonly { address: string; kemPublicKey: Uint8Array | undefined }[]): EnvelopeVerdict {
  let parsed: ReturnType<typeof parseEnvelope>;
  try {
    parsed = parseEnvelope(envelope);
  } catch {
    return { state: "unreadable" };
  }
  const hints = parsed.entries.map((entry) => entry.hint);
  const taken = new Set<number>();
  const unmatched: string[] = [];
  const keyless: string[] = [];
  for (const reader of expected) {
    if (reader.kemPublicKey === undefined) {
      keyless.push(reader.address);
      continue;
    }
    const hint = recipientHint(parsed.salt, reader.kemPublicKey);
    const at = hints.findIndex((h, i) => !taken.has(i) && sameBytes(h, hint));
    if (at >= 0) taken.add(at);
    else unmatched.push(reader.address);
  }
  const recipients = hints.length;
  const unexplained = recipients - taken.size;
  // A reader with no entry under its current key may hold one under an earlier key; so may one with no key now.
  const mayExplain = unmatched.length + keyless.length;
  if (unexplained > mayExplain) return { state: "unknown_reader", recipients, unknown: unexplained - mayExplain };
  if (unexplained > 0) return { state: "unverified", recipients, unexplained, unmatched: [...unmatched, ...keyless] };
  if (unmatched.length > 0 || keyless.length > 0) return { state: "left_out", recipients, leftOut: [...unmatched, ...keyless] };
  return { state: "clean", recipients };
}

/**
 * Who one grant's envelope should be sealed to, from the board's history alone: the one member a
 * seal-current envelope names, or, for the rotation that opened an epoch, everyone on the board as
 * that epoch began (a member added by that rotation included, the one removed by it not).
 */
export function expectedReaders(events: readonly HistoryEvent[], grant: { epoch: number; mode: number; member: string }): string[] {
  if (grant.mode !== MODE_ROTATE) return [grant.member];
  const out: string[] = [];
  for (const [member, tenures] of tenuresByMember([...events])) {
    const there = tenures.some((t) => (t.startEpoch < grant.epoch || (t.startEpoch === grant.epoch && t.mode === MODE_ROTATE)) && (t.endEpoch === null || t.endEpoch > grant.epoch));
    if (there) out.push(member);
  }
  return out;
}
