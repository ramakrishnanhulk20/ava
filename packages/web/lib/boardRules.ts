// The one rule behind the proof section. It reads the registry's events and says, for every director
// and every pack, whether that director held the key for the pack's epoch. No chain access lives here,
// so the same code runs in the browser and in the checks.

export type Hex = `0x${string}`;
export type Address = `0x${string}`;

export const MODE_SEAL_CURRENT = 0;
export const MODE_ROTATE = 1;

type Placed = { tx: Hex; block: number; index: number };

export type HistoryEvent =
  | ({ name: "BoardCreated"; chair: Address } & Placed)
  | ({ name: "MemberAdded"; member: Address; epoch: number; mode: number } & Placed)
  | ({ name: "MemberRemoved"; member: Address; newEpoch: number } & Placed)
  | ({ name: "EpochRotated"; newEpoch: number } & Placed)
  | ({ name: "EnvelopeGranted"; epoch: number; mode: number; member: Address } & Placed)
  | ({ name: "DocumentPosted"; docId: number; epoch: number } & Placed);

export type Director = { name: string; address: Address };

/** One posted pack, as the registry's getDocument reports it. */
export type PackInfo = { index: number; epoch: number; postedAt: number };

/** One stretch of membership: the epoch the member joined and, once they are removed, the epoch their removal started. */
export type Tenure = {
  startEpoch: number;
  mode: number;
  startTx: Hex;
  startBlock: number;
  endEpoch: number | null;
  endTx: Hex | null;
  endBlock: number | null;
};

export type CellState = "open" | "locked" | "notyet";

/** The answer for one director and one pack, with the transaction that backs it. */
export type Cell = { state: CellState; tx: Hex | null; block: number | null };

export type Chip =
  { kind: "chair" } | { kind: "member" } | { kind: "removed"; epoch: number; tx: Hex } | { kind: "none" };

export type DirectorRow = { director: Director; chip: Chip; cells: Cell[] };

export type ProofModel = {
  rows: DirectorRow[];
  guests: { now: number; ever: number; perPack: number[] };
  proof: {
    /** Packs a removed director could open although they were posted after the removal. */
    opened: number;
    /** Packs a removed director could open that were posted before the removal. */
    kept: number;
    removal: { name: string; tx: Hex; block: number } | null;
  };
};

const byChainOrder = (a: Placed, b: Placed) => a.block - b.block || a.index - b.index;

/** Every address's tenures, in the order the events landed. The chair's first tenure starts at epoch 0 from BoardCreated. */
export function tenuresByMember(events: HistoryEvent[]): Map<string, Tenure[]> {
  const out = new Map<string, Tenure[]>();
  const open = (who: string, epoch: number, mode: number, at: Placed) => {
    const list = out.get(who) ?? [];
    const last = list[list.length - 1];
    if (last && last.endEpoch === null) return;
    list.push({
      startEpoch: epoch,
      mode,
      startTx: at.tx,
      startBlock: at.block,
      endEpoch: null,
      endTx: null,
      endBlock: null,
    });
    out.set(who, list);
  };
  const close = (who: string, epoch: number, at: Placed) => {
    const last = out.get(who)?.at(-1);
    if (!last || last.endEpoch !== null) return;
    last.endEpoch = epoch;
    last.endTx = at.tx;
    last.endBlock = at.block;
  };

  for (const event of [...events].sort(byChainOrder)) {
    if (event.name === "BoardCreated") open(event.chair.toLowerCase(), 0, MODE_ROTATE, event);
    else if (event.name === "MemberAdded") open(event.member.toLowerCase(), event.epoch, event.mode, event);
    else if (event.name === "MemberRemoved") close(event.member.toLowerCase(), event.newEpoch, event);
  }
  return out;
}

/** For each epoch, the transaction of the first MODE_ROTATE envelope that opened it. */
export function rotateGrants(events: HistoryEvent[]): Map<number, { tx: Hex; block: number }> {
  const out = new Map<number, { tx: Hex; block: number }>();
  for (const event of [...events].sort(byChainOrder)) {
    if (event.name === "EnvelopeGranted" && event.mode === MODE_ROTATE && !out.has(event.epoch)) {
      out.set(event.epoch, { tx: event.tx, block: event.block });
    }
  }
  return out;
}

/** The rule. Open inside any tenure, locked once removed and not covered again, otherwise not yet a member. */
export function stateAt(tenures: Tenure[], epoch: number): CellState {
  if (tenures.some((t) => epoch >= t.startEpoch && (t.endEpoch === null || epoch < t.endEpoch))) return "open";
  if (tenures.some((t) => t.endEpoch !== null && t.endEpoch <= epoch)) return "locked";
  return "notyet";
}

export function cellAt(tenures: Tenure[], epoch: number, grants: Map<number, { tx: Hex; block: number }>): Cell {
  const state = stateAt(tenures, epoch);

  if (state === "open") {
    const tenure = tenures.find((t) => epoch >= t.startEpoch && (t.endEpoch === null || epoch < t.endEpoch));
    // A member who joined during this epoch by a single envelope got the key from their own add; everyone else got it from the epoch's rotation.
    if (tenure && tenure.startEpoch === epoch && tenure.mode === MODE_SEAL_CURRENT) {
      return { state, tx: tenure.startTx, block: tenure.startBlock };
    }
    const grant = grants.get(epoch);
    return { state, tx: grant?.tx ?? null, block: grant?.block ?? null };
  }

  if (state === "locked") {
    const removal = tenures
      .filter((t) => t.endEpoch !== null && t.endEpoch <= epoch)
      .sort((a, b) => (b.endEpoch ?? 0) - (a.endEpoch ?? 0))[0];
    return { state, tx: removal?.endTx ?? null, block: removal?.endBlock ?? null };
  }

  const first = tenures[0];
  return { state, tx: first?.startTx ?? null, block: first?.startBlock ?? null };
}

export function buildProofModel(
  events: HistoryEvent[],
  packs: PackInfo[],
  directors: Director[],
  chair: Address | null,
): ProofModel {
  const tenures = tenuresByMember(events);
  const grants = rotateGrants(events);
  const directorKeys = new Set(directors.map((d) => d.address.toLowerCase()));

  const rows: DirectorRow[] = directors.map((director) => {
    const own = tenures.get(director.address.toLowerCase()) ?? [];
    const last = own.at(-1);
    let chip: Chip;
    if (chair && director.address.toLowerCase() === chair.toLowerCase()) chip = { kind: "chair" };
    else if (!last) chip = { kind: "none" };
    else if (last.endEpoch !== null && last.endTx) chip = { kind: "removed", epoch: last.endEpoch, tx: last.endTx };
    else chip = { kind: "member" };
    return { director, chip, cells: packs.map((pack) => cellAt(own, pack.epoch, grants)) };
  });

  const guestKeys = [...tenures.keys()].filter((key) => !directorKeys.has(key));
  const guests = {
    now: guestKeys.filter((key) => tenures.get(key)?.at(-1)?.endEpoch === null).length,
    ever: guestKeys.length,
    perPack: packs.map(
      (pack) => guestKeys.filter((key) => stateAt(tenures.get(key) ?? [], pack.epoch) === "open").length,
    ),
  };

  let opened = 0;
  let kept = 0;
  let removal: ProofModel["proof"]["removal"] = null;
  for (const row of rows) {
    const own = tenures.get(row.director.address.toLowerCase()) ?? [];
    const ends = own.filter((t) => t.endEpoch !== null);
    if (ends.length === 0) continue;
    if (!removal) {
      const first = ends[0];
      if (first?.endTx && first.endBlock !== null)
        removal = { name: row.director.name, tx: first.endTx, block: first.endBlock };
    }
    packs.forEach((pack, i) => {
      if (row.cells[i]?.state !== "open") return;
      const afterRemoval = ends.some((t) => (t.endEpoch ?? Infinity) <= pack.epoch);
      if (afterRemoval) opened += 1;
      else kept += 1;
    });
  }

  return { rows, guests, proof: { opened, kept, removal } };
}

export function shortHash(hash: string): string {
  return `${hash.slice(0, 6)}…${hash.slice(-4)}`;
}

const MONTHS = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];

/** "19 NOV", in UTC, so every reader sees the same day. */
export function shortDate(unixSeconds: number): string {
  const date = new Date(unixSeconds * 1000);
  return `${date.getUTCDate()} ${MONTHS[date.getUTCMonth()]}`;
}
