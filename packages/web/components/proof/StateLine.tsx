import type { CellState } from "../../lib/boardRules";
import { Cross, Hollow, Tick } from "./Glyphs";

const LABEL: Record<CellState, string> = {
  open: "CAN OPEN",
  locked: "LOCKED",
  notyet: "NOT YET A MEMBER",
};

type StateLineProps = {
  state: CellState;
  tickSize: number;
  /** Seconds before the tick draws, for the table. Leave out where nothing animates. */
  drawAfter?: number;
};

export function StateLine({ state, tickSize, drawAfter }: StateLineProps) {
  return (
    <span
      className={`mono flex items-center gap-2 text-[11px] tracking-[0.12em] ${state === "notyet" ? "text-ink-soft" : "text-ink"}`}
    >
      {state === "open" ? <Tick size={tickSize} drawAfter={drawAfter} /> : null}
      {state === "locked" ? <Cross size={12} /> : null}
      {state === "notyet" ? <Hollow /> : null}
      {LABEL[state]}
    </span>
  );
}
