"use client";

import { formatCount, useDemoBoard } from "../../lib/chain";
import { PackSheets, WIDE_ROWS } from "../hero/PackSheets";
import { RING_AFTER, RING_BEFORE } from "../hero/rings";
import { Seal } from "../hero/Seal";
import { CipherRows } from "./CipherRows";
import { LedgerCard } from "./LedgerCard";
import { SignatureSlip } from "./SignatureSlip";

export type StillKind = "seal" | "sign" | "remove";

// Height of the drawing for each beat. The slip hangs below the pack, and the ledger card sits under it.
const DESIGN_HEIGHT: Record<StillKind, number> = { seal: 620, sign: 640, remove: 770 };

type HowStillProps = {
  kind: StillKind;
};

/** The small, still version of the visual that sits under each beat on narrow screens, already at the beat's end state. */
export function HowStill({ kind }: HowStillProps) {
  const board = useDemoBoard();
  const block = board.block === null ? null : formatCount(board.block);
  const height = DESIGN_HEIGHT[kind];

  return (
    <div className="how-still lg:hidden" style={{ aspectRatio: `492 / ${height}` }} aria-hidden="true">
      <div className="how-still-design" style={{ height }}>
        <div className="absolute" style={{ left: 0, top: 0, width: 460, height: 580 }}>
          <div className="how-pack relative h-full w-full">
            <PackSheets
              fixed
              sealSize={132}
              seal={<Seal size={132} ringText={kind === "remove" ? RING_AFTER : RING_BEFORE} state="reformed" />}
            >
              <CipherRows rows={WIDE_ROWS} />
            </PackSheets>
          </div>
        </div>
        {kind === "sign" ? <SignatureSlip on block={block} place={{ left: 0, top: 556 }} /> : null}
        {kind === "remove" ? <LedgerCard on place={{ left: 110, top: 640 }} /> : null}
      </div>
    </div>
  );
}
