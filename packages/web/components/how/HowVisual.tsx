"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { formatCount, useDemoBoard } from "../../lib/chain";
import { randomHexRow } from "../../lib/hexRows";
import { useMotionMode } from "../../lib/motionMode";
import { PackSheets, WIDE_ROWS } from "../hero/PackSheets";
import { RING_AFTER, RING_BEFORE } from "../hero/rings";
import { Seal, type SealState } from "../hero/Seal";
import { CipherRows, type CipherRowText } from "./CipherRows";
import { LedgerCard } from "./LedgerCard";
import { SignatureSlip } from "./SignatureSlip";

/** "idle" is the section before its first beat is reached: the pack waits as plain text bars. */
export type Stage = "idle" | "seal" | "sign" | "remove";

const ROW_STAGGER_MS = 60;
const ROW_SCRAMBLE_MS = 420;
const SCRAMBLE_TOTAL_MS = (WIDE_ROWS.length - 1) * ROW_STAGGER_MS + ROW_SCRAMBLE_MS;
// Redrawing every 50ms keeps the hex flicker readable instead of a blur.
const SCRAMBLE_REDRAW_MS = 50;

const BARS: CipherRowText[] = WIDE_ROWS.map(() => null);

/** Draws the rows for one moment of the scramble: bars not yet reached, random hex while scrambling, final text after. */
function rowsAt(elapsed: number): CipherRowText[] {
  return WIDE_ROWS.map((finalRow, i) => {
    const local = elapsed - i * ROW_STAGGER_MS;
    if (local < 0) return null;
    return local >= ROW_SCRAMBLE_MS ? finalRow : randomHexRow(34);
  });
}

type HowVisualProps = {
  stage: Stage;
};

export function HowVisual({ stage }: HowVisualProps) {
  const mode = useMotionMode();
  const board = useDemoBoard();
  const [rows, setRows] = useState<CipherRowText[]>(BARS);
  const [sealOn, setSealOn] = useState(false);
  const [removed, setRemoved] = useState(false);
  const settled = useRef(false);

  useEffect(() => {
    if (stage === "idle" || mode === "pending" || settled.current) return;

    const finish = () => {
      settled.current = true;
      setRows(WIDE_ROWS);
      setSealOn(true);
    };

    // Reduced motion, or a reader who landed past the first beat, gets the sealed pack at once.
    if (mode === "reduced" || stage !== "seal") {
      finish();
      return;
    }

    const start = performance.now();
    let frame = 0;
    let lastDraw = 0;
    const tick = (now: number) => {
      const elapsed = now - start;
      if (elapsed >= SCRAMBLE_TOTAL_MS) {
        finish();
        return;
      }
      if (now - lastDraw >= SCRAMBLE_REDRAW_MS) {
        lastDraw = now;
        setRows(rowsAt(elapsed));
      }
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [stage, mode]);

  useEffect(() => {
    if (stage !== "remove") setRemoved(false);
  }, [stage]);

  const sealDone = useCallback(() => setRemoved(true), []);

  const sealState: SealState = stage === "remove" ? (removed ? "reformed" : "breaking") : "intact";
  const ring = stage === "remove" ? RING_AFTER : RING_BEFORE;
  const block = board.block === null ? null : formatCount(board.block);

  return (
    <div className="how-stage" aria-hidden="true">
      <div className="how-stage-design">
        <div className="absolute" style={{ left: 24, top: 0, width: 460, height: 580 }}>
          <div className="how-pack relative h-full w-full">
            <PackSheets
              fixed
              sealSize={132}
              seal={sealOn ? <Seal size={132} ringText={ring} state={sealState} onDone={sealDone} /> : null}
            >
              <CipherRows rows={rows} />
            </PackSheets>
          </div>
        </div>
        <SignatureSlip on={stage === "sign"} block={block} place={{ left: 0, top: 556 }} />
        <LedgerCard on={stage === "remove" && removed} place={{ left: 456, top: 150 }} />
      </div>
    </div>
  );
}
