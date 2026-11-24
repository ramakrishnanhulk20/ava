"use client";

import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { formatCount, useDemoBoard } from "../../lib/chain";
import { hexRows, randomHexRow } from "../../lib/hexRows";
import { shortQor1 } from "../../lib/drillAccount";
import type { JourneyView } from "../../lib/guest/journey";
import type { LeaveStepKey, LeaveView } from "../../lib/guest/leaveJourney";
import { SHOWN_BYTES_PER_ROW, SHOWN_ROWS, hexRowsOf } from "../../lib/guest/shut";
import { useMotionMode } from "../../lib/motionMode";
import { PackSheets, ROW_CLASS, WIDE_ROWS } from "../hero/PackSheets";
import { Seal, type SealState } from "../hero/Seal";
import { CipherRows } from "../how/CipherRows";
import { Cross } from "../proof/Glyphs";
import { chaptersOf, sponsoredAmount, type ChapterId, type ChapterView } from "./chapters";
import { DemoSlip } from "./DemoSlip";

const RING_START = "SEALED TO THE DEMO BOARD ·";
const RING_MEMBER = "SEALED TO THE BOARD · AND YOU ·";
const RING_GONE = "SEALED TO THE BOARD · WITHOUT YOU ·";

const ROW_STAGGER_MS = 60;
const ROW_SCRAMBLE_MS = 420;
const READ_DELAY_MS = 600;
// The opened sheet takes this long to slide away; the seal under it breaks once it has gone.
const SHEET_LEAVE_MS = 700;
const ROWS = 9;
const COLS = 34;

// The new sheet starts as ciphertext of its own, so the pack underneath keeps its rows.
const NEW_SHEET_HEX = hexRows("ava-demo-new-pack", ROWS, COLS);

// A stamp is the seal drawn in ink. The seal reads the accent variables, so scoping them is enough.
const STAMP_INK = { "--accent": "var(--ink)", "--accent-deep": "#0b0a0f" } as CSSProperties;

const TAG = "demo-fade mono rounded-[4px] border border-rule px-2 py-[3px] text-[11px] tracking-[0.12em]";

type SheetRow = { text: string; readable: boolean };

const HEX_SHEET_ROWS: SheetRow[] = NEW_SHEET_HEX.map((text) => ({ text, readable: false }));

/** The first lines of the decrypted pack that have words on them: they are what the rows settle on. */
function firstLines(text: string, count: number): string[] {
  return text
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line !== "")
    .slice(0, count);
}

function rowsAt(lines: string[], elapsed: number): SheetRow[] {
  return Array.from({ length: ROWS }, (_, i) => {
    const local = elapsed - i * ROW_STAGGER_MS;
    const line = lines[i];
    if (line === undefined) return { text: "", readable: true };
    if (local < 0) return { text: NEW_SHEET_HEX[i] ?? "", readable: false };
    if (local >= ROW_SCRAMBLE_MS) return { text: line, readable: true };
    return { text: randomHexRow(COLS), readable: false };
  });
}

/** The sealed pack's rows on their way from the drawn ciphertext to the next pack's real bytes. */
function sealedRowsAt(real: string[], elapsed: number): string[] {
  return WIDE_ROWS.map((drawn, i) => {
    const local = elapsed - i * ROW_STAGGER_MS;
    if (local < 0) return drawn;
    return local >= ROW_SCRAMBLE_MS ? (real[i] ?? "") : randomHexRow(COLS);
  });
}

const SCRAMBLE_TOTAL_MS = (ROWS - 1) * ROW_STAGGER_MS + ROW_SCRAMBLE_MS;

function packNumber(docId: bigint): string {
  return (docId + 1n).toString();
}

type DemoStageProps = {
  view: JourneyView;
  /** The removal and the check of the next pack, once the guest has asked for them. */
  leave?: LeaveView;
  /** Called once the new sheet has unscrambled and a moment has passed: the cue to open the reading view. */
  onRead: () => void;
};

function chapterState(chapters: ChapterView[], id: ChapterId): ChapterView["state"] {
  return chapters.find((chapter) => chapter.id === id)?.state ?? "waiting";
}

export function DemoStage({ view, leave, onRead }: DemoStageProps) {
  const mode = useMotionMode();
  const board = useDemoBoard();
  const chapters = useMemo(() => chaptersOf(view), [view]);
  const done = (id: ChapterId) => chapterState(chapters, id) === "done";
  const packState = chapterState(chapters, "pack");

  const leaveStep = (key: LeaveStepKey) => leave?.steps.find((s) => s.key === key);
  const removal = leave?.removal;
  const gone = removal !== undefined;
  // Only a removal this page watched land breaks the seal; a seat that was already gone is simply shown sealed without the guest.
  const sawRemoval = removal?.txHash !== undefined;
  const found = leave?.found;
  const shut = leave?.shut;
  const leaveFacts = leaveStep("request")?.detail?.match(/^(\d+) bytes for board (\d+)/);
  const leaveSlipOn = leaveStep("request")?.state === "done" && leaveStep("removal")?.state === "running" && leaveFacts !== null && leaveFacts !== undefined;

  const keyCardOn = done("identity");
  const sponsorOn = done("sponsor");
  const stampsOn = done("keys");
  const challenge = chapters.find((chapter) => chapter.id === "challenge");
  const challengeFacts = challenge?.details[0]?.match(/^(\d+) bytes for board (\d+)/);
  // The slip waits with the guest for the admission; a join that ended, either way, puts it away.
  const slipOn = done("challenge") && chapterState(chapters, "admitted") === "running" && challengeFacts !== null && challengeFacts !== undefined;
  const memberOn = done("admitted");
  const sheetOn = (packState === "running" || packState === "done") && !gone;
  const amount = sponsoredAmount(view);

  const [rows, setRows] = useState<SheetRow[]>(HEX_SHEET_ROWS);
  const readRef = useRef(onRead);
  readRef.current = onRead;

  const lines = useMemo(() => (view.pack === undefined ? undefined : firstLines(view.pack, ROWS)), [view.pack]);

  useEffect(() => {
    if (lines === undefined) {
      setRows(HEX_SHEET_ROWS);
      return;
    }
    if (mode === "pending") return;
    let frame = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const settle = () => {
      setRows(rowsAt(lines, SCRAMBLE_TOTAL_MS));
      timer = setTimeout(() => readRef.current(), mode === "reduced" ? 0 : READ_DELAY_MS);
    };
    if (mode === "reduced") {
      settle();
    } else {
      const start = performance.now();
      let lastDraw = 0;
      const tick = (now: number) => {
        const elapsed = now - start;
        if (elapsed >= SCRAMBLE_TOTAL_MS) {
          settle();
          return;
        }
        if (now - lastDraw >= 50) {
          lastDraw = now;
          setRows(rowsAt(lines, elapsed));
        }
        frame = requestAnimationFrame(tick);
      };
      frame = requestAnimationFrame(tick);
    }
    return () => {
      cancelAnimationFrame(frame);
      clearTimeout(timer);
    };
  }, [lines, mode]);

  // The seal waits for the opened sheet to leave, then cracks and re-forms around the board without the guest.
  const [sheetGone, setSheetGone] = useState(false);
  const [reformed, setReformed] = useState(false);
  useEffect(() => {
    if (!gone) {
      setSheetGone(false);
      setReformed(false);
      return;
    }
    if (mode === "pending") return;
    const timer = setTimeout(() => setSheetGone(true), mode === "reduced" ? 0 : SHEET_LEAVE_MS);
    return () => clearTimeout(timer);
  }, [gone, mode]);
  const sealedWithout = gone && sheetGone;
  const sealState: SealState = sealedWithout && sawRemoval ? (reformed ? "reformed" : "breaking") : "intact";
  const ring = sealedWithout ? RING_GONE : memberOn ? RING_MEMBER : RING_START;

  // Once the next pack is found its real stored bytes replace the drawn ciphertext on the sealed pack.
  const realRows = useMemo(() => (found === undefined ? undefined : hexRowsOf(found.firstBytes, SHOWN_ROWS, SHOWN_BYTES_PER_ROW)), [found]);
  const [sealedRows, setSealedRows] = useState<string[]>(WIDE_ROWS);
  useEffect(() => {
    if (realRows === undefined) {
      setSealedRows(WIDE_ROWS);
      return;
    }
    if (mode === "pending") return;
    if (mode === "reduced") {
      setSealedRows(sealedRowsAt(realRows, SCRAMBLE_TOTAL_MS));
      return;
    }
    let frame = 0;
    const start = performance.now();
    let lastDraw = 0;
    const tick = (now: number) => {
      const elapsed = now - start;
      if (elapsed >= SCRAMBLE_TOTAL_MS) {
        setSealedRows(sealedRowsAt(realRows, SCRAMBLE_TOTAL_MS));
        return;
      }
      if (now - lastDraw >= 50) {
        lastDraw = now;
        setSealedRows(sealedRowsAt(realRows, elapsed));
      }
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [realRows, mode]);

  const packInfo = view.packInfo;
  const qor1 = view.account?.qor1;
  const boardId = challengeFacts?.[2] ?? board.id;
  // The line under the title is always there, so the rows never jump: the board before, the next pack once it is found.
  const sealedLine =
    found !== undefined
      ? `PACK ${packNumber(found.docId)} · EPOCH ${found.epoch.toString()} · ${found.size.toLocaleString("en-US")} BYTES`
      : `DEMO BOARD ${board.id}${board.epoch === null ? "" : ` · EPOCH ${formatCount(board.epoch)}`}`;

  return (
    <div className="demo-stage" aria-hidden="true">
      <div className="demo-stage-design">
        <div className="absolute" style={{ left: 24, top: 0, width: 460, height: 580 }}>
          <div className="how-pack relative h-full w-full">
            <PackSheets
              fixed
              liveLine={sealedLine}
              sealSize={132}
              seal={
                <div className="demo-fade" data-on={!sheetOn}>
                  <Seal
                    key={memberOn ? "member" : "start"}
                    size={132}
                    ringText={ring}
                    state={sealState}
                    onDone={() => setReformed(true)}
                  />
                </div>
              }
            >
              <CipherRows rows={sealedRows} />
            </PackSheets>
            <div className="pack-sheet demo-sheet p-10" data-on={sheetOn} style={{ background: "var(--sheet)" }}>
              <div className="mono flex justify-between text-[11px] tracking-[0.14em] text-ink-soft">
                {packInfo ? (
                  <>
                    <span>[ PACK {packNumber(packInfo.docId)} ]</span>
                    <span>[ EPOCH {packInfo.epoch.toString()} ]</span>
                  </>
                ) : (
                  <span>[ THE CHAIR IS POSTING THE NEXT PACK ]</span>
                )}
              </div>
              <div className={ROW_CLASS}>
                {rows.map((row, i) => (
                  <div
                    key={i}
                    className="h-[19px] overflow-hidden text-ellipsis"
                    style={row.readable ? { color: "rgba(22, 20, 28, 0.75)" } : undefined}
                  >
                    {row.text}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div
          data-on={keyCardOn}
          className="keycard paper mono absolute flex flex-col justify-between text-[10px] tracking-[0.12em]"
          style={{ left: 0, top: 396, width: 240, height: 150, padding: 18, borderRadius: 8 }}
        >
          <p className="text-ink-soft">[ YOUR ACCOUNT ]</p>
          <p className="font-mono text-[12px] tracking-normal text-ink normal-case">{qor1 ? shortQor1(qor1) : ""}</p>
          <p className="text-ink-soft">ML-DSA-87 · {stampsOn ? "ON CHAIN" : "MADE HERE"}</p>
          <p className="text-ink-soft">ML-KEM-1024 · {stampsOn ? "ON CHAIN" : "MADE HERE"}</p>
          <p data-on={sponsorOn} className="demo-fade text-ink-soft">
            {amount ? `${amount} · FROM THE SPONSOR` : "FROM THE SPONSOR"}
          </p>
        </div>

        {stampsOn ? (
          <>
            <div className="absolute" style={{ left: 220, top: 404, ...STAMP_INK }}>
              <Seal size={40} ringText={null} monogram="S" state="intact" />
            </div>
            <div className="absolute" style={{ left: 220, top: 456, ...STAMP_INK }}>
              <Seal size={40} ringText={null} monogram="K" state="intact" pressDelay={0.35} />
            </div>
          </>
        ) : null}

        <DemoSlip
          on={slipOn}
          rows={[`CHALLENGE · ${challengeFacts?.[1] ?? ""} BYTES`, "SIGNED · ML-DSA-87", `BOARD ${boardId}`]}
          place={{ left: 0, top: 556 }}
        />
        <DemoSlip
          on={leaveSlipOn}
          rows={[`LEAVE REQUEST · ${leaveFacts?.[1] ?? ""} BYTES`, "SIGNED · ML-DSA-87", `BOARD ${leaveFacts?.[2] ?? boardId}`]}
          place={{ left: 0, top: 556 }}
        />

        <div className="absolute flex gap-2" style={{ left: 24, top: 602 }}>
          <p data-on={(memberOn || gone) && !leaveSlipOn} className={`${TAG} text-ink-soft`}>
            {gone
              ? `REMOVED · EPOCH ${removal.epoch.toString()}`
              : `MEMBER${view.epoch === undefined ? "" : ` · EPOCH ${view.epoch.toString()}`}`}
          </p>
          <p data-on={shut !== undefined} className={`${TAG} flex items-center gap-1.5 text-ink`}>
            <Cross size={9} />
            LOCKED TO YOU
          </p>
        </div>
      </div>
    </div>
  );
}
