import type { ReactNode } from "react";
import { hexRows } from "../../lib/hexRows";

const SEED = "ava-board-pack";
export const WIDE_ROWS = hexRows(SEED, 9, 34);
export const NARROW_ROWS = hexRows(SEED, 7, 24);

export const ROW_CLASS = "font-mono mt-7 text-[10px] leading-[1.9] tracking-[0.06em] whitespace-nowrap text-ink/28";

type PackSheetsProps = {
  /** The pack's live line under the title. The "how it works" pack leaves it out. */
  liveLine?: string;
  /** The rows of ciphertext, or whatever stands in for them. */
  children: ReactNode;
  seal: ReactNode;
  sealSize: number;
  /** Draws the 460px design at every screen width, for packs that are scaled as a whole. */
  fixed?: boolean;
};

export function HexRows() {
  return (
    <>
      <div className={`${ROW_CLASS} hidden sm:block`}>
        {WIDE_ROWS.map((row, i) => (
          <div key={i}>{row}</div>
        ))}
      </div>
      <div className={`${ROW_CLASS} sm:hidden`}>
        {NARROW_ROWS.map((row, i) => (
          <div key={i}>{row}</div>
        ))}
      </div>
    </>
  );
}

export function PackSheets({ liveLine, children, seal, sealSize, fixed = false }: PackSheetsProps) {
  const padding = fixed ? "p-10" : "p-7 sm:p-10";
  const headerTracking = fixed ? "" : "max-sm:tracking-[0.06em]";
  const footerPlace = fixed ? "bottom-10 left-10" : "bottom-7 left-7 sm:bottom-10 sm:left-10";

  return (
    <>
      <div
        className="pack-sheet"
        style={{ background: "var(--sheet-2)", transform: "translate(18px, 14px) rotate(3deg)" }}
      />
      <div
        className="pack-sheet"
        style={{ background: "var(--sheet-1)", transform: "translate(9px, 7px) rotate(1.5deg)" }}
      />
      <div className={`pack-sheet ${padding}`} style={{ background: "var(--sheet)" }}>
        <div className={`mono flex justify-between text-[11px] tracking-[0.14em] text-ink-soft ${headerTracking}`}>
          <span>[ BOARD PACK ]</span>
          <span>[ CONFIDENTIAL ]</span>
        </div>
        <p className="display mt-7 text-[34px] leading-none text-ink">Board papers</p>
        {liveLine ? <p className="mono mt-2 text-[11px] tracking-[0.12em] text-ink-soft">{liveLine}</p> : null}
        {children}
        <p className={`mono absolute text-[10px] text-ink-soft ${footerPlace}`}>ML-KEM-1024 · AES-256-GCM</p>
        <div className="absolute" style={{ right: 34 - sealSize / 2, bottom: 34 - sealSize / 2 }}>
          {seal}
        </div>
      </div>
    </>
  );
}
