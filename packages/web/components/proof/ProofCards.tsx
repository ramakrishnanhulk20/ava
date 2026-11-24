import type { BoardHistory } from "../../lib/boardHistory";
import { shortDate, shortHash } from "../../lib/boardRules";
import { Chip } from "./Chip";
import { StateLine } from "./StateLine";
import { TxHash } from "./TxHash";

const CARD = "rounded-lg border border-rule p-5";
const CARD_BACKGROUND = { background: "rgba(251, 249, 246, 0.6)" };

type ProofCardsProps = {
  history: BoardHistory;
};

export function ProofCards({ history }: ProofCardsProps) {
  const { packs, model, directors } = history;

  if (!model) {
    return (
      <div className="flex flex-col gap-4">
        {directors.map((director) => (
          <div key={director.address} className={CARD} style={CARD_BACKGROUND}>
            <p className="text-[17px] leading-tight text-ink">{director.name}</p>
            <p className="mt-1 font-mono text-[11px] text-ink-soft">{shortHash(director.address)}</p>
            <div className="mt-5 h-2 w-2/5 rounded-[2px]" style={{ background: "rgba(22, 20, 28, 0.06)" }} />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {model.rows.map((row) => (
        <div key={row.director.address} className={CARD} style={CARD_BACKGROUND}>
          <div className="flex flex-col items-start gap-1">
            <p className="text-[17px] leading-tight text-ink">{row.director.name}</p>
            <p className="font-mono text-[11px] text-ink-soft">{shortHash(row.director.address)}</p>
            <Chip chip={row.chip} />
          </div>
          <ul className="mt-4 flex flex-col">
            {row.cells.map((cell, i) => {
              const pack = packs[i];
              return (
                <li key={pack?.index ?? i} className="flex items-start justify-between gap-4 border-t border-rule py-3">
                  <p className="mono text-[11px] tracking-[0.12em] text-ink-soft">
                    PACK {(pack?.index ?? i) + 1} · EPOCH {pack?.epoch}
                    <span className="mt-1 block">{pack ? shortDate(pack.postedAt) : null}</span>
                  </p>
                  <div className="flex flex-col items-end gap-1.5">
                    <StateLine state={cell.state} tickSize={14} />
                    <TxHash hash={cell.tx} className="font-mono text-[10px] text-ink-soft" />
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
      <div className={CARD} style={CARD_BACKGROUND}>
        <p className="text-[17px] leading-tight text-ink">Guests</p>
        <p className="mono mt-1 text-[11px] text-ink-soft">
          {model.guests.now} NOW · {model.guests.ever} SINCE THE BOARD BEGAN
        </p>
        <ul className="mt-4 flex flex-col">
          {model.guests.perPack.map((count, i) => (
            <li
              key={packs[i]?.index ?? i}
              className="flex items-center justify-between gap-4 border-t border-rule py-3"
            >
              <p className="mono text-[11px] tracking-[0.12em] text-ink-soft">
                PACK {(packs[i]?.index ?? i) + 1} · EPOCH {packs[i]?.epoch}
              </p>
              <p className="mono text-[11px] tracking-[0.12em] text-ink-soft">{count} COULD OPEN</p>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
