"use client";

import { motion } from "motion/react";
import type { BoardHistory } from "../../lib/boardHistory";
import { shortDate, shortHash } from "../../lib/boardRules";
import { Chip } from "./Chip";
import { StateLine } from "./StateLine";
import { TxHash } from "./TxHash";

const EASE: [number, number, number, number] = [0.2, 0.8, 0.2, 1];
const STAGGER = 0.06;
const BAR_BACKGROUND = { background: "rgba(22, 20, 28, 0.06)" };

type ProofTableProps = {
  history: BoardHistory;
};

function SkeletonRow({ columns, name, address }: { columns: string; name?: string; address?: string }) {
  return (
    <div className="grid h-[88px] items-center border-t border-rule" style={{ gridTemplateColumns: columns }}>
      <div className="flex flex-col justify-center gap-1 border-l-2 border-transparent pl-4">
        {name ? <p className="text-[17px] leading-tight text-ink">{name}</p> : null}
        {address ? <p className="font-mono text-[11px] text-ink-soft">{shortHash(address)}</p> : null}
      </div>
      <div className="col-start-2 col-end-[-1] px-4">
        <div className="h-2 w-2/5 rounded-[2px]" style={BAR_BACKGROUND} />
      </div>
    </div>
  );
}

function rowMotion(index: number) {
  return {
    initial: { opacity: 0, y: 12 },
    whileInView: { opacity: 1, y: 0 },
    viewport: { once: true },
    transition: { duration: 0.4, ease: EASE, delay: index * STAGGER },
  };
}

export function ProofTable({ history }: ProofTableProps) {
  const { packs, model, directors } = history;
  const columns = `260px repeat(${Math.max(packs.length, 1)}, minmax(120px, 1fr))`;

  return (
    <div className="overflow-x-auto">
      <div className="min-w-[640px]">
        <div className="grid items-end border-b border-rule pb-4" style={{ gridTemplateColumns: columns }}>
          <div />
          {packs.map((pack) => (
            <div key={pack.index} className="mono px-4 text-[11px] tracking-[0.14em]">
              <p className="text-ink">PACK {pack.index + 1}</p>
              <p className="mt-1 text-ink-soft">
                EPOCH {pack.epoch} · {shortDate(pack.postedAt)}
              </p>
            </div>
          ))}
        </div>

        {model ? (
          <>
            {model.rows.map((row, rowIndex) => (
              <motion.div
                key={row.director.address}
                className="proof-row grid h-[88px] border-t border-rule"
                style={{ gridTemplateColumns: columns }}
                {...rowMotion(rowIndex)}
              >
                <div
                  className={`flex flex-col justify-center gap-1 border-l-2 pl-4 ${row.chip.kind === "removed" ? "border-ink" : "border-transparent"}`}
                >
                  <p className="text-[17px] leading-tight text-ink">{row.director.name}</p>
                  <p className="font-mono text-[11px] text-ink-soft">{shortHash(row.director.address)}</p>
                  <Chip chip={row.chip} />
                </div>
                {row.cells.map((cell, i) => (
                  <div
                    key={packs[i]?.index ?? i}
                    className="flex flex-col justify-center gap-2 px-4"
                    style={cell.state === "locked" ? { background: "rgba(22, 20, 28, 0.04)" } : undefined}
                  >
                    <StateLine state={cell.state} tickSize={14} drawAfter={rowIndex * STAGGER + 0.4} />
                    <TxHash hash={cell.tx} className="font-mono text-[10px] text-ink-soft" />
                  </div>
                ))}
              </motion.div>
            ))}
            <motion.div
              className="proof-row grid min-h-[88px] border-t border-rule"
              style={{ gridTemplateColumns: columns }}
              {...rowMotion(model.rows.length)}
            >
              <div className="flex flex-col justify-center gap-1 border-l-2 border-transparent pl-4">
                <p className="text-[17px] leading-tight text-ink">Guests</p>
                <p className="mono text-[11px] text-ink-soft">
                  {model.guests.now} NOW · {model.guests.ever} SINCE THE BOARD BEGAN
                </p>
              </div>
              {model.guests.perPack.map((count, i) => (
                <div key={packs[i]?.index ?? i} className="mono flex items-center px-4 text-[11px] text-ink-soft">
                  {count} COULD OPEN
                </div>
              ))}
            </motion.div>
          </>
        ) : (
          <>
            {directors.map((director) => (
              <SkeletonRow key={director.address} columns={columns} name={director.name} address={director.address} />
            ))}
            <SkeletonRow columns={columns} />
          </>
        )}
      </div>
    </div>
  );
}
