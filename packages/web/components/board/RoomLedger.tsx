"use client";

import { sameAccount } from "@ava/core";
import { useCallback, useMemo, useState } from "react";
import { buildProofModel, shortDate, shortHash, tenuresByMember, type Director, type PackInfo } from "../../lib/boardRules";
import { auditEnvelopes, type EnvelopeAudit, type Room } from "../../lib/chair/room";
import { formatCount } from "../../lib/chain";
import type { GuestAccount } from "../../lib/guest/identity";
import { Stopped } from "../../lib/guest/time";
import { Chip } from "../proof/Chip";
import { Cross, Tick } from "../proof/Glyphs";
import { StateLine } from "../proof/StateLine";
import { TxHash } from "../proof/TxHash";

const LABEL = "mono text-[11px] tracking-[0.14em] text-ink-soft";
const SMALL_BUTTON =
  "mono min-h-9 cursor-pointer rounded-lg border border-ink px-4 py-1.5 text-[12px] tracking-[0.12em] text-ink transition-colors duration-200 hover:bg-ink hover:text-on-ink disabled:cursor-not-allowed disabled:opacity-45";

type Audit = { state: "idle" } | { state: "running"; done: number; total: number } | { state: "done"; rows: EnvelopeAudit[] } | { state: "failed" };

function verdictLine(audit: EnvelopeAudit): { ok: boolean; text: string } {
  const v = audit.verdict;
  const who = audit.mode === 1 ? `${formatCount(audit.expected)} ${audit.expected === 1 ? "MEMBER" : "MEMBERS"} OF THE EPOCH` : "THE ONE MEMBER IT ADMITTED";
  switch (v.state) {
    case "clean":
      return { ok: true, text: `SEALED TO EXACTLY ${who}` };
    case "unknown_reader":
      return { ok: false, text: `${formatCount(v.unknown)} UNKNOWN ${v.unknown === 1 ? "READER" : "READERS"}: ${formatCount(v.recipients)} ENTRIES, ${formatCount(audit.expected)} EXPECTED` };
    case "left_out":
      return { ok: false, text: `NOT SEALED TO ${v.leftOut.map(shortHash).join(", ")}` };
    case "unverified":
      // Two things look the same from here: a reader who changed their key after the envelope was sealed, and a
      // reader left out with someone else's entry in their place. The line states what is seen and names both.
      return {
        ok: false,
        text: `UNVERIFIED: ${formatCount(v.unexplained)} OF ${formatCount(v.recipients)} ${v.recipients === 1 ? "ENTRY MATCHES" : "ENTRIES MATCH"} NO KEY ON CHAIN NOW, AND ${v.unmatched.map(shortHash).join(", ")} ${v.unmatched.length === 1 ? "HAS" : "HAVE"} NO ENTRY UNDER THE KEY THE CHAIN HOLDS. A KEY CHANGED SINCE, OR ANOTHER READER`,
      };
    case "unreadable":
      return { ok: false, text: "UNVERIFIED: THE STORED ENVELOPE COULD NOT BE READ AS THE RECORDED BYTES" };
  }
}

type RoomLedgerProps = {
  room: Room;
  me: GuestAccount;
  signal: () => AbortSignal | undefined;
};

/**
 * Who could open each pack, worked out from the board's own events (the epoch each pack was posted
 * in, and who held that epoch's key), and a check of every key envelope against the people it
 * should name (threat model C38, C39). A removed director's row shows what they kept as well as
 * what they lost.
 */
export function RoomLedger({ room, me, signal }: RoomLedgerProps) {
  const { snapshot, events } = room;
  const [audit, setAudit] = useState<Audit>({ state: "idle" });

  const packs: PackInfo[] = useMemo(() => room.packs.map((p) => ({ index: p.index, epoch: p.epoch, postedAt: p.postedAt })), [room.packs]);
  const model = useMemo(() => {
    const everyone = [...tenuresByMember(events).keys()];
    const directors: Director[] = everyone.map((address) => ({
      name: sameAccount(address, me.identity.evm) ? "You" : sameAccount(address, snapshot.chair) ? "The chair" : "A director",
      address: address as `0x${string}`,
    }));
    return buildProofModel(events, packs, directors, snapshot.chair);
  }, [events, me.identity.evm, packs, snapshot.chair]);

  const check = useCallback(() => {
    const live = signal();
    if (live === undefined) return;
    setAudit({ state: "running", done: 0, total: Number(snapshot.epoch) + 1 });
    void auditEnvelopes(room, live, (done, total) => {
      if (!live.aborted) setAudit({ state: "running", done, total });
    })
      .then((rows) => {
        if (!live.aborted) setAudit({ state: "done", rows });
      })
      .catch((error: unknown) => {
        if (error instanceof Stopped || live.aborted) return;
        setAudit({ state: "failed" });
      });
  }, [room, signal, snapshot.epoch]);

  const columns = `220px repeat(${Math.max(packs.length, 1)}, minmax(132px, 1fr))`;

  return (
    <section aria-labelledby="ledger-title">
      <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
        <h2 id="ledger-title" className={LABEL}>
          [ WHO CAN READ EACH PACK ]
        </h2>
        <p className={LABEL}>FROM THE REGISTRY&apos;S EVENTS · BLOCK {formatCount(snapshot.blockNumber)}</p>
      </div>

      {!room.complete ? (
        <p className="mt-6 max-w-[52ch] border-t border-rule pt-6 text-[17px] leading-[1.5] text-ink">
          Incomplete. The members this board&apos;s events add up to are not the registry&apos;s own member list at block {formatCount(snapshot.blockNumber)}, so no ledger is drawn from them.
        </p>
      ) : packs.length === 0 ? (
        <p className="mt-6 max-w-[48ch] border-t border-rule pt-6 text-[17px] leading-[1.5] text-ink">The ledger fills in with the first pack.</p>
      ) : (
        <div className="mt-6 overflow-x-auto">
          <div style={{ minWidth: 220 + packs.length * 132 }}>
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
            {model.rows.map((row) => (
              <div key={row.director.address} className="grid min-h-[84px] border-b border-rule" style={{ gridTemplateColumns: columns }}>
                <div className={`flex flex-col justify-center gap-1 border-l-2 pl-4 ${row.chip.kind === "removed" ? "border-ink" : "border-transparent"}`}>
                  <p className="text-[16px] leading-tight text-ink">{row.director.name}</p>
                  <p className="font-mono text-[11px] text-ink-soft">{shortHash(row.director.address)}</p>
                  <Chip chip={row.chip} />
                </div>
                {row.cells.map((cell, i) => (
                  <div key={packs[i]?.index ?? i} className="flex flex-col justify-center gap-2 px-4" style={cell.state === "locked" ? { background: "rgba(22, 20, 28, 0.04)" } : undefined}>
                    <StateLine state={cell.state} tickSize={14} />
                    <TxHash hash={cell.tx} className="font-mono text-[10px] text-ink-soft" />
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {room.complete ? (
        <div className="mt-8">
          {audit.state === "idle" || audit.state === "failed" ? (
            <>
              {audit.state === "failed" ? (
                <p className="mb-4 max-w-[52ch] text-[15px] leading-[1.5] text-ink">The check could not read every key or envelope, so it shows no result rather than a partial one.</p>
              ) : null}
              <button type="button" onClick={check} className={SMALL_BUTTON}>
                CHECK EVERY KEY ENVELOPE
              </button>
              <p className={`${LABEL} mt-3.5 max-w-[60ch] leading-[1.7]`}>
                THE TABLE ABOVE COMES FROM EVENTS. THIS DOWNLOADS EVERY ENVELOPE THE BOARD HAS RECORDED AND COUNTS ITS ENTRIES AGAINST THE PEOPLE IT SHOULD NAME, SO AN EXTRA READER CANNOT HIDE.
              </p>
            </>
          ) : audit.state === "running" ? (
            <div className="max-w-[560px]" aria-live="polite">
              <div className="demo-track" />
              <p className={`${LABEL} mt-2`}>
                CHECKING THE ENVELOPES · EPOCH {formatCount(audit.done)} OF {formatCount(audit.total)}
              </p>
            </div>
          ) : (
            <ul className="flex flex-col gap-2" aria-live="polite">
              {audit.rows.map((row, i) => {
                const line = verdictLine(row);
                return (
                  <li key={i} className="mono flex items-start gap-2.5 text-[11px] leading-[1.6] tracking-[0.12em] text-ink">
                    <span className="mt-[3px]">{line.ok ? <Tick size={13} /> : <Cross size={11} />}</span>
                    <span>
                      <span className="text-ink-soft">EPOCH {formatCount(row.epoch)} · </span>
                      {line.text}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      ) : null}
    </section>
  );
}
