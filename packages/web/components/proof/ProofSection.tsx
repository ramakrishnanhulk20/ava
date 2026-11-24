"use client";

import { useEffect, useState } from "react";
import { useBoardHistory } from "../../lib/boardHistory";
import { formatCount } from "../../lib/chain";
import { TxHash } from "./TxHash";
import { ProofCards } from "./ProofCards";
import { ProofTable } from "./ProofTable";

// Counts the seconds toward the next retry, and only ticks while a retry is pending.
function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [active]);
  return now;
}

export function ProofSection() {
  const history = useBoardHistory();
  const [explainOpen, setExplainOpen] = useState(false);
  const now = useNow(history.retryAt !== null);

  const { model } = history;
  const proof = model?.proof ?? null;
  const loading = model === null;
  const retryIn = history.retryAt === null ? null : Math.max(0, Math.ceil((history.retryAt - now) / 1000));
  const progress = history.pagesTotal > 0 ? Math.round((history.pagesDone / history.pagesTotal) * 100) : 0;

  return (
    <section id="proof" className="relative mx-auto w-full max-w-[1440px] overflow-x-clip px-5 py-24 sm:px-14 lg:py-40">
      <div className="lg:grid lg:grid-cols-12 lg:gap-x-8">
        <div className="lg:col-span-7">
          <p className="mono flex items-center gap-2.5 text-[12px] tracking-[0.16em] text-ink-soft">
            <span className="size-2 rounded-full bg-accent" aria-hidden="true" />[ THE PROOF ]
          </p>
          <h2 className="display mt-6 max-w-[13em] text-[clamp(2.5rem,4.8vw,4.75rem)] leading-none tracking-[-0.02em] text-ink">
            Ask the chain who can read what.
          </h2>
          <p className="mt-6 max-w-[44ch] text-[18px] leading-[1.6] text-ink-soft">
            Every cell below is read from QoreChain as you look at it: who held the key to each board pack, and the
            transaction that gave it or took it away. This is the demo board you can join.
          </p>
        </div>
      </div>

      <div className="mt-24 lg:grid lg:grid-cols-12 lg:items-baseline lg:gap-x-8">
        <div className="lg:col-span-5">
          <p
            className={`display text-[clamp(7rem,15vw,14rem)] leading-[0.85] tracking-[-0.04em] ${proof ? "text-ink" : "text-ink-soft"}`}
          >
            {proof ? formatCount(proof.opened) : "…"}
          </p>
        </div>
        <div className="mt-8 lg:col-span-7 lg:col-start-6 lg:mt-0">
          <p className="mono max-w-[30ch] text-[13px] tracking-[0.14em] text-ink">
            PACKS A REMOVED DIRECTOR COULD OPEN AFTER THEIR REMOVAL
          </p>
          <p className="mt-4 max-w-[40ch] text-[16px] leading-[1.6] text-ink-soft">
            {proof ? formatCount(proof.kept) : "…"} packs they could open before it, which they keep. Removal is not a
            recall, and Ava says so.
          </p>
          {proof?.removal ? (
            <p className="mono mt-3 flex flex-wrap items-center gap-2 text-[11px] tracking-[0.12em] text-ink-soft">
              REMOVAL · <TxHash hash={proof.removal.tx} className="font-mono" />
            </p>
          ) : null}
        </div>
      </div>

      <div className="mt-[72px]">
        <div className="hidden lg:block">
          <ProofTable history={history} />
        </div>
        <div className="lg:hidden">
          <ProofCards history={history} />
        </div>

        {loading ? (
          <div className="mt-6">
            <p className="mono text-[11px] tracking-[0.12em] text-ink-soft">
              READING BOARD {history.boardId} FROM QORECHAIN
              {history.pagesTotal > 0 ? ` · ${history.pagesDone} OF ${history.pagesTotal}` : ""}
            </p>
            <div
              className="mt-3 h-px bg-ink transition-[width] duration-300 ease-out"
              style={{ width: `${progress}%` }}
            />
          </div>
        ) : null}

        {retryIn !== null ? (
          <p className="mono mt-4 text-[11px] tracking-[0.12em] text-ink">
            THE TESTNET IS NOT ANSWERING · RETRYING IN {retryIn} S
          </p>
        ) : null}

        {!loading && history.lastBlock !== null && history.fromBlock !== null ? (
          <p className="mono mt-6 text-[11px] tracking-[0.12em] text-ink-soft">
            READ LIVE FROM DEMO BOARD {history.boardId} · BLOCK {formatCount(history.lastBlock)} ·{" "}
            {formatCount(history.events.length)} EVENTS SINCE BLOCK {formatCount(history.fromBlock)}
          </p>
        ) : null}
        <button
          type="button"
          aria-expanded={explainOpen}
          onClick={() => setExplainOpen((open) => !open)}
          className="link-draw mono mt-4 cursor-pointer text-[11px] tracking-[0.12em] text-ink-soft"
        >
          [ HOW THIS IS COMPUTED ]
        </button>
        <div
          className={`proof-explain grid transition-[grid-template-rows,opacity] duration-300 ease-out ${explainOpen ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0"}`}
          aria-hidden={!explainOpen}
        >
          <div className="overflow-hidden">
            <p className="mt-4 max-w-[60ch] text-[16px] leading-[1.6] text-ink-soft">
              A director holds the key for every epoch from the one they joined until the one their removal started. A
              pack is readable by whoever held the key for its epoch. Both come from the registry&apos;s MemberAdded,
              MemberRemoved and EnvelopeGranted events, read as you load this page; nothing here is stored or typed in.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
