"use client";

import { Seal } from "../hero/Seal";
import { SealedPack } from "../hero/SealedPack";

const MARKS = ["ML-DSA-87 SIGNED", "ML-KEM-1024 SEALED", "ON QORECHAIN"];

/**
 * The project's cover and social card, drawn from the hero's own parts so it is the same seal, the
 * same paper and the same type as the site. Every size is in viewport units, so one page gives a
 * 16:9 cover at 1600 by 900 and a card at 1200 by 630. It is captured from the dev server, never linked.
 */
export function CoverPoster() {
  return (
    <main data-hero className="relative h-svh w-full overflow-hidden">
      <div className="absolute inset-0 grid grid-cols-12 items-center gap-x-[2vw] px-[5.5vw]">
        <div className="col-span-7">
          <div className="flex items-center gap-[0.9vw] text-ink">
            <Seal size={34} ringText={null} state="reformed" />
            <span className="display text-[2.6vw] leading-none">Ava</span>
          </div>
          <p className="mono mt-[4.2vw] flex items-center gap-[0.7vw] text-[0.95vw] tracking-[0.16em] text-ink-soft">
            <span className="size-[0.6vw] rounded-full bg-accent" aria-hidden="true" />[ POST-QUANTUM BOARD ROOM ]
          </p>
          <h1 className="display mt-[1.8vw] max-w-[8.4em] text-[6.6vw] leading-[0.94] tracking-[-0.025em] text-balance text-ink">
            Seal the board pack. <span className="text-accent">Lock out</span> whoever leaves.
          </h1>
          <p className="mt-[2.2vw] max-w-[30ch] text-[1.55vw] leading-[1.45] text-ink-soft">Board papers your directors open today and nobody opens on Q-Day.</p>
          <ul className="mt-[3.4vw] flex items-center gap-x-[1.4vw]">
            {MARKS.map((mark) => (
              <li key={mark} className="trust-item mono text-[0.85vw] tracking-[0.14em] text-ink-soft">
                {mark}
              </li>
            ))}
          </ul>
        </div>
        <div className="col-span-5">
          <div className="origin-center scale-[1.18]">
            <SealedPack sealState="reformed" />
          </div>
        </div>
      </div>
      <p className="mono absolute right-[5.5vw] bottom-[3.2vw] text-[0.85vw] tracking-[0.14em] text-ink-soft">[ BUILD BEFORE Q-DAY · ENCRYPTED APPS ]</p>
    </main>
  );
}
