import Link from "next/link";
import { LiveProofLine } from "./LiveProofLine";
import { Nav } from "./Nav";
import { SealedPack } from "./SealedPack";
import type { SealState } from "./Seal";

type HeroProps = {
  sealState?: SealState;
  ringText?: string | null;
  onSealDone?: () => void;
  caption?: boolean;
};

const TRUST = ["ML-DSA-87 SIGNED", "ML-KEM-1024 SEALED", "ON QORECHAIN"];

export function Hero({ sealState, ringText, onSealDone, caption }: HeroProps = {}) {
  return (
    <section
      data-hero
      className="relative mx-auto flex min-h-svh w-full max-w-[1440px] flex-col overflow-x-clip px-5 pt-7 pb-14 sm:px-14"
    >
      <Nav />
      <div className="flex flex-1 items-center py-10">
        <div className="grid w-full grid-cols-1 items-center gap-x-8 lg:grid-cols-12">
          <div className="lg:col-span-7">
            <p className="mono flex items-center gap-2.5 text-[12px] tracking-[0.16em] text-ink-soft">
              <span className="size-2 rounded-full bg-accent" aria-hidden="true" />[ POST-QUANTUM BOARD ROOM ]
            </p>
            <h1 className="headline mt-7">
              Seal the board pack. <span className="text-accent">Lock out</span> whoever leaves.
            </h1>
            <p className="mt-7 max-w-[30ch] text-[20px] leading-[1.5] text-ink-soft">
              Board papers your directors open today and nobody opens on Q-Day.
            </p>
            <div className="mt-10 flex flex-wrap items-center gap-6">
              <Link href="/demo" className="btn-primary max-sm:w-full max-sm:justify-center">
                JOIN THE DEMO BOARD <span className="arrow">→</span>
              </Link>
              <Link href="/docs" className="link-draw mono text-[13px] tracking-[0.12em] text-ink">
                [ READ THE DOCS ]
              </Link>
            </div>
            <ul className="mt-14 flex flex-wrap items-center gap-x-4 gap-y-3 max-sm:gap-x-5">
              {TRUST.map((item) => (
                <li key={item} className="trust-item mono text-[11px] tracking-[0.14em] text-ink-soft">
                  {item}
                </li>
              ))}
            </ul>
            <LiveProofLine />
          </div>
          <div className="lg:col-span-5">
            <SealedPack sealState={sealState} ringText={ringText} onSealDone={onSealDone} caption={caption} />
          </div>
        </div>
      </div>
    </section>
  );
}
