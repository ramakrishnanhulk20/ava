import type { Metadata } from "next";
import Link from "next/link";
import { Footer } from "../components/Footer";
import { Nav } from "../components/hero/Nav";
import { Seal } from "../components/hero/Seal";

export const metadata: Metadata = {
  title: "Not on the record · Ava",
};

const LINK = "link-draw mono text-[12px] tracking-[0.12em] text-ink";

export default function NotFound() {
  return (
    <main className="w-full overflow-x-clip">
      <div className="mx-auto w-full max-w-[1440px] px-5 pt-7 pb-24 sm:px-14">
        <Nav />

        <header className="grid items-end gap-12 pt-[120px] lg:grid-cols-[1fr_auto]">
          <div>
            <p className="mono flex items-center gap-2.5 text-[12px] tracking-[0.16em] text-ink-soft">
              <span className="size-2 rounded-full bg-accent" aria-hidden="true" />[ 404 · NOTHING AT THIS ADDRESS ]
            </p>
            <h1 className="display mt-6 max-w-[11em] text-[clamp(2.75rem,5.5vw,5.5rem)] leading-[0.98] tracking-[-0.02em] text-ink">
              This page is not on the record.
            </h1>
            <p className="mt-6 max-w-[46ch] text-[18px] leading-[1.6] text-ink-soft">
              Nothing was ever posted here. Every board and every pack Ava knows about is on the chain, and this address is not one of them.
            </p>
            <div className="mt-10 flex flex-wrap items-center gap-x-8 gap-y-4">
              <Link href="/" className="btn-primary">
                BACK TO THE START <span className="arrow" aria-hidden="true">→</span>
              </Link>
              <Link href="/board" className={LINK}>
                [ YOUR BOARD ROOM ]
              </Link>
              <Link href="/docs" className={LINK}>
                [ DOCS ]
              </Link>
            </div>
          </div>
          <div className="max-lg:hidden" aria-hidden="true">
            <Seal size={168} ringText="NOT ON THE RECORD · 404 ·" monogram="?" state="intact" />
          </div>
        </header>
      </div>
      <Footer />
    </main>
  );
}
