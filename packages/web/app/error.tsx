"use client";

import Link from "next/link";

const LINK = "link-draw mono text-[12px] tracking-[0.12em] text-ink";

export default function PageError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="w-full overflow-x-clip">
      <div className="mx-auto w-full max-w-[1440px] px-5 pt-7 pb-24 sm:px-14">
        <Link href="/" className="link-draw display text-[26px] leading-none text-ink">
          Ava
        </Link>

        <header className="pt-[120px]">
          <p className="mono flex items-center gap-2.5 text-[12px] tracking-[0.16em] text-ink-soft">
            <span className="size-2 rounded-full bg-accent" aria-hidden="true" />[ THIS PAGE STOPPED ]
          </p>
          <h1 className="display mt-6 max-w-[11em] text-[clamp(2.75rem,5.5vw,5.5rem)] leading-[0.98] tracking-[-0.02em] text-ink">
            Something broke on this page.
          </h1>
          <p className="mt-6 max-w-[48ch] text-[18px] leading-[1.6] text-ink-soft">
            Your identity is still locked in this browser, and whatever already reached the chain is still there. Try the page again; if it stops a
            second time, start from the front page.
          </p>
          <div className="mt-10 flex flex-wrap items-center gap-x-8 gap-y-4">
            <button type="button" onClick={reset} className="btn-primary cursor-pointer">
              Try again <span className="arrow">→</span>
            </button>
            <Link href="/" className={LINK}>
              [ BACK TO THE START ]
            </Link>
          </div>
        </header>
      </div>
    </main>
  );
}
