"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { MouseEvent } from "react";
import { scrollToTarget } from "../../lib/smoothScroll";
import { Seal } from "./Seal";

const LINK = "link-draw mono text-[12px] tracking-[0.12em] text-ink-soft";

export function Nav() {
  const pathname = usePathname();
  // Only the home page has the section to glide to; from anywhere else the link goes home first.
  const glideToHow = (event: MouseEvent<HTMLAnchorElement>) => {
    if (pathname === "/" && scrollToTarget("#how")) event.preventDefault();
  };

  return (
    <nav aria-label="Main" className="flex items-center justify-between">
      <Link href="/" className="link-draw flex items-center gap-[10px] text-ink">
        <Seal size={22} ringText={null} state="reformed" />
        <span className="display text-[26px] leading-none">Ava</span>
      </Link>
      <ul className="flex items-center gap-7">
        <li className="max-sm:hidden">
          <a href="/#how" onClick={glideToHow} className={LINK}>
            [ HOW IT WORKS ]
          </a>
        </li>
        <li className="max-sm:hidden">
          <Link href="/board" className={LINK}>
            [ BOARD ROOM ]
          </Link>
        </li>
        <li>
          <Link href="/docs" className={LINK}>
            [ DOCS ]
          </Link>
        </li>
        <li className="max-sm:hidden">
          <a href="https://github.com/ramakrishnanhulk20/ava" target="_blank" rel="noopener" className={LINK}>
            [ GITHUB ]
          </a>
        </li>
      </ul>
    </nav>
  );
}
