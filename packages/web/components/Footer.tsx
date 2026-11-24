"use client";

import { usePathname } from "next/navigation";
import type { MouseEvent } from "react";
import { formatCount, useDemoBoard } from "../lib/chain";
import { liveText } from "../lib/drillAccount";
import { scrollToTarget } from "../lib/smoothScroll";

const REPO = "https://github.com/ramakrishnanhulk20/ava";

type FooterLink = { label: string; href: string; external: boolean };

const LINKS: FooterLink[] = [
  { label: "[ HOW IT WORKS ]", href: "/#how", external: false },
  { label: "[ WHO CAN READ ]", href: "/#proof", external: false },
  { label: "[ THE DEMO BOARD ]", href: "/demo", external: false },
  { label: "[ YOUR BOARD ROOM ]", href: "/board", external: false },
  { label: "[ ATTACK IT ]", href: "/proof", external: false },
  { label: "[ DOCS ]", href: "/docs", external: false },
  { label: "[ GITHUB ]", href: REPO, external: true },
  { label: "[ THREAT MODEL ]", href: `${REPO}/blob/main/docs/security/threat-model.md`, external: true },
  { label: "[ SECURITY TESTS ]", href: `${REPO}/tree/main/security`, external: true },
];

export function Footer() {
  const board = useDemoBoard();
  const failing = board.status === "retrying" || board.status === "down";
  const block = liveText(board.block === null ? null : `BLOCK ${formatCount(board.block)}`, failing);

  const pathname = usePathname();
  // On the home page a link to one of its own sections glides there; from any other page it is an ordinary link home.
  const glide = (event: MouseEvent<HTMLAnchorElement>, href: string) => {
    if (pathname === "/" && href.startsWith("/#") && scrollToTarget(href.slice(1))) event.preventDefault();
  };

  return (
    <footer data-ink-surface className="w-full bg-ink px-5 pb-12 text-on-ink sm:px-14">
      <div className="mx-auto w-full max-w-[1440px] pt-24" style={{ borderTop: "1px solid rgba(247, 244, 242, 0.12)" }}>
        <div className="lg:flex lg:items-end lg:gap-12">
          <p className="display text-[clamp(6rem,16vw,15rem)] leading-[0.85] tracking-[-0.03em] text-on-ink">Ava</p>
          <p className="mt-6 max-w-[30ch] text-[16px] leading-[1.6] text-[rgba(247,244,242,0.72)] lg:mt-0 lg:pb-4">
            From the Tamil avai, the assembly where a council meets.
          </p>
        </div>

        <nav aria-label="Footer" className="mt-12">
          <ul className="flex flex-wrap gap-x-7 gap-y-3">
            {LINKS.map((link) => (
              <li key={link.label}>
                <a
                  href={link.href}
                  {...(link.external ? { target: "_blank", rel: "noopener" } : {})}
                  onClick={(event) => glide(event, link.href)}
                  className="link-draw mono text-[12px] tracking-[0.14em] text-[rgba(247,244,242,0.72)] hover:text-on-ink focus-visible:text-on-ink"
                >
                  {link.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>

        <div
          className="mono mt-16 flex flex-wrap justify-between gap-x-8 gap-y-2 text-[11px] tracking-[0.12em]"
          style={{ color: "rgba(247, 244, 242, 0.5)" }}
        >
          <p>BUILT FOR BUILD BEFORE Q-DAY · QORECHAIN TESTNET · MIT LICENCE</p>
          <p>{block}</p>
        </div>
      </div>
    </footer>
  );
}
