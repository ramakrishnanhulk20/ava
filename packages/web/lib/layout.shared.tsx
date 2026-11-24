import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";

/** What every docs layout shares: the site name in the docs nav, and the way back to the product. */
export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <span className="flex items-baseline gap-2">
          <span className="display text-[24px] leading-none">Ava</span>
          <span className="mono text-[11px] tracking-[0.14em]">[ DOCS ]</span>
        </span>
      ),
      url: "/",
    },
    links: [
      { text: "The demo board", url: "/demo" },
      { text: "Your board room", url: "/board" },
      { text: "Attack it", url: "/proof" },
    ],
    githubUrl: "https://github.com/ramakrishnanhulk20/ava",
    // One light theme, like the rest of the site.
    themeSwitch: { enabled: false },
  };
}
