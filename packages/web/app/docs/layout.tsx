import { CSPProvider } from "@base-ui/react/csp-provider";
import { DocsLayout } from "fumadocs-ui/layouts/docs";
import { RootProvider } from "fumadocs-ui/provider/next";
import type { ReactNode } from "react";
import { baseOptions } from "@/lib/layout.shared";
import { source } from "@/lib/source";

// The docs keep the site in its one light theme, so the theme switch and its inline script are off.
// The sidebar's scroll area would write a <style> element of its own, which the page's policy refuses
// (threat model C19). It is switched off here and its one rule lives in globals.css.
export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="docs-root flex min-h-screen flex-col">
      <CSPProvider disableStyleElements>
        <RootProvider theme={{ enabled: false }}>
          <DocsLayout tree={source.getPageTree()} {...baseOptions()}>
            {children}
          </DocsLayout>
        </RootProvider>
      </CSPProvider>
    </div>
  );
}
