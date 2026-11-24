"use client";

import { useEffect, useRef, useState } from "react";
import { shortHash } from "../../lib/boardRules";

type TxHashProps = {
  hash: string | null;
  className?: string;
  /** On the ink band the copy control lights up instead of going dark. */
  onInk?: boolean;
};

// The explorer opens a transaction by its Cosmos hash, and the registry's events carry the EVM hash, so
// the explorer answers "not found" for every hash here. Until it takes EVM hashes the hash is copied, not linked.
export function TxHash({ hash, className = "", onInk = false }: TxHashProps) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => () => clearTimeout(timer.current), []);

  if (!hash) return <span className={className}>…</span>;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access can be refused; the full hash is still in the title for selecting by hand.
    }
  };

  return (
    <span className={`inline-flex items-center gap-2 ${className}`}>
      <span title={hash} className="normal-case">
        {shortHash(hash)}
      </span>
      <button
        type="button"
        onClick={copy}
        aria-label={`Copy transaction hash ${hash}`}
        className={`link-draw mono cursor-pointer text-[10px] tracking-[0.12em] ${onInk ? "text-[rgba(247,244,242,0.6)] hover:text-on-ink focus-visible:text-on-ink" : ""}`}
      >
        {copied ? "COPIED" : "COPY"}
      </button>
    </span>
  );
}
