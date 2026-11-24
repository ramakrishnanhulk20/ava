"use client";

import { useEffect, useRef, useState, type CSSProperties } from "react";
import { shortHash } from "../../lib/boardRules";
import { RecoveryWords } from "../demo/RecoveryWords";
import { Seal } from "../hero/Seal";

// A stamp is the seal drawn in ink. The seal reads the accent variables, so scoping them is enough.
const STAMP_INK = { "--accent": "var(--ink)", "--accent-deep": "#0b0a0f" } as CSSProperties;

function CopyButton({ text, what }: { text: string; what: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access can be refused; the address is on screen in full to select by hand.
    }
  };

  return (
    <button type="button" onClick={copy} aria-label={`Copy ${what}`} className="link-draw mono cursor-pointer text-[10px] tracking-[0.12em] text-ink-soft">
      {copied ? "COPIED" : "COPY"}
    </button>
  );
}

type IdentityCardProps = {
  account: { qor1: string; evm: string } | undefined;
  /** True once the chain shows both keys for this account. */
  keysOnChain: boolean;
  /** The recovery words of the open session, held in memory only. */
  words: readonly string[] | undefined;
};

/** The account this browser holds, as a card: the address a chair needs to add it, and where its two keys stand. */
export function IdentityCard({ account, keysOnChain, words }: IdentityCardProps) {
  return (
    <div className="relative">
      <div className="paper relative p-7 lg:rotate-[1.5deg]">
        <p className="mono text-[11px] tracking-[0.14em] text-ink-soft">[ YOUR ACCOUNT ]</p>
        {account === undefined ? (
          <p className="mt-4 font-mono text-[13px] text-ink-soft">…</p>
        ) : (
          <>
            <p className="mt-4 font-mono text-[13px] leading-[1.5] break-all text-ink">{account.qor1}</p>
            <p className="mt-1 flex items-center gap-3">
              <span className="font-mono text-[12px] text-ink-soft" title={account.evm}>
                {shortHash(account.evm)}
              </span>
              <CopyButton text={account.qor1} what="your address" />
            </p>
          </>
        )}
        <div className="mono mt-6 flex flex-col gap-2 border-t border-rule pt-5 text-[11px] tracking-[0.12em] text-ink-soft">
          <p>SIGNING KEY · ML-DSA-87 · {keysOnChain ? "ON CHAIN, POSSESSION PROVEN" : "NOT ON CHAIN YET"}</p>
          <p>SEALING KEY · ML-KEM-1024 · {keysOnChain ? "ON CHAIN" : "NOT ON CHAIN YET"}</p>
        </div>
        <p className="mt-5 max-w-[34ch] text-[15px] leading-[1.5] text-ink-soft">
          A chair adds you to a board with this address. Send it to them; it is not a secret.
        </p>
        {keysOnChain ? (
          <div className="absolute -top-4 -right-3 flex gap-2" style={STAMP_INK} aria-hidden="true">
            <Seal size={40} ringText={null} monogram="S" state="intact" />
            <Seal size={40} ringText={null} monogram="K" state="intact" pressDelay={0.35} />
          </div>
        ) : null}
      </div>
      {words !== undefined ? <RecoveryWords words={words} /> : null}
    </div>
  );
}
