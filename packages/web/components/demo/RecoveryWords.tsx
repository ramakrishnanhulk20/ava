"use client";

import { useState } from "react";

/**
 * Shows the recovery words only while the guest has asked to see them. They come from the open
 * session in memory, never from storage, where they exist only as ciphertext (threat model C18).
 */
export function RecoveryWords({ words }: { words: readonly string[] }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="mt-10">
      {open ? (
        <div>
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="link-draw mono cursor-pointer text-[12px] tracking-[0.12em] text-ink"
          >
            [ HIDE ]
          </button>
          <div className="mt-4 max-w-[520px] rounded-lg border border-rule bg-sheet p-5">
            <ol className="grid grid-cols-2 gap-x-4 gap-y-2 font-mono text-[13px] text-ink sm:grid-cols-4">
              {words.map((word, i) => (
                <li key={i}>
                  <span className="text-ink-soft">{String(i + 1).padStart(2, "0")}</span> {word}
                </li>
              ))}
            </ol>
            <p className="mt-4 text-[14px] leading-[1.5] text-ink-soft">
              Testnet only. Anyone with these words is you on this demo board.
            </p>
          </div>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="link-draw mono cursor-pointer text-[12px] tracking-[0.12em] text-ink"
        >
          [ SHOW MY RECOVERY WORDS ]
        </button>
      )}
    </div>
  );
}
