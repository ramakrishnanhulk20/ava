"use client";

import { useId, useState, type FormEvent } from "react";
import { shortQor1 } from "../../lib/drillAccount";
import type { StoredGuest } from "../../lib/guest/identity";
import { MIN_PASSPHRASE_LENGTH, passphraseLongEnough } from "../../lib/guest/vault";

export type StartWork = "making" | "opening";

type StartBlockProps = {
  stored: StoredGuest;
  /** Set while the keys are being made or the vault opened; both take a moment on purpose. */
  busy: StartWork | undefined;
  /** Why the last try did not start, in words the guest can act on. */
  problem: string | undefined;
  note: string | undefined;
  onCreate: (passphrase: string) => void;
  onReopen: (passphrase: string) => void;
  onProtect: (passphrase: string) => void;
  onForget: () => void;
  /** The button for a browser with no identity yet; the demo's own when left out. */
  createLabel?: string;
  /** The line under that button; the demo's own when left out. */
  createHint?: string;
  /** Given where an identity can be brought back from its recovery words; the form then offers it to a browser that holds none. */
  onRestore?: (phrase: string, passphrase: string) => void;
};

const COPY = {
  none: { label: "CHOOSE A PASSPHRASE", button: "MAKE MY IDENTITY AND JOIN", busy: "MAKING YOUR KEYS" },
  unprotected: { label: "CHOOSE A PASSPHRASE", button: "LOCK IT AND CONTINUE", busy: "LOCKING YOUR KEYS" },
  vault: { label: "YOUR PASSPHRASE", button: "OPEN IT AND CONTINUE", busy: "OPENING" },
} as const;

const QUIET_BUTTON = "link-draw mono cursor-pointer text-[12px] tracking-[0.12em]";

// Forgetting deletes the only copy of the identity this browser holds, so it takes a second, deliberate press.
function ForgetButton({ onForget }: { onForget: () => void }) {
  const [asking, setAsking] = useState(false);
  if (!asking) {
    return (
      <button type="button" onClick={() => setAsking(true)} className={`${QUIET_BUTTON} text-ink`}>
        [ FORGET ME ]
      </button>
    );
  }
  return (
    <span role="group" aria-label="Forget this identity" className="flex basis-full flex-wrap items-center gap-x-6 gap-y-2">
      <span className="max-w-[44ch] text-[15px] leading-[1.5] text-ink-soft">Forget this identity? Only its 24 recovery words can bring it back.</span>
      <button type="button" onClick={onForget} className={`${QUIET_BUTTON} text-accent`}>
        [ YES, FORGET IT ]
      </button>
      <button type="button" onClick={() => setAsking(false)} className={`${QUIET_BUTTON} text-ink`}>
        [ KEEP IT ]
      </button>
    </span>
  );
}

export function StartBlock({ stored, busy, problem, note, onCreate, onReopen, onProtect, onForget, createLabel, createHint, onRestore }: StartBlockProps) {
  const [passphrase, setPassphrase] = useState("");
  const [shown, setShown] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [phrase, setPhrase] = useState("");
  const fieldId = useId();
  const helpId = useId();
  const wordsId = useId();

  if (stored.kind === "damaged") {
    return (
      <div className="mt-10">
        <p className="max-w-[48ch] text-[15px] leading-[1.5] text-ink-soft">
          This browser holds an identity record that cannot be read. Forget it to start again with a new one.
        </p>
        <div className="mt-4">
          <ForgetButton onForget={onForget} />
        </div>
        {note ? <p className="mt-4 max-w-[52ch] text-[15px] leading-[1.5] text-ink-soft">{note}</p> : null}
      </div>
    );
  }

  const bringingBack = restoring && stored.kind === "none" && onRestore !== undefined;
  const copy = bringingBack
    ? { label: "CHOOSE A PASSPHRASE FOR THIS BROWSER", button: "RESTORE MY IDENTITY", busy: "RESTORING YOUR KEYS" }
    : stored.kind === "none" && createLabel !== undefined
      ? { ...COPY.none, button: createLabel }
      : COPY[stored.kind];
  const choosing = stored.kind !== "vault";
  const wordCount = phrase.trim() === "" ? 0 : phrase.trim().split(/\s+/u).length;
  const ready = (choosing ? passphraseLongEnough(passphrase) : passphrase.length > 0) && (!bringingBack || wordCount === 24);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!ready || busy !== undefined) return;
    if (stored.kind === "vault") onReopen(passphrase);
    else if (stored.kind === "unprotected") onProtect(passphrase);
    else if (bringingBack) onRestore(phrase, passphrase);
    else onCreate(passphrase);
  };

  return (
    <form onSubmit={submit} className="mt-10 max-w-[440px]" noValidate>
      {stored.kind === "vault" ? (
        <p className="mono mb-5 text-[12px] tracking-[0.12em] text-ink">
          WELCOME BACK · <span className="normal-case">{shortQor1(stored.qor1)}</span>
        </p>
      ) : null}
      {stored.kind === "unprotected" ? (
        <p className="mb-5 max-w-[46ch] text-[15px] leading-[1.5] text-ink-soft">
          This browser holds an identity from an earlier visit that has no passphrase yet. Choose one to lock it.
        </p>
      ) : null}

      {bringingBack ? (
        <div className="mb-5">
          <label htmlFor={wordsId} className="mono block text-[11px] tracking-[0.14em] text-ink-soft">
            YOUR 24 RECOVERY WORDS
          </label>
          <textarea
            id={wordsId}
            className="field mt-2"
            style={{ height: "auto", padding: "12px 16px", lineHeight: 1.5, resize: "vertical" }}
            rows={4}
            value={phrase}
            onChange={(event) => setPhrase(event.target.value)}
            disabled={busy !== undefined}
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="none"
            autoCorrect="off"
          />
          <p className="mt-2.5 text-[14px] leading-[1.5] text-ink-soft">
            {wordCount === 24 ? "24 words." : `${wordCount} of 24 words.`} They are read on this device only, and locked here with the passphrase below.
          </p>
        </div>
      ) : null}

      {/* Lets a password manager file the passphrase under a name instead of an empty one. */}
      <input type="text" name="username" autoComplete="username" value="Ava board identity" readOnly hidden />
      <label htmlFor={fieldId} className="mono block text-[11px] tracking-[0.14em] text-ink-soft">
        {copy.label}
      </label>
      <div className="relative mt-2">
        <input
          id={fieldId}
          name="passphrase"
          type={shown ? "text" : "password"}
          className="field"
          value={passphrase}
          onChange={(event) => setPassphrase(event.target.value)}
          autoComplete={choosing ? "new-password" : "current-password"}
          aria-describedby={helpId}
          aria-invalid={problem !== undefined}
          disabled={busy !== undefined}
          spellCheck={false}
          autoCapitalize="none"
          autoCorrect="off"
        />
        <button
          type="button"
          onClick={() => setShown((now) => !now)}
          aria-pressed={shown}
          className="link-draw mono absolute top-1/2 right-4 -translate-y-1/2 cursor-pointer text-[11px] tracking-[0.12em] text-ink-soft"
        >
          {shown ? "HIDE" : "SHOW"}
        </button>
      </div>
      <p id={helpId} className="mt-2.5 text-[14px] leading-[1.5] text-ink-soft">
        {choosing
          ? `${MIN_PASSPHRASE_LENGTH} characters or more. It locks your recovery words in this browser. We never see it, and nobody can reset it.`
          : "The one you chose when you made this identity. It never leaves this browser."}
      </p>
      {problem ? (
        <p role="alert" className="mt-3 text-[15px] leading-[1.5] text-ink">
          {problem}
        </p>
      ) : null}

      <div className="mt-6 flex flex-wrap items-center gap-6">
        <button type="submit" disabled={!ready || busy !== undefined} className="btn-primary max-sm:w-full max-sm:justify-center">
          {busy === undefined ? (
            <>
              {copy.button} <span className="arrow">→</span>
            </>
          ) : (
            copy.busy
          )}
        </button>
        {stored.kind === "none" ? null : <ForgetButton onForget={onForget} />}
        {stored.kind === "none" && onRestore !== undefined && busy === undefined ? (
          <button type="button" onClick={() => setRestoring((now) => !now)} className="link-draw mono cursor-pointer text-[12px] tracking-[0.12em] text-ink">
            {restoring ? "[ MAKE A NEW IDENTITY INSTEAD ]" : "[ I HAVE RECOVERY WORDS ]"}
          </button>
        ) : null}
      </div>
      {stored.kind === "none" ? (
        <p className="mono mt-3.5 text-[11px] tracking-[0.12em] text-ink-soft">
          {createHint ?? "TESTNET ONLY · YOUR RECOVERY WORDS NEVER LEAVE THIS BROWSER · ABOUT THREE MINUTES"}
        </p>
      ) : null}
      {note ? <p className="mt-4 max-w-[52ch] text-[15px] leading-[1.5] text-ink-soft">{note}</p> : null}
    </form>
  );
}
