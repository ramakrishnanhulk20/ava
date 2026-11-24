"use client";

import { Mode, generateMnemonic } from "@ava/core";
import { useCallback, useEffect, useRef, useState } from "react";
import { addDirector, createBoard, openPack, postPack, removeDirector } from "../../lib/chair/board";
import { createGuest, guestFromPhrase, openGuest, storedGuest, type GuestAccount, type GuestSession, type StoredGuest } from "../../lib/guest/identity";
import { fundAndRegister, type OnboardSteps } from "../../lib/guest/onboard";
import { Stopped } from "../../lib/guest/time";

type Line = { at: string; label: string; text: string; hash?: string };

const seconds = (from: number): string => `${((performance.now() - from) / 1000).toFixed(1)} s`;
const decode = (bytes: Uint8Array): string => new TextDecoder("utf-8", { fatal: true }).decode(bytes);

/**
 * The chair's whole loop, with no design: one identity funds itself and registers its keys,
 * creates a board, posts a pack it encrypted here and opens it back; a second identity, made in
 * memory to stand in for a director on another device, is added, opens that pack, is removed, and
 * then cannot open the pack posted next. Every line is what a real call answered. A lab page,
 * never linked from the site.
 */
export function ChairSpike() {
  const [stored, setStored] = useState<StoredGuest>({ kind: "none" });
  const [passphrase, setPassphrase] = useState("");
  const [lines, setLines] = useState<Line[]>([]);
  const [running, setRunning] = useState(false);
  const run = useRef<AbortController | undefined>(undefined);

  useEffect(() => {
    setStored(storedGuest());
    return () => run.current?.abort();
  }, []);

  const start = useCallback(() => {
    run.current?.abort();
    const controller = new AbortController();
    run.current = controller;
    const { signal } = controller;
    const began = performance.now();
    setLines([]);
    setRunning(true);
    const say = (label: string, text: string, hash?: string) => {
      if (!signal.aborted) setLines((prior) => [...prior, { at: seconds(began), label, text, hash }]);
    };
    const onboarding = (who: string): OnboardSteps => ({
      start: () => undefined,
      update: (key, patch) => {
        if (patch.hash !== undefined) say(`${who} ${key}`, patch.detail ?? "transaction signed", patch.hash);
      },
      end: (key, state, detail) => say(`${who} ${key}`, `${state}: ${detail}`),
    });

    void (async () => {
      try {
        const held = storedGuest();
        let session: GuestSession;
        if (held.kind === "vault") session = await openGuest(passphrase);
        else if (held.kind === "none") session = await createGuest(passphrase);
        else throw new Error("This browser holds an identity this page cannot open. Forget it on /demo first.");
        setStored(storedGuest());
        const chair = session.guest;
        say("chair", `${session.resumed ? "Opened" : "Made"} ${chair.identity.qor1} (${chair.identity.evm}).`);
        await fundAndRegister(chair, signal, onboarding("chair"));

        const board = await createBoard(chair, signal, (line) => say("create", line.text, line.hash));
        const id = board.boardId;
        say("create", `Board ${id} exists, chaired by this account, in block ${board.block}. boardRef ${board.boardRef}.`, board.txHash);

        const first = `Ava chair loop. Board ${id}, pack 1. Written ${new Date().toISOString()} and encrypted in this browser.`;
        const pack1 = await postPack(chair, id, new TextEncoder().encode(first), signal, (line) => say("post 1", line.text, line.hash));
        say("post 1", `Pack ${pack1.docId + 1n} posted at epoch ${pack1.epoch} in block ${pack1.block}: ${pack1.cipherSize} bytes of ciphertext, SHA-256 ${pack1.cipherHash}.`, pack1.txHash);
        const chairReads1 = decode((await openPack(chair, id, pack1.docId, signal)).plaintext) === first;
        say("open", chairReads1 ? "The chair opened pack 1 back from the chain's record, byte for byte." : "MISMATCH: the chair did not get pack 1 back.");

        const director: GuestAccount = await guestFromPhrase(generateMnemonic());
        say("director", `Made ${director.identity.qor1} in memory, to stand in for a director on another device.`);
        await fundAndRegister(director, signal, onboarding("director"));

        const added = await addDirector(chair, id, director.identity.evm, Mode.SEAL_CURRENT, signal, (line) => say("add", line.text, line.hash));
        say("add", `The director is a member at epoch ${added.epoch}, block ${added.block}.`, added.txHash);
        const directorReads1 = decode((await openPack(director, id, pack1.docId, signal)).plaintext) === first;
        say("open", directorReads1 ? "The director opened pack 1 with their own keys." : "MISMATCH: the director did not get pack 1.");

        const removed = await removeDirector(chair, id, director.identity.evm, signal, (line) => say("remove", line.text, line.hash));
        say("remove", `The director is off the board; it moved to epoch ${removed.epoch} in block ${removed.block}.`, removed.txHash);

        const second = `Ava chair loop. Board ${id}, pack 2. Written ${new Date().toISOString()} after the removal.`;
        const pack2 = await postPack(chair, id, new TextEncoder().encode(second), signal, (line) => say("post 2", line.text, line.hash));
        say("post 2", `Pack ${pack2.docId + 1n} posted at epoch ${pack2.epoch} in block ${pack2.block}.`, pack2.txHash);

        let shut = false;
        let why = "it opened";
        try {
          await openPack(director, id, pack2.docId, signal);
        } catch (error) {
          why = error instanceof Error ? error.message : "an error";
          shut = /No envelope of epoch \d+ is sealed to this guest/.test(why);
        }
        say("shut", shut ? `The removed director could not open pack 2: ${why}` : `FAILED: the removed director's try at pack 2 ended another way: ${why}`);
        const kept = decode((await openPack(director, id, pack1.docId, signal)).plaintext) === first;
        say("kept", kept ? "The removed director still opens pack 1, which they could already read." : "MISMATCH: the removed director lost pack 1.");
        const chairReads2 = decode((await openPack(chair, id, pack2.docId, signal)).plaintext) === second;
        say("open", chairReads2 ? "The chair opened pack 2." : "MISMATCH: the chair did not get pack 2 back.");

        const passed = chairReads1 && directorReads1 && shut && kept && chairReads2;
        say("done", passed ? "The chair loop passed." : "The chair loop FAILED.");
      } catch (error) {
        if (error instanceof Stopped || signal.aborted) return;
        say("failed", error instanceof Error ? error.message : "Something failed.");
      } finally {
        if (run.current === controller) setRunning(false);
      }
    })();
  }, [passphrase]);

  return (
    <main className="mx-auto w-full max-w-[960px] px-5 py-16 sm:px-14">
      <p className="mono text-[12px] tracking-[0.16em] text-ink-soft">[ LAB · THE CHAIR&apos;S LOOP · LIVE ON TESTNET ]</p>
      <h1 className="display mt-4 text-[40px] leading-none text-ink">Create a board, post, add, remove, post again.</h1>
      <p className="mt-4 max-w-[60ch] text-[16px] leading-[1.6] text-ink-soft">
        {stored.kind === "vault"
          ? `This browser holds ${stored.qor1}. Type its passphrase to run as that identity.`
          : "No identity in this browser yet. Choose a passphrase of ten characters or more to make one."}
      </p>
      <form
        className="mt-6 flex flex-wrap items-center gap-4"
        onSubmit={(event) => {
          event.preventDefault();
          start();
        }}
      >
        <input
          type="password"
          value={passphrase}
          onChange={(event) => setPassphrase(event.target.value)}
          aria-label="Passphrase"
          autoComplete="off"
          className="field h-[52px] w-[320px] max-w-full"
        />
        <button type="submit" disabled={running || passphrase.length < 10} className="btn-primary cursor-pointer">
          {running ? "Running" : "Run the chair loop"}
        </button>
      </form>
      <ol className="mt-10 flex flex-col gap-2">
        {lines.map((line, i) => (
          <li key={i} data-label={line.label} className="grid grid-cols-[64px_120px_1fr] gap-x-3 text-[13px] leading-[1.5]">
            <span className="mono text-ink-soft">{line.at}</span>
            <span className="mono text-ink-soft">{line.label}</span>
            <span className="min-w-0 break-words text-ink">
              {line.text}
              {line.hash ? <span className="block font-mono text-[11px] text-ink-soft">{line.hash}</span> : null}
            </span>
          </li>
        ))}
      </ol>
    </main>
  );
}
