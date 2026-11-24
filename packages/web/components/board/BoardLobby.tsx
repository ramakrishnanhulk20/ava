"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createBoard } from "../../lib/chair/board";
import { findBoards, mergeBoards, rememberBoards, rememberedBoards, type SeenBoards } from "../../lib/chair/myBoards";
import { summariseBoards, type BoardSummary } from "../../lib/chair/summary";
import { formatCount } from "../../lib/chain";
import { createGuest, forgetGuest, openGuest, protectStoredPhrase, restoreGuest, storedGuest, type GuestSession, type StoredGuest } from "../../lib/guest/identity";
import { initialView, type JourneyView } from "../../lib/guest/journey";
import { fundAndRegister } from "../../lib/guest/onboard";
import { trackOnboarding } from "../../lib/guest/onboardView";
import { heldSession, holdSession } from "../../lib/guest/session";
import { Stopped } from "../../lib/guest/time";
import { ChapterList, type ChapterAction } from "../demo/ChapterList";
import { chaptersOf, plainError, secondsBetween, type ChapterView } from "../demo/chapters";
import { StartBlock, type StartWork } from "../demo/StartBlock";
import { Footer } from "../Footer";
import { Nav } from "../hero/Nav";
import { Tick } from "../proof/Glyphs";
import { TxHash } from "../proof/TxHash";
import { IdentityCard } from "./IdentityCard";

const TICK_MS = 200;
const LABEL = "mono text-[11px] tracking-[0.14em] text-ink-soft";

type Phase = "locked" | "onboarding" | "ready";
type Reading = { state: "reading"; done: number; total: number } | { state: "ready"; block: bigint } | { state: "failed"; error: string };
type Creating = { state: "running" | "done" | "failed"; text: string; hash?: string; startedAt: number; endedAt?: number; boardId?: bigint };

const STANDING: Record<BoardSummary["standing"], string> = { chair: "YOU CHAIR", member: "YOU ARE A MEMBER", removed: "YOU WERE REMOVED" };

function plural(count: number, one: string, many: string): string {
  return `${formatCount(count)} ${count === 1 ? one : many}`;
}

function BoardRow({ board }: { board: BoardSummary }) {
  return (
    <li className="group border-t border-rule">
      <Link href={`/board/${board.boardId.toString()}`} className="flex items-center gap-5 py-5 sm:gap-7">
        <span className="display w-16 shrink-0 text-[40px] leading-none text-ink transition-colors duration-200 group-hover:text-accent" aria-hidden="true">
          {board.boardId.toString().padStart(2, "0")}
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
            <span className="text-[18px] leading-[1.35] text-ink">Board {board.boardId.toString()}</span>
            <span className="mono rounded-[4px] border border-rule px-2 py-[3px] text-[10px] tracking-[0.12em] text-ink-soft">{STANDING[board.standing]}</span>
          </span>
          <span className={`${LABEL} mt-1.5 block`}>
            EPOCH {formatCount(board.epoch)} · {plural(board.memberCount, "MEMBER", "MEMBERS")} · {plural(board.documentCount, "PACK", "PACKS")}
          </span>
          {board.standing === "chair" ? null : (
            // Anyone can name any address on a board of theirs, so a board someone else chairs says whose it is (threat model C21).
            <span className="mt-1 block font-mono text-[11px] break-all text-ink-soft">
              <span className="mono tracking-[0.14em]">CHAIRED BY</span> {board.chair}
            </span>
          )}
        </span>
        <span className="link-draw mono shrink-0 text-[12px] tracking-[0.12em] text-ink">[ OPEN ]</span>
      </Link>
    </li>
  );
}

/**
 * The chair's and the director's way in: open or make the identity this browser holds, put its two
 * keys on chain, then see every board the registry's own history names it in, and create one.
 * Nothing on this screen comes from our server's memory: the boards are read from the chain.
 */
export function BoardLobby() {
  const [stored, setStored] = useState<StoredGuest>({ kind: "none" });
  const [busy, setBusy] = useState<StartWork | undefined>(undefined);
  const [problem, setProblem] = useState<string | undefined>(undefined);
  const [note, setNote] = useState<string | undefined>(undefined);
  const [phase, setPhase] = useState<Phase>("locked");
  const [view, setView] = useState<JourneyView>(initialView);
  const [words, setWords] = useState<readonly string[] | undefined>(undefined);
  const [boards, setBoards] = useState<BoardSummary[]>([]);
  const [reading, setReading] = useState<Reading | undefined>(undefined);
  const [creating, setCreating] = useState<Creating | undefined>(undefined);
  const [now, setNow] = useState(0);
  const run = useRef<AbortController | undefined>(undefined);
  // The open identity lives here for this page view only; a reload asks for the passphrase again.
  const session = useRef<GuestSession | undefined>(undefined);

  useEffect(() => {
    setStored(storedGuest());
    return () => {
      run.current?.abort();
      session.current = undefined;
    };
  }, []);

  const ticking = phase === "onboarding" || creating?.state === "running";
  useEffect(() => {
    if (!ticking) return;
    setNow(performance.now());
    const timer = setInterval(() => setNow(performance.now()), TICK_MS);
    return () => clearInterval(timer);
  }, [ticking]);

  const showBoards = useCallback(async (seen: SeenBoards, evm: `0x${string}`, signal: AbortSignal) => {
    const list = await summariseBoards([...new Set([...seen.chaired, ...seen.joined])], evm);
    if (signal.aborted) return;
    setBoards(list.sort((a, b) => (a.boardId > b.boardId ? -1 : 1)));
    setReading({ state: "ready", block: list[0]?.blockNumber ?? seen.through });
  }, []);

  const loadBoards = useCallback(
    async (signal: AbortSignal) => {
      const evm = session.current?.guest.identity.evm;
      if (evm === undefined) return;
      try {
        const known = rememberedBoards(evm);
        setReading({ state: "reading", done: 0, total: 0 });
        const seen = await findBoards(evm, known, signal, (done, total) => {
          if (!signal.aborted) setReading({ state: "reading", done, total });
        });
        rememberBoards(evm, seen);
        await showBoards(seen, evm, signal);
      } catch (error) {
        if (error instanceof Stopped || signal.aborted) return;
        setReading({ state: "failed", error: "The registry's history could not be read in full, so no list is shown rather than a partial one." });
      }
    },
    [showBoards],
  );

  const begin = useCallback(
    (tookMs: number) => {
      const guest = session.current;
      if (guest === undefined) return;
      run.current?.abort();
      const controller = new AbortController();
      run.current = controller;
      const { signal } = controller;
      const tracker = trackOnboarding(setView, signal);
      tracker.identity({ qor1: guest.guest.identity.qor1, evm: guest.guest.identity.evm }, guest.resumed, tookMs);
      setPhase("onboarding");
      setNote(undefined);
      void (async () => {
        try {
          await fundAndRegister(guest.guest, signal, tracker);
          tracker.finish();
          if (signal.aborted) return;
          setPhase("ready");
          await loadBoards(signal);
        } catch (error) {
          if (error instanceof Stopped || signal.aborted) return;
          tracker.fail(error);
        }
      })();
    },
    [loadBoards],
  );

  // Coming from a board room in this same page view, the identity is already open: no passphrase is asked for twice.
  useEffect(() => {
    const held = heldSession();
    if (held === undefined || session.current !== undefined) return;
    session.current = held;
    setWords(held.words);
    begin(0);
  }, [begin]);

  // Making or opening the identity happens before anything else, so a wrong passphrase is answered at the field.
  const open = useCallback(
    (work: StartWork, obtain: (passphrase: string) => Promise<GuestSession>) => (passphrase: string) => {
      setBusy(work);
      setProblem(undefined);
      const began = performance.now();
      void obtain(passphrase)
        .then((guest) => {
          session.current = guest;
          holdSession(guest);
          setWords(guest.words);
          setStored(storedGuest());
          begin(performance.now() - began);
        })
        .catch((error: unknown) => setProblem(error instanceof Error ? error.message : "That did not work. Try again."))
        .finally(() => setBusy(undefined));
    },
    [begin],
  );
  const create = useMemo(() => open("making", (passphrase) => createGuest(passphrase)), [open]);
  const reopen = useMemo(() => open("opening", (passphrase) => openGuest(passphrase)), [open]);
  const protect = useMemo(() => open("making", (passphrase) => protectStoredPhrase(passphrase)), [open]);
  const restore = useCallback((phrase: string, passphrase: string) => open("making", (chosen) => restoreGuest(phrase, chosen))(passphrase), [open]);

  const forget = useCallback(() => {
    try {
      forgetGuest();
      setNote("This browser no longer holds your identity. Starting again makes a new one.");
    } catch (error) {
      setNote(error instanceof Error ? error.message : "The identity could not be removed.");
    }
    session.current = undefined;
    holdSession(undefined);
    setWords(undefined);
    setProblem(undefined);
    setStored(storedGuest());
  }, []);

  const createOne = useCallback(() => {
    const guest = session.current?.guest;
    const signal = run.current?.signal;
    if (guest === undefined || signal === undefined) return;
    const startedAt = performance.now();
    setCreating({ state: "running", text: "Starting.", startedAt });
    void createBoard(guest, signal, (line) => setCreating((prior) => (prior === undefined || prior.state !== "running" ? prior : { ...prior, text: line.text, hash: line.hash ?? prior.hash })))
      .then(async (made) => {
        if (signal.aborted) return;
        setCreating({ state: "done", text: `Board ${made.boardId.toString()} is on chain, in block ${formatCount(made.block)}.`, hash: made.txHash, startedAt, endedAt: performance.now(), boardId: made.boardId });
        const evm = guest.identity.evm;
        const seen = mergeBoards(rememberedBoards(evm), { through: 0n, chaired: [made.boardId], joined: [] });
        rememberBoards(evm, seen);
        await showBoards(seen, evm, signal);
      })
      .catch((error: unknown) => {
        if (error instanceof Stopped || signal.aborted) return;
        setCreating({ state: "failed", text: error instanceof Error ? error.message : "Something failed.", startedAt, endedAt: performance.now() });
      });
  }, [showBoards]);

  const chapters = useMemo(() => chaptersOf(view).slice(0, 3), [view]);
  const errors = useMemo(() => {
    const out: Partial<Record<ChapterView["id"], string>> = {};
    for (const chapter of chapters) if (chapter.state === "failed") out[chapter.id] = view.error;
    return out;
  }, [chapters, view.error]);
  const actionsFor = useCallback((): ChapterAction[] => [{ label: "TRY AGAIN", onClick: () => begin(0) }], [begin]);

  return (
    <main className="w-full overflow-x-clip">
      <div className="mx-auto w-full max-w-[1440px] px-5 pt-7 pb-24 sm:px-14">
        <Nav />

        <header className="pt-[120px]">
          <p className="mono flex items-center gap-2.5 text-[12px] tracking-[0.16em] text-ink-soft">
            <span className="size-2 rounded-full bg-accent" aria-hidden="true" />[ YOUR BOARD ROOM · QORECHAIN TESTNET ]
          </p>
          <h1 className="display mt-6 max-w-[12em] text-[clamp(2.75rem,5.5vw,5.5rem)] leading-[0.98] tracking-[-0.02em] text-ink">
            {phase === "ready" ? "Your boards." : "Seal a pack for your board."}
          </h1>
          <p className="mt-6 max-w-[50ch] text-[18px] leading-[1.6] text-ink-soft">
            {phase === "ready"
              ? "Every board below was found in the registry's own history for your account. We keep no list of who sits on which board."
              : "Create a board, add your directors, and post packs only they can open. Every change is signed on this device with ML-DSA-87 and checked on chain."}
          </p>
          {phase === "locked" ? (
            <StartBlock
              stored={stored}
              busy={busy}
              problem={problem}
              note={note}
              onCreate={create}
              onReopen={reopen}
              onProtect={protect}
              onForget={forget}
              createLabel="MAKE MY IDENTITY"
              createHint="TESTNET ONLY · YOUR RECOVERY WORDS NEVER LEAVE THIS BROWSER · ABOUT A MINUTE"
              onRestore={restore}
            />
          ) : null}
        </header>

        {phase === "locked" ? null : (
          <section className="mt-[72px] lg:grid lg:grid-cols-12 lg:gap-x-8">
            <div className="lg:col-span-7">
              {phase === "onboarding" ? (
                <ChapterList chapters={chapters} now={now} errors={errors} actionsFor={actionsFor} />
              ) : (
                <>
                  <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
                    <p className={LABEL}>[ BOARDS THAT NAME THIS ACCOUNT ]</p>
                    <p className={LABEL} aria-live="polite">
                      {reading?.state === "reading"
                        ? reading.total === 0
                          ? "READING THE REGISTRY'S HISTORY"
                          : `READING THE REGISTRY'S HISTORY · PAGE ${formatCount(reading.done)} OF ${formatCount(reading.total)}`
                        : reading?.state === "ready"
                          ? `READ FROM THE REGISTRY · BLOCK ${formatCount(reading.block)}`
                          : ""}
                    </p>
                  </div>

                  {reading?.state === "failed" ? (
                    <div className="mt-6">
                      <p className="max-w-[48ch] text-[15px] leading-[1.5] text-ink">{reading.error}</p>
                      <button
                        type="button"
                        onClick={() => run.current && void loadBoards(run.current.signal)}
                        className="mono mt-4 min-h-9 cursor-pointer rounded-lg border border-ink px-4 py-1.5 text-[12px] tracking-[0.12em] text-ink transition-colors duration-200 hover:bg-ink hover:text-on-ink"
                      >
                        READ IT AGAIN
                      </button>
                    </div>
                  ) : boards.length > 0 ? (
                    <>
                      <ol className="mt-6 border-b border-rule">
                        {boards.map((board) => (
                          <BoardRow key={board.boardId.toString()} board={board} />
                        ))}
                      </ol>
                      {boards.some((board) => board.standing !== "chair") ? (
                        <p className="mt-4 max-w-[60ch] text-[15px] leading-[1.5] text-ink-soft">
                          A chair can put any address on a board without asking. This list shows only what the chain says about each board; nothing a board stores is
                          downloaded until you open one of its packs. Open the boards whose chair you know.
                        </p>
                      ) : null}
                    </>
                  ) : reading?.state === "ready" ? (
                    <p className="mt-6 max-w-[48ch] border-t border-rule pt-6 text-[17px] leading-[1.5] text-ink">
                      No board names this account yet. Create one below, or send your address to a chair who wants to add you.
                    </p>
                  ) : (
                    <div className="mt-6 border-t border-rule pt-6">
                      <div className="demo-track" />
                    </div>
                  )}

                  <div className="mt-10">
                    {creating?.state === "running" ? (
                      <div className="max-w-[520px]">
                        <p className="text-[18px] leading-[1.35] text-ink">Creating your board</p>
                        <div className="demo-track mt-3" />
                        <p className={`${LABEL} mt-2`}>{secondsBetween(creating.startedAt, now)}</p>
                        <p className="mt-2 max-w-[48ch] text-[15px] leading-[1.5] text-ink-soft">{creating.text}</p>
                      </div>
                    ) : (
                      <>
                        {creating?.state === "done" ? (
                          <div className="mb-8 max-w-[520px]">
                            <p className="flex items-start gap-2.5 text-[18px] leading-[1.35] text-ink">
                              <span className="mt-[5px]">
                                <Tick size={14} drawAfter={0} />
                              </span>
                              {creating.text}
                            </p>
                            <p className={`${LABEL} mt-2 flex flex-wrap items-center gap-x-2`}>
                              <span>CREATED · CREATEBOARD ·</span>
                              <TxHash hash={creating.hash ?? null} className="font-mono text-[11px]" />
                              <span>· {secondsBetween(creating.startedAt, creating.endedAt ?? creating.startedAt)}</span>
                            </p>
                          </div>
                        ) : null}
                        {creating?.state === "failed" ? <p className="mb-6 max-w-[48ch] text-[15px] leading-[1.5] text-ink">{plainError(creating.text)}</p> : null}
                        <button type="button" onClick={createOne} disabled={reading?.state === "reading"} className="btn-primary cursor-pointer">
                          {creating?.state === "done" ? "Create another board" : "Create a board"} <span className="arrow">→</span>
                        </button>
                        <p className={`${LABEL} mt-3.5 max-w-[60ch] leading-[1.7]`}>
                          YOUR BROWSER MAKES THE BOARD&apos;S FIRST KEY, SEALS IT TO YOU AND SIGNS THE CREATE. OUR RELAY PAYS THE GAS. ABOUT HALF A MINUTE.
                        </p>
                      </>
                    )}
                  </div>
                </>
              )}
            </div>

            <div className="max-lg:mt-14 lg:col-span-4 lg:col-start-9">
              <IdentityCard account={view.account} keysOnChain={phase === "ready"} words={words} />
            </div>
          </section>
        )}
      </div>
      <Footer />
    </main>
  );
}
