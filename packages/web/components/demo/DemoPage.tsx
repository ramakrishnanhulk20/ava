"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createGuest, forgetGuest, protectStoredPhrase, storedGuest, openGuest, type GuestSession, type StoredGuest } from "../../lib/guest/identity";
import { initialView, runJourney, type JourneyView } from "../../lib/guest/journey";
import { initialLeaveView, runLeave, type LeaveView } from "../../lib/guest/leaveJourney";
import { useMotionMode } from "../../lib/motionMode";
import { scrollToTarget } from "../../lib/smoothScroll";
import { Footer } from "../Footer";
import { Nav } from "../hero/Nav";
import { ALREADY_ADMITTED, chaptersOf, leaveChaptersOf, type ChapterView } from "./chapters";
import { ChapterList, type ChapterAction } from "./ChapterList";
import { DemoStage } from "./DemoStage";
import { LeaveBand } from "./LeaveBand";
import { ReadingView } from "./ReadingView";
import { RecoveryWords } from "./RecoveryWords";
import { StartBlock, type StartWork } from "./StartBlock";

const TICK_MS = 200;
// Long enough to watch the sealed pack take the next pack's bytes and the lock land before the page moves on.
const RESULT_DELAY_MS = 1_800;

/**
 * Glides with Lenis where it runs, and jumps where it does not (reduced motion).
 *
 * @param place "top" puts the target at the top of the window; "upper" a third of the way down, so what sits beside it stays in view.
 */
function bringIntoView(selector: string, place: "top" | "upper" = "top") {
  const offset = place === "upper" ? -Math.round(window.innerHeight * 0.3) : 0;
  if (scrollToTarget(selector, offset)) return;
  document.querySelector(selector)?.scrollIntoView(place === "upper" ? { block: "center" } : undefined);
}

export function DemoPage() {
  const mode = useMotionMode();
  const [view, setView] = useState<JourneyView>(initialView);
  const [started, setStarted] = useState(false);
  const [running, setRunning] = useState(false);
  const [stored, setStored] = useState<StoredGuest>({ kind: "none" });
  const [busy, setBusy] = useState<StartWork | undefined>(undefined);
  const [problem, setProblem] = useState<string | undefined>(undefined);
  const [words, setWords] = useState<readonly string[] | undefined>(undefined);
  const [note, setNote] = useState<string | undefined>(undefined);
  const [now, setNow] = useState(0);
  const [reading, setReading] = useState(false);
  const [leave, setLeave] = useState<LeaveView | undefined>(undefined);
  const [leaving, setLeaving] = useState(false);
  const run = useRef<AbortController | undefined>(undefined);
  const leaveRun = useRef<AbortController | undefined>(undefined);
  // The open guest lives here for this page view only; a reload asks for the passphrase again.
  const session = useRef<GuestSession | undefined>(undefined);
  // The latest leave view, for the start of a retry to read without waiting for a render.
  const leaveView = useRef<LeaveView | undefined>(undefined);
  const showLeave = useCallback((next: LeaveView | undefined) => {
    leaveView.current = next;
    setLeave(next);
  }, []);

  useEffect(() => {
    setStored(storedGuest());
    return () => {
      run.current?.abort();
      leaveRun.current?.abort();
      session.current = undefined;
    };
  }, []);

  const ticking = running || leaving;
  useEffect(() => {
    if (!ticking) return;
    setNow(performance.now());
    const timer = setInterval(() => setNow(performance.now()), TICK_MS);
    return () => clearInterval(timer);
  }, [ticking]);

  useEffect(() => {
    if (started) requestAnimationFrame(() => bringIntoView("#journey"));
  }, [started]);

  useEffect(() => {
    if (reading) requestAnimationFrame(() => bringIntoView("#reading"));
  }, [reading]);

  const start = useCallback((tookMs: number) => {
    const guest = session.current;
    if (guest === undefined) return;
    run.current?.abort();
    leaveRun.current?.abort();
    const controller = new AbortController();
    run.current = controller;
    setNote(undefined);
    setView(initialView());
    showLeave(undefined);
    setLeaving(false);
    setReading(false);
    setStarted(true);
    setRunning(true);
    void runJourney({ guest: guest.guest, resumed: guest.resumed, tookMs }, setView, controller.signal).finally(() => {
      if (run.current !== controller) return;
      setNow(performance.now());
      setRunning(false);
    });
  }, []);

  // Making or opening the identity happens before the journey, so a wrong passphrase is answered
  // at the field and never shows up as a failed chapter.
  const open = useCallback(
    (work: StartWork, obtain: (passphrase: string) => Promise<GuestSession>) => (passphrase: string) => {
      setBusy(work);
      setProblem(undefined);
      const began = performance.now();
      void obtain(passphrase)
        .then((guest) => {
          session.current = guest;
          setWords(guest.words);
          setStored(storedGuest());
          start(performance.now() - began);
        })
        .catch((error: unknown) => setProblem(error instanceof Error ? error.message : "That did not work. Try again."))
        .finally(() => setBusy(undefined));
    },
    [start],
  );
  const create = useMemo(() => open("making", (passphrase) => createGuest(passphrase)), [open]);
  const reopen = useMemo(() => open("opening", (passphrase) => openGuest(passphrase)), [open]);
  const protect = useMemo(() => open("making", (passphrase) => protectStoredPhrase(passphrase)), [open]);
  const retry = useCallback(() => start(0), [start]);

  const heldEpoch = view.packInfo?.epoch ?? view.epoch;
  // Runs only from a control the guest pressed: the leave button, or the check offered to a seat that is already gone.
  const startLeave = useCallback(() => {
    const guest = session.current;
    if (guest === undefined) return;
    leaveRun.current?.abort();
    const controller = new AbortController();
    leaveRun.current = controller;
    // A run that already saw the seat go keeps that and goes on from the pack; any other starts clean.
    const prior = leaveView.current?.removal === undefined ? undefined : leaveView.current;
    if (prior === undefined) showLeave(initialLeaveView());
    setLeaving(true);
    void runLeave({ guest: guest.guest, heldEpoch, prior }, showLeave, controller.signal).finally(() => {
      if (leaveRun.current !== controller) return;
      setNow(performance.now());
      setLeaving(false);
    });
    requestAnimationFrame(() => bringIntoView('[data-chapter="leave"]', "upper"));
  }, [heldEpoch, showLeave]);

  const shutKnown = leave?.shut !== undefined;
  useEffect(() => {
    if (!shutKnown || mode === "pending") return;
    const timer = setTimeout(() => bringIntoView("#removal"), mode === "reduced" ? 0 : RESULT_DELAY_MS);
    return () => clearTimeout(timer);
  }, [shutKnown, mode]);

  const forget = useCallback(() => {
    try {
      forgetGuest();
      setNote("This browser no longer holds your identity. Starting again makes a new one.");
    } catch (error) {
      setNote(error instanceof Error ? error.message : "The identity could not be removed.");
    }
    session.current = undefined;
    setWords(undefined);
    setProblem(undefined);
    setStored(storedGuest());
  }, []);

  /** Forgets this identity and puts the page back to its start, for a seat that is spent. */
  const startOver = useCallback(() => {
    run.current?.abort();
    leaveRun.current?.abort();
    forget();
    setView(initialView());
    showLeave(undefined);
    setLeaving(false);
    setRunning(false);
    setReading(false);
    setStarted(false);
    requestAnimationFrame(() => bringIntoView("#demo-top"));
  }, [forget]);

  const journeyChapters = useMemo(() => chaptersOf(view), [view]);
  const leaveChapters = useMemo(() => (leave === undefined ? [] : leaveChaptersOf(leave)), [leave]);
  const chapters = useMemo(() => [...journeyChapters, ...leaveChapters], [journeyChapters, leaveChapters]);
  const errors = useMemo(() => {
    const out: Partial<Record<ChapterView["id"], string>> = {};
    for (const chapter of journeyChapters) if (chapter.state === "failed") out[chapter.id] = view.error;
    for (const chapter of leaveChapters) if (chapter.state === "failed") out[chapter.id] = leave?.error;
    return out;
  }, [journeyChapters, leaveChapters, view.error, leave?.error]);
  const actionsFor = useCallback(
    (chapter: ChapterView): ChapterAction[] => {
      if (chapter.id === "leave" || chapter.id === "shut") return [{ label: "TRY AGAIN", onClick: startLeave }];
      // An address that has had its seat cannot join again, so trying again is not offered.
      if (ALREADY_ADMITTED.test(view.error ?? "")) {
        return [
          ...(leave === undefined ? [{ label: "CHECK THE CURRENT PACK", onClick: startLeave }] : []),
          { label: "START OVER AS A NEW VISITOR", onClick: startOver },
        ];
      }
      return [{ label: "TRY AGAIN", onClick: retry }];
    },
    [leave, retry, startLeave, startOver, view.error],
  );
  const identityDone = journeyChapters[0]?.state === "done";
  const bandOn = started && (view.pack !== undefined || leave !== undefined);

  return (
    <main className="w-full overflow-x-clip">
      <div id="demo-top" className="mx-auto w-full max-w-[1440px] px-5 pt-7 pb-24 sm:px-14">
        <Nav />

        <header className="pt-[120px]">
          <p className="mono flex items-center gap-2.5 text-[12px] tracking-[0.16em] text-ink-soft">
            <span className="size-2 rounded-full bg-accent" aria-hidden="true" />[ THE DEMO BOARD · LIVE ON QORECHAIN
            TESTNET ]
          </p>
          <h1 className="display mt-6 max-w-[12em] text-[clamp(2.75rem,5.5vw,5.5rem)] leading-[0.98] tracking-[-0.02em] text-ink">
            Join the board. Open the next pack.
          </h1>
          <p className="mt-6 max-w-[48ch] text-[18px] leading-[1.6] text-ink-soft">
            In about three minutes your browser makes a quantum-safe identity, puts its keys on QoreChain, gets
            admitted by the demo chair and opens a board pack sealed to you. Then you can leave, and watch the next
            pack stay shut. Nothing is simulated: every step is a real transaction you can check.
          </p>
          {started ? null : (
            <StartBlock
              stored={stored}
              busy={busy}
              problem={problem}
              note={note}
              onCreate={create}
              onReopen={reopen}
              onProtect={protect}
              onForget={forget}
            />
          )}
        </header>

        <section id="journey" className="mt-[72px] lg:grid lg:grid-cols-12 lg:gap-x-8">
          <div className="max-lg:order-1 max-lg:mx-auto max-lg:mb-12 max-lg:w-[min(360px,80vw)] lg:col-span-6 lg:col-start-7">
            <div className="lg:sticky lg:top-[calc(50vh-290px)]">
              <DemoStage view={view} leave={leave} onRead={() => setReading(true)} />
            </div>
          </div>
          {/* Once the removal's chapters are on the list, room under them keeps the stage beside them, not above. */}
          <div className={`max-lg:order-2 lg:col-span-6 lg:col-start-1 lg:row-start-1 ${leave === undefined ? "" : "lg:pb-[32vh]"}`}>
            <ChapterList chapters={chapters} now={now} errors={errors} actionsFor={actionsFor} />
            {identityDone && words !== undefined ? <RecoveryWords words={words} /> : null}
          </div>
        </section>

        {reading ? <ReadingView view={view} /> : null}
      </div>

      {bandOn ? <LeaveBand view={view} leave={leave} leaving={leaving} onLeave={startLeave} onStartOver={startOver} /> : null}
      <Footer />
    </main>
  );
}
