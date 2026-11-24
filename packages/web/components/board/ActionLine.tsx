"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Stopped } from "../../lib/guest/time";
import { plainError, secondsBetween } from "../demo/chapters";
import { Cross, Tick } from "../proof/Glyphs";
import { TxHash } from "../proof/TxHash";

const TICK_MS = 200;
const LABEL = "mono text-[11px] tracking-[0.14em] text-ink-soft";

/** One signed board change as the page follows it: what it is doing now, then how it ended. */
export type ActionRun = {
  title: string;
  state: "running" | "done" | "failed";
  text: string;
  hash?: string;
  startedAt: number;
  endedAt?: number;
};

type Say = (line: { text: string; hash?: string }) => void;

/**
 * Runs one board change at a time and keeps its line. `work` reports through `say` and resolves to
 * the sentence that states what is now true; a failure keeps its own words.
 */
export function useAction(signal: () => AbortSignal | undefined) {
  const [run, setRun] = useState<ActionRun | undefined>(undefined);
  const busy = run?.state === "running";

  const start = useCallback(
    (title: string, work: (say: Say, signal: AbortSignal) => Promise<{ text: string; hash?: string }>, after?: () => void) => {
      const live = signal();
      if (live === undefined) return;
      const startedAt = performance.now();
      setRun({ title, state: "running", text: "Starting.", startedAt });
      const say: Say = (line) => setRun((prior) => (prior === undefined || prior.state !== "running" ? prior : { ...prior, text: line.text, hash: line.hash ?? prior.hash }));
      void work(say, live)
        .then((done) => {
          if (live.aborted) return;
          setRun((prior) => ({ title, state: "done", text: done.text, hash: done.hash ?? prior?.hash, startedAt, endedAt: performance.now() }));
          after?.();
        })
        .catch((error: unknown) => {
          if (error instanceof Stopped || live.aborted) return;
          setRun((prior) => ({ title, state: "failed", text: error instanceof Error ? error.message : "Something failed.", hash: prior?.hash, startedAt, endedAt: performance.now() }));
        });
    },
    [signal],
  );

  const clear = useCallback(() => setRun(undefined), []);
  return { run, busy, start, clear };
}

/** The line of one board change: a moving track and an honest sentence while it runs, then the result with its transaction. */
export function ActionLine({ run }: { run: ActionRun | undefined }) {
  const [now, setNow] = useState(0);
  const running = run?.state === "running";
  const timer = useRef<ReturnType<typeof setInterval> | undefined>(undefined);

  useEffect(() => {
    if (!running) return;
    setNow(performance.now());
    timer.current = setInterval(() => setNow(performance.now()), TICK_MS);
    return () => clearInterval(timer.current);
  }, [running]);

  if (run === undefined) return null;

  if (run.state === "running") {
    return (
      <div className="max-w-[560px]" aria-live="polite">
        <p className="text-[17px] leading-[1.35] text-ink">{run.title}</p>
        <div className="demo-track mt-3" />
        <p className={`${LABEL} mt-2`}>{secondsBetween(run.startedAt, now)}</p>
        <p className="mt-2 max-w-[52ch] text-[15px] leading-[1.5] text-ink-soft">{run.text}</p>
      </div>
    );
  }

  return (
    <div className="max-w-[560px]" aria-live="polite">
      <p className="flex items-start gap-2.5 text-[17px] leading-[1.35] text-ink">
        <span className={run.state === "done" ? "mt-[5px]" : "mt-[6px]"}>{run.state === "done" ? <Tick size={14} drawAfter={0} /> : <Cross size={12} />}</span>
        <span>{run.state === "done" ? run.text : plainError(run.text)}</span>
      </p>
      {run.hash !== undefined || run.endedAt !== undefined ? (
        <p className={`${LABEL} mt-2 flex flex-wrap items-center gap-x-2`}>
          {run.hash !== undefined ? <TxHash hash={run.hash} className="font-mono text-[11px]" /> : null}
          {run.endedAt !== undefined ? <span>{run.hash !== undefined ? "· " : ""}{secondsBetween(run.startedAt, run.endedAt)}</span> : null}
        </p>
      ) : null}
    </div>
  );
}
