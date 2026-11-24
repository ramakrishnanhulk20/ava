/** One wait's time budget on the page's monotonic clock, so a changed system clock cannot stretch it. */
export interface Deadline {
  readonly startedAt: number;
  readonly endsAt: number;
}

export class OutOfTime extends Error {
  constructor(what: string) {
    super(`Ran out of time ${what}.`);
    this.name = "OutOfTime";
  }
}

/** Forget me, or leaving the page, stopped the journey. */
export class Stopped extends Error {
  constructor() {
    super("Stopped.");
    this.name = "Stopped";
  }
}

export function startDeadline(totalMs: number): Deadline {
  const startedAt = performance.now();
  return { startedAt, endsAt: startedAt + totalMs };
}

export function leftMs(deadline: Deadline): number {
  return Math.max(0, deadline.endsAt - performance.now());
}

export function throwIfStopped(signal: AbortSignal): void {
  if (signal.aborted) throw new Stopped();
}

/** Waits `ms`, or rejects with Stopped as soon as `signal` fires. */
export function pause(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new Stopped());
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new Stopped());
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}
