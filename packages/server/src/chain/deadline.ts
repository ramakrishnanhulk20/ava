/**
 * One relay's time budget on one monotonic clock. A serverless function is cut off at about a
 * minute and the relayer's locks expire at 60 s, so every wait in the relay path is bounded by
 * what is left here, never by a fixed retry count alone.
 */
export interface Deadline {
  readonly startedAt: number;
  readonly endsAt: number;
  readonly now: () => number;
}

/** The step could not finish inside the time left. A send never starts after this is thrown. */
export class OutOfTime extends Error {
  constructor(what: string) {
    super(`Out of time before ${what}.`);
    this.name = "OutOfTime";
  }
}

const monotonic = (): number => performance.now();

/** A deadline `totalMs` from now. `now` defaults to the process's monotonic clock; tests pass their own. */
export function startDeadline(totalMs: number, now: () => number = monotonic): Deadline {
  const startedAt = now();
  return { startedAt, endsAt: startedAt + totalMs, now };
}

export function elapsedMs(deadline: Deadline): number {
  return deadline.now() - deadline.startedAt;
}

export function leftMs(deadline: Deadline): number {
  return Math.max(0, deadline.endsAt - deadline.now());
}

/** A deadline that ends `ms` from now or at `parent`'s end, whichever is sooner. */
export function narrowed(parent: Deadline, ms: number): Deadline {
  const now = parent.now();
  return { startedAt: parent.startedAt, endsAt: Math.min(parent.endsAt, now + ms), now: parent.now };
}

/**
 * Settles as `work` does, or rejects with OutOfTime once the deadline passes first. For reads only:
 * the request itself is abandoned, not undone, so it must be safe to have happened.
 */
export async function within<T>(deadline: Deadline, work: Promise<T>, what: string): Promise<T> {
  const left = leftMs(deadline);
  if (left <= 0) {
    work.catch(() => undefined);
    throw new OutOfTime(what);
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new OutOfTime(what)), left);
  });
  try {
    return await Promise.race([work, late]);
  } finally {
    clearTimeout(timer);
    work.catch(() => undefined);
  }
}

export const pause = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
