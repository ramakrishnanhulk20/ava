import type { Hex } from "viem";
import { initialView, type JourneyView, type StepKey, type StepLine } from "./journey";
import type { OnboardStepKey, OnboardSteps } from "./onboard";

/** What the first three chapters need, wherever they are shown: the identity step and the four onboarding steps. */
export interface OnboardTracker extends OnboardSteps {
  /** The identity was made or opened before the steps began; `tookMs` is how long that took. */
  identity(account: { qor1: string; evm: Hex }, resumed: boolean, tookMs: number): void;
  fail(error: unknown): void;
  finish(): void;
}

/**
 * Keeps a journey view for a screen that shows only the identity, the funding and the keys, such
 * as the chair's board room. The steps and their wording are the demo's own, so both screens say
 * the same thing about the same work.
 *
 * @param onChange Called with a fresh copy of the view after every change, until `signal` fires.
 */
export function trackOnboarding(onChange: (view: JourneyView) => void, signal: AbortSignal): OnboardTracker {
  const view = initialView();
  const emit = (): void => {
    if (!signal.aborted) onChange({ ...view, steps: view.steps.map((s) => ({ ...s })) });
  };
  const step = (key: StepKey): StepLine => {
    const found = view.steps.find((s) => s.key === key);
    if (found === undefined) throw new Error(`No step ${key}.`);
    return found;
  };
  return {
    identity(account, resumed, tookMs) {
      const now = performance.now();
      Object.assign(step("identity"), {
        state: "done",
        startedAt: now - Math.max(0, tookMs),
        endedAt: now,
        detail: resumed ? "Opened the identity this browser keeps." : "Made a new identity. Its recovery words are locked in this browser with your passphrase.",
      });
      view.account = account;
      emit();
    },
    start(key: OnboardStepKey, wait?: string) {
      Object.assign(step(key), { state: "running", startedAt: performance.now(), wait });
      emit();
    },
    update(key, patch) {
      Object.assign(step(key), patch);
      emit();
    },
    end(key, state, detail) {
      const line = step(key);
      Object.assign(line, { state, detail, wait: undefined, endedAt: performance.now(), startedAt: line.startedAt ?? performance.now() });
      emit();
    },
    fail(error) {
      const message = error instanceof Error ? error.message : "Something failed.";
      const running = view.steps.find((s) => s.state === "running");
      if (running !== undefined) Object.assign(running, { state: "failed", wait: undefined, endedAt: performance.now(), detail: message });
      view.error = message;
      view.finished = true;
      emit();
    },
    finish() {
      view.finished = true;
      emit();
    },
  };
}
