import { sameAccount } from "@ava/core";
import type { Hex } from "viem";
import { BOARD_ID } from "../chain";
import { readBoard } from "./board";
import type { GuestAccount } from "./identity";
import type { StepLine } from "./journey";
import { LeaveRefused, confirmLeave, requestLeave } from "./leave";
import { waitForShutPack, type FoundPack, type ShutPack } from "./shut";
import { Stopped, pause, throwIfStopped } from "./time";

export type LeaveStepKey = "request" | "removal" | "nextPack" | "shut";

/** The guest's seat coming off the board: by its own signed leave here, or already gone when this page looked. */
export interface Removal {
  /** The removeMember this page confirmed; absent when the seat was already gone. */
  txHash?: Hex;
  block: bigint;
  /** The epoch the board is in without this guest. */
  epoch: bigint;
  members: number;
}

export interface LeaveView {
  steps: StepLine<LeaveStepKey>[];
  removal?: Removal;
  /** Set once the next pack is found and its stored bytes are checked, before the keys are tried. */
  found?: FoundPack;
  shut?: ShutPack;
  error?: string;
  finished: boolean;
}

const TITLES: Readonly<Record<LeaveStepKey, string>> = {
  request: "Ask the demo bot for a leave request and check its bytes",
  removal: "Sign the leave and have the chair remove this account",
  nextPack: "Wait for the board's next pack",
  shut: "Try this browser's keys on the next pack",
};
const ORDER: readonly LeaveStepKey[] = ["request", "removal", "nextPack", "shut"];
const READ_TRIES = 3;
const READ_RETRY_MS = 2_000;

export const REMOVAL_WAIT =
  "The bot checks the ML-DSA-87 signature, makes a new board key, seals it to everyone still on the board, uploads the envelope and relays the removeMember. This takes up to a minute.";
export const NEXT_PACK_WAIT = "Waiting for the demo chair to post the next pack under the new key. The bot posts one after a removal; it can take a minute or two. Reading the board every 5 s.";

export function initialLeaveView(): LeaveView {
  return { steps: ORDER.map((key) => ({ key, title: TITLES[key], state: "pending" })), finished: false };
}

class Tracker {
  private view: LeaveView;

  constructor(
    private readonly onChange: (view: LeaveView) => void,
    private readonly signal: AbortSignal,
    prior: LeaveView | undefined,
  ) {
    this.view = initialLeaveView();
    // A retry after the seat is gone keeps what the first run confirmed and goes on from the pack.
    if (prior?.removal !== undefined) {
      this.view.removal = prior.removal;
      for (const key of ["request", "removal"] as const) Object.assign(this.step(key), prior.steps.find((s) => s.key === key));
    }
  }

  private emit(): void {
    if (this.signal.aborted) return;
    this.onChange({ ...this.view, steps: this.view.steps.map((s) => ({ ...s })) });
  }

  private step(key: LeaveStepKey): StepLine<LeaveStepKey> {
    const found = this.view.steps.find((s) => s.key === key);
    if (found === undefined) throw new Error(`No step ${key}.`);
    return found;
  }

  get removal(): Removal | undefined {
    return this.view.removal;
  }

  stateOf(key: LeaveStepKey): StepLine["state"] {
    return this.step(key).state;
  }

  start(key: LeaveStepKey, wait?: string): void {
    Object.assign(this.step(key), { state: "running", startedAt: performance.now(), wait });
    this.emit();
  }

  update(key: LeaveStepKey, patch: Partial<Pick<StepLine, "detail" | "hash" | "hashKind" | "wait">>): void {
    Object.assign(this.step(key), patch);
    this.emit();
  }

  end(key: LeaveStepKey, state: "done" | "skipped", detail: string): void {
    const step = this.step(key);
    Object.assign(step, { state, detail, wait: undefined, endedAt: performance.now(), startedAt: step.startedAt ?? performance.now() });
    this.emit();
  }

  set(patch: Pick<LeaveView, "removal"> | Pick<LeaveView, "found"> | Pick<LeaveView, "shut">): void {
    Object.assign(this.view, patch);
    this.emit();
  }

  fail(error: unknown): void {
    const message = error instanceof Error ? error.message : "Something failed.";
    const running = this.view.steps.find((s) => s.state === "running");
    if (running !== undefined) Object.assign(running, { state: "failed", wait: undefined, endedAt: performance.now(), detail: message });
    this.view.error = message;
    this.view.finished = true;
    this.emit();
  }

  finish(): void {
    this.view.finished = true;
    this.emit();
  }
}

async function retryRead<T>(read: () => Promise<T>, signal: AbortSignal): Promise<T> {
  for (let tried = 1; ; tried++) {
    throwIfStopped(signal);
    try {
      return await read();
    } catch (error) {
      if (error instanceof Stopped || signal.aborted || tried >= READ_TRIES) throw error;
      await pause(READ_RETRY_MS, signal);
    }
  }
}

/** The seat was gone before this page asked: a pass or a sweep removed it, or an earlier visit left. */
function alreadyGone(t: Tracker, board: { blockNumber: bigint; epoch: bigint; members: readonly Hex[] }): void {
  const detail = `This account was not on the board at block ${board.blockNumber}.`;
  if (t.stateOf("request") !== "done") t.end("request", "skipped", detail);
  t.end("removal", "skipped", detail);
  t.set({ removal: { block: board.blockNumber, epoch: board.epoch, members: board.members.length } });
}

async function leaveBoard(t: Tracker, guest: GuestAccount, boardId: bigint, signal: AbortSignal): Promise<void> {
  const before = await retryRead(() => readBoard(boardId), signal);
  if (!before.members.some((m) => sameAccount(m, guest.identity.evm))) {
    alreadyGone(t, before);
    return;
  }
  t.start("request", "Asking the demo bot through our API.");
  let txHash: Hex;
  try {
    txHash = await requestLeave(guest, signal, (p) => {
      if (p.kind === "request") {
        const detail = `224 bytes for board ${p.request.boardId}, expiring at unix ${p.request.expiry}; rebuilt here byte for byte.`;
        if (t.stateOf("request") !== "done") {
          t.end("request", "done", detail);
          t.start("removal", REMOVAL_WAIT);
        } else {
          t.update("removal", { detail: `Signed a fresh leave request: ${detail}` });
        }
      } else if (p.kind === "retrying") {
        const why = p.reason === "busy" ? "The board is in the middle of another change." : "The bot could not finish the removal yet.";
        t.update("removal", { detail: why, wait: `${why} Trying again in ${p.seconds} s with a fresh request (try ${p.attempt} of ${p.of}).` });
      } else {
        t.update("removal", { hash: p.txHash, hashKind: "evm", wait: "The bot sent the removeMember. Waiting for its receipt on the public EVM RPC." });
      }
    });
  } catch (error) {
    // The bot's own read found the seat gone: a pass removed it between this page's read and the request.
    if (!(error instanceof LeaveRefused) || error.reason !== "not_a_member") throw error;
    alreadyGone(t, await retryRead(() => readBoard(boardId), signal));
    return;
  }
  const landed = await confirmLeave(txHash, guest.identity.evm, boardId);
  const after = await retryRead(() => readBoard(boardId), signal);
  if (after.members.some((m) => sameAccount(m, guest.identity.evm))) throw new Error("The removeMember landed but this account is still a member.");
  t.end("removal", "done", `The removeMember landed in block ${landed.block}; the board moved to epoch ${landed.epoch} with ${after.members.length} members.`);
  t.set({ removal: { txHash, block: landed.block, epoch: landed.epoch, members: after.members.length } });
}

/**
 * The guest leaves the demo board by its own signature, then this browser tries to open the pack
 * the chair posts next (threat model C47, C26, C38, C39). Run after the guest presses the control
 * that says so, and never on its own. A guest whose seat is already gone skips the leave and goes
 * straight to the pack, so a return visit shows the same lock.
 *
 * @param input.heldEpoch The last epoch whose key this guest opened in this page view, if any.
 * @param input.prior The view of an earlier run in this page view; its confirmed removal is kept.
 * @param onChange Called with a fresh copy of the view after every change.
 * @param signal Stops the run; nothing more is shown after it fires.
 */
export async function runLeave(input: { guest: GuestAccount; heldEpoch?: bigint; prior?: LeaveView }, onChange: (view: LeaveView) => void, signal: AbortSignal): Promise<void> {
  const t = new Tracker(onChange, signal, input.prior);
  try {
    if (BOARD_ID === null) throw new Error("NEXT_PUBLIC_DEMO_BOARD_ID is not set.");
    const boardId = BOARD_ID;
    if (t.removal === undefined) await leaveBoard(t, input.guest, boardId, signal);
    const removal = t.removal;
    if (removal === undefined) throw new Error("The removal was not confirmed.");

    t.start("nextPack", NEXT_PACK_WAIT);
    const shut = await waitForShutPack(boardId, input.guest, { fromEpoch: removal.epoch, heldEpoch: input.heldEpoch }, signal, (found) => {
      t.set({ found });
      t.end("nextPack", "done", `Pack ${found.docId + 1n}, epoch ${found.epoch}, ${found.size} bytes, its size and SHA-256 checked against the registry.`);
      t.start("shut", `Downloading every envelope of epoch ${found.epoch} and trying this account's keys on each.`);
    });
    const old = shut.oldEpoch === undefined ? "" : ` The key of epoch ${shut.oldEpoch} does not open it either.`;
    t.set({ shut });
    t.end("shut", "done", `${shut.envelopesTried} of ${shut.envelopesTried} envelopes of epoch ${shut.epoch} refused this account's keys at block ${shut.blockNumber}.${old}`);
    t.finish();
  } catch (error) {
    if (error instanceof Stopped || signal.aborted) return;
    t.fail(error);
  }
}
