import { sameAccount } from "@ava/core";
import type { Hex } from "viem";
import { BOARD_ID } from "../chain";
import { openGuestEpochKey, readBoard, waitAndOpenPack } from "./board";
import type { GuestAccount, GuestSession } from "./identity";
import { challengeAndJoin, confirmJoin } from "./join";
import { fundAndRegister, retryRead } from "./onboard";
import { Stopped } from "./time";

export type StepKey = "identity" | "sponsor" | "mldsa" | "mlkem" | "keys" | "challenge" | "join" | "epochKey" | "pack";
export type StepState = "pending" | "running" | "done" | "skipped" | "failed";

export interface StepLine<K extends string = StepKey> {
  key: K;
  /** What the step does, in plain words. */
  title: string;
  state: StepState;
  /** What it found or did, in plain words. */
  detail?: string;
  /** Its transaction: 64 hex digits on the native lane, 0x and 64 hex digits on the EVM lane. */
  hash?: string;
  hashKind?: "native" | "evm";
  /** What a wait is for, shown once the step has run past two seconds. */
  wait?: string;
  /** performance.now() readings. */
  startedAt?: number;
  endedAt?: number;
}

export interface JourneyView {
  steps: StepLine[];
  account?: { qor1: string; evm: Hex };
  /** The board epoch this account's key was opened for, once the epoch key step is done. */
  epoch?: bigint;
  /** The decrypted pack, once it is open on this device. */
  pack?: string;
  /** Which pack that was, for the line above it. */
  packInfo?: { docId: bigint; epoch: bigint; size: bigint };
  error?: string;
  finished: boolean;
}

const TITLES: Readonly<Record<StepKey, string>> = {
  identity: "Make a quantum-safe identity on this device",
  sponsor: "Get testnet QOR from our sponsor for the two key registrations",
  mldsa: "Register the ML-DSA-87 signing key, with its proof of possession",
  mlkem: "Publish the ML-KEM-1024 sealing key, hybrid-signed",
  keys: "Wait until the chain shows both keys",
  challenge: "Ask the demo bot for a challenge and check its bytes",
  join: "Sign the challenge and join the demo board",
  epochKey: "Open this epoch's key on this device",
  pack: "Wait for this epoch's board pack and decrypt it here",
};
const ORDER: readonly StepKey[] = ["identity", "sponsor", "mldsa", "mlkem", "keys", "challenge", "join", "epochKey", "pack"];


export function initialView(): JourneyView {
  return { steps: ORDER.map((key) => ({ key, title: TITLES[key], state: "pending" })), finished: false };
}

/** Keeps the view and hands the page a fresh copy after every change. */
class Tracker {
  private view = initialView();

  constructor(
    private readonly onChange: (view: JourneyView) => void,
    private readonly signal: AbortSignal,
  ) {}

  private emit(): void {
    if (this.signal.aborted) return;
    this.onChange({ ...this.view, steps: this.view.steps.map((s) => ({ ...s })) });
  }

  private step(key: StepKey): StepLine {
    const found = this.view.steps.find((s) => s.key === key);
    if (found === undefined) throw new Error(`No step ${key}.`);
    return found;
  }

  stateOf(key: StepKey): StepState {
    return this.step(key).state;
  }

  /** @param tookMs Work already done for this step before the journey began, so its seconds are honest. */
  start(key: StepKey, wait?: string, tookMs = 0): void {
    Object.assign(this.step(key), { state: "running", startedAt: performance.now() - Math.max(0, tookMs), wait });
    this.emit();
  }

  update(key: StepKey, patch: Partial<Pick<StepLine, "detail" | "hash" | "hashKind" | "wait">>): void {
    Object.assign(this.step(key), patch);
    this.emit();
  }

  end(key: StepKey, state: "done" | "skipped", detail: string): void {
    const step = this.step(key);
    Object.assign(step, { state, detail, wait: undefined, endedAt: performance.now(), startedAt: step.startedAt ?? performance.now() });
    this.emit();
  }

  account(qor1: string, evm: Hex): void {
    this.view.account = { qor1, evm };
    this.emit();
  }

  /** Records the epoch without a change of its own; the step that ends next emits it. */
  epoch(epoch: bigint): void {
    this.view.epoch = epoch;
  }

  pack(text: string, info: { docId: bigint; epoch: bigint; size: bigint }): void {
    this.view.pack = text;
    this.view.packInfo = info;
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

async function joinBoard(t: Tracker, guest: GuestAccount, boardId: bigint, signal: AbortSignal): Promise<void> {
  const before = await retryRead(() => readBoard(boardId), signal);
  if (before.members.some((m) => sameAccount(m, guest.identity.evm))) {
    t.end("challenge", "skipped", "This account is already a member of the demo board.");
    t.end("join", "skipped", `Already 1 of ${before.members.length} members at block ${before.blockNumber}.`);
    return;
  }
  t.start("challenge", "Asking the demo bot through our API.");
  const txHash = await challengeAndJoin(guest, signal, (p) => {
    if (p.kind === "challenge") {
      const detail = `224 bytes for board ${p.challenge.boardId}, expiring at unix ${p.challenge.expiry}; rebuilt here byte for byte.`;
      if (t.stateOf("challenge") !== "done") {
        t.end("challenge", "done", detail);
        t.start("join", "The bot checks the ML-DSA-87 signature, seals this epoch's key to the new ML-KEM key, uploads the envelope and relays the addMember. This takes up to a minute.");
      } else {
        t.update("join", { detail: `Signed a fresh challenge: ${detail}` });
      }
    } else if (p.kind === "retrying") {
      const why = p.reason === "board_full" ? "The demo board is full and the bot is freeing seats." : "The bot cannot yet tell whether an earlier join of this account landed.";
      t.update("join", { detail: why, wait: `${why} Trying again in ${p.seconds} s (try ${p.attempt} of ${p.of}).` });
    } else {
      t.update("join", { hash: p.txHash, hashKind: "evm", wait: "The bot sent the addMember. Waiting for its receipt on the public EVM RPC." });
    }
  });
  const block = await confirmJoin(txHash, guest.identity.evm, boardId);
  const after = await retryRead(() => readBoard(boardId), signal);
  if (!after.members.some((m) => sameAccount(m, guest.identity.evm))) throw new Error("The addMember landed but this account is not a member.");
  t.end("join", "done", `The addMember landed in block ${block}; this account is 1 of ${after.members.length} members.`);
}

/**
 * The whole guest journey in this browser: sponsorship, both key registrations, the challenge and
 * the join, then the epoch key and the pack opened on this device. The identity is made or
 * opened before this runs (identity.ts), so a wrong passphrase never starts a journey. Each step
 * first reads what the chain already holds, so a return visit picks up where it stopped and never
 * pays twice for a key that is already there.
 *
 * @param session The open guest, and how long making or opening it took.
 * @param onChange Called with a fresh copy of the view after every change.
 * @param signal Stops the journey (Forget me); nothing more is shown after it fires.
 */
export async function runJourney(session: Pick<GuestSession, "guest" | "resumed"> & { tookMs?: number }, onChange: (view: JourneyView) => void, signal: AbortSignal): Promise<void> {
  const t = new Tracker(onChange, signal);
  try {
    if (BOARD_ID === null) throw new Error("NEXT_PUBLIC_DEMO_BOARD_ID is not set.");
    const boardId = BOARD_ID;

    const { guest, resumed } = session;
    t.start("identity", undefined, session.tookMs);
    t.account(guest.identity.qor1, guest.identity.evm);
    t.end("identity", "done", resumed ? "Opened the identity this browser keeps." : "Made a new identity. Its recovery words are locked in this browser with your passphrase.");

    await fundAndRegister(guest, signal, t);

    await joinBoard(t, guest, boardId, signal);

    t.start("epochKey", "Reading the board's grants and downloading the envelope sealed to this account.");
    const snapshot = await retryRead(() => readBoard(boardId), signal);
    const opened = await openGuestEpochKey(snapshot, guest, signal);
    t.epoch(snapshot.epoch);
    t.end("epochKey", "done", `Epoch ${snapshot.epoch}, from the envelope ${opened.grant.envelopeHash.slice(0, 10)}... (${opened.grant.envelopeSize} bytes), its size and SHA-256 checked against the registry.`);

    t.start("pack", "Waiting for the demo chair to post this epoch's pack. The bot posts one after a join; it can take a minute or two. Reading the board every 5 s.");
    const pack = await waitAndOpenPack(boardId, guest, { epoch: snapshot.epoch, epochKey: opened.epochKey }, signal, (epoch) =>
      t.update("pack", { detail: `The epoch moved to ${epoch} while waiting; opened its key from the envelope sealed to this account.` }),
    );
    t.pack(pack.text, { docId: pack.docId, epoch: pack.epoch, size: pack.size });
    t.end("pack", "done", `Pack ${pack.docId + 1n}, epoch ${pack.epoch}, ${pack.size} bytes, its size and SHA-256 checked, decrypted on this device.`);
    t.finish();
  } catch (error) {
    if (error instanceof Stopped || signal.aborted) return;
    t.fail(error);
  }
}
