import type { JourneyView, StepKey, StepLine } from "../../lib/guest/journey";
import { NEXT_PACK_WAIT, REMOVAL_WAIT, type LeaveStepKey, type LeaveView } from "../../lib/guest/leaveJourney";

export type ChapterState = "waiting" | "running" | "done" | "failed";

export type ChapterId = "identity" | "sponsor" | "keys" | "challenge" | "admitted" | "pack" | "leave" | "shut";

type AnyStep = StepLine<StepKey | LeaveStepKey>;

type ChapterPlan = {
  id: ChapterId;
  number: string;
  title: string;
  steps: StepKey[];
};

export const CHAPTER_PLAN: ChapterPlan[] = [
  { id: "identity", number: "01", title: "A quantum-safe identity, made on this device", steps: ["identity"] },
  { id: "sponsor", number: "02", title: "Test funds from our sponsor", steps: ["sponsor"] },
  { id: "keys", number: "03", title: "Your keys on QoreChain", steps: ["mldsa", "mlkem", "keys"] },
  { id: "challenge", number: "04", title: "The chair's challenge, signed by you", steps: ["challenge"] },
  { id: "admitted", number: "05", title: "Admitted to the board", steps: ["join", "epochKey"] },
  { id: "pack", number: "06", title: "The next pack, opened on your device", steps: ["pack"] },
];

/** The transaction lines a chapter shows once it is done. Only steps that carry a hash appear. */
const HASH_LABELS: Partial<Record<StepKey | LeaveStepKey, string>> = {
  sponsor: "SPONSOR SEND",
  mldsa: "SIGNING KEY · ML-DSA-87",
  mlkem: "SEALING KEY · ML-KEM-1024",
  join: "ADMITTED · ADDMEMBER",
  removal: "REMOVED · REMOVEMEMBER",
};

const LEAVE_PLAN: { id: ChapterId; number: string; title: string; steps: LeaveStepKey[] }[] = [
  { id: "leave", number: "07", title: "Your removal, signed by you", steps: ["request", "removal"] },
  { id: "shut", number: "08", title: "The next pack, shut to you", steps: ["nextPack", "shut"] },
];

export type ChapterView = {
  id: ChapterId;
  number: string;
  title: string;
  state: ChapterState;
  steps: AnyStep[];
  /** performance.now() of the chapter's first step start, if any step has started. */
  startedAt?: number;
  /** performance.now() of the chapter's last step end, once the chapter is done or failed. */
  endedAt?: number;
  details: string[];
  /** One or two plain sentences about what the chapter did, built from the view. Only once the chapter is done. */
  summary?: string;
  hashes: Array<{ label: string; hash: string }>;
};

function stateOf(steps: AnyStep[], journeyActive: boolean): ChapterState {
  if (steps.some((s) => s.state === "failed")) return "failed";
  if (steps.some((s) => s.state === "running")) return "running";
  if (steps.every((s) => s.state === "done" || s.state === "skipped")) return "done";
  // Between two steps of one chapter nothing is running for a moment; the chapter is still under way.
  if (journeyActive && steps.some((s) => s.state === "done" || s.state === "skipped")) return "running";
  return "waiting";
}

function count(value: number | bigint): string {
  return value.toLocaleString("en-US");
}

/** The chapter in plain sentences. Every number comes from the view; nothing here is typed in. */
function summaryOf(id: ChapterId, steps: StepLine[], view: JourneyView): string | undefined {
  const first = steps[0];
  switch (id) {
    case "identity":
      return first?.detail?.startsWith("Opened")
        ? "Opened with your passphrase. Its keys never leave this browser."
        : "Made on this device. Its recovery words are locked in this browser with your passphrase.";
    case "sponsor": {
      const amount = sponsoredAmount(view);
      if (first?.state === "skipped" || amount === undefined)
        return "No funding was needed: this account already had enough.";
      return `${amount} arrived, enough for both key registrations.`;
    }
    case "keys":
      return "Both keys are on chain: the signing key with its proof of possession, the sealing key published for anyone to encrypt to.";
    case "challenge": {
      if (first?.state === "skipped") return "You were already a member, so no challenge was needed.";
      const bytes = first?.detail?.match(/^(\d+) bytes/)?.[1];
      return bytes === undefined
        ? undefined
        : `${count(Number(bytes))} bytes naming this board and your account, rebuilt here and checked before you signed.`;
    }
    case "admitted": {
      const members = steps.find((s) => s.key === "join")?.detail?.match(/of (\d+) members/)?.[1];
      const sentences = [
        members === undefined ? undefined : `You are one of ${count(Number(members))} members.`,
        view.epoch === undefined
          ? undefined
          : `Your key for epoch ${count(view.epoch)} came from the envelope the registry recorded, checked by size and hash.`,
      ].filter((s): s is string => s !== undefined);
      return sentences.length === 0 ? undefined : sentences.join(" ");
    }
    case "pack": {
      const info = view.packInfo;
      return info === undefined
        ? undefined
        : `Pack ${count(info.docId + 1n)} from epoch ${count(info.epoch)}, ${count(info.size)} bytes, checked by size and hash and decrypted here.`;
    }
  }
}

function chapterOf(plan: { id: ChapterId; number: string; title: string }, steps: AnyStep[], active: boolean, summary: () => string | undefined): ChapterView {
  const state = stateOf(steps, active);
  const starts = steps.map((s) => s.startedAt).filter((t): t is number => t !== undefined);
  const ends = steps.map((s) => s.endedAt).filter((t): t is number => t !== undefined);
  return {
    id: plan.id,
    number: plan.number,
    title: plan.title,
    state,
    steps,
    startedAt: starts.length > 0 ? Math.min(...starts) : undefined,
    endedAt: (state === "done" || state === "failed") && ends.length > 0 ? Math.max(...ends) : undefined,
    details: steps.map((s) => s.detail).filter((d): d is string => d !== undefined && d !== ""),
    summary: state === "done" ? summary() : undefined,
    hashes: steps.flatMap((s) =>
      s.hash !== undefined && HASH_LABELS[s.key] !== undefined ? [{ label: HASH_LABELS[s.key] as string, hash: s.hash }] : [],
    ),
  };
}

export function chaptersOf(view: JourneyView): ChapterView[] {
  const active = !view.finished;
  return CHAPTER_PLAN.map((plan) => {
    const steps = plan.steps
      .map((key) => view.steps.find((s) => s.key === key))
      .filter((s): s is StepLine => s !== undefined);
    return chapterOf(plan, steps, active, () => summaryOf(plan.id, steps, view));
  });
}

/** The two chapters of the removal, in plain sentences. Every number comes from the view. */
function leaveSummary(id: ChapterId, view: LeaveView): string | undefined {
  if (id === "leave") {
    const removal = view.removal;
    if (removal === undefined) return undefined;
    if (removal.txHash === undefined) return `This seat was already off the board at block ${count(removal.block)}, so there was nothing left to sign.`;
    return `224 bytes naming this board and your account under their own tag, rebuilt here and checked before you signed. The removal landed in block ${count(removal.block)} and moved the board to epoch ${count(removal.epoch)}; ${count(removal.members)} members remain.`;
  }
  const shut = view.shut;
  if (shut === undefined) return undefined;
  const envelopes = shut.envelopesTried === 1 ? "The one envelope of that epoch refused your keys" : `All ${count(shut.envelopesTried)} envelopes of that epoch refused your keys`;
  const old = shut.oldEpoch === undefined ? "" : ` Your epoch ${count(shut.oldEpoch)} key does not open it either.`;
  return `Pack ${count(shut.docId + 1n)} of epoch ${count(shut.epoch)} is on chain, ${count(shut.size)} bytes, checked here by size and hash. ${envelopes}: none is sealed to you.${old}`;
}

/** Chapters 07 and 08, once the guest has asked to leave. */
export function leaveChaptersOf(view: LeaveView): ChapterView[] {
  const active = !view.finished;
  return LEAVE_PLAN.map((plan) => {
    const steps = plan.steps
      .map((key) => view.steps.find((s) => s.key === key))
      .filter((s): s is StepLine<LeaveStepKey> => s !== undefined);
    return chapterOf(plan, steps, active, () => leaveSummary(plan.id, view));
  });
}

/** Seconds as one decimal, never below zero: the clock reading can trail a step's start by a tick. */
export function secondsBetween(from: number | undefined, to: number): string | undefined {
  if (from === undefined) return undefined;
  return `${(Math.max(0, to - from) / 1000).toFixed(1)} S`;
}

const ADMITTING =
  "The demo chair is admitting you: it signs your addMember and our relayer submits it. About a minute.";
const POSTING =
  "The chair is posting the next pack, sealed to everyone on the board now. Up to two minutes if the board is freeing seats.";
const REMOVING =
  "The demo chair is removing you: it makes a new board key, seals it to everyone still on the board and signs your removeMember. About a minute.";
const POSTING_NEXT = "The chair is posting the next pack under the new key. A minute or two.";

/**
 * The step that is running now and has a wait to explain, once it has run past two seconds. The two long
 * waits get a plainer line, unless the journey has already said something more specific (a retry, a receipt).
 */
export function waitText(chapter: ChapterView, now: number): string | undefined {
  const running = chapter.steps.find((s) => s.state === "running");
  if (running?.wait === undefined || running.startedAt === undefined) return undefined;
  if (now - running.startedAt <= 2_000) return undefined;
  if (running.key === "join" && running.wait.startsWith("The bot checks the ML-DSA-87 signature")) return ADMITTING;
  if (running.key === "pack" && running.wait.startsWith("Waiting for the demo chair to post")) return POSTING;
  if (running.key === "removal" && running.wait === REMOVAL_WAIT) return REMOVING;
  if (running.key === "nextPack" && running.wait === NEXT_PACK_WAIT) return POSTING_NEXT;
  return running.wait;
}

/** The join's answer for an address that has had its seat: trying again cannot change it. */
export const ALREADY_ADMITTED = /already_admitted/;

/** The error in plain words, with what to do next. Refusals the journey is known to end on are mapped; the rest keep their own words. */
export function plainError(message: string): string {
  if (/sponsor refused/i.test(message) && /daily_limit/.test(message)) {
    return "The sponsor has given out today's testnet funds. Try again after 00:00 UTC.";
  }
  if (/board_full/.test(message)) {
    return "The board is full right now. It frees seats every few minutes; try again shortly.";
  }
  if (ALREADY_ADMITTED.test(message)) {
    return "This address has already had its seat on the demo board, and each address is admitted once. You can still check that the board's current pack is shut to it.";
  }
  if (/demo_busy/.test(message)) {
    return "The demo chair has sent every transaction it is allowed this hour. Try again once the hour turns.";
  }
  if (/rate_limited/.test(message)) {
    return "Too many requests from this network in the last hour. Try again later.";
  }
  if (/should not happen/.test(message)) return message;
  if (
    /failed to fetch|network|timed out|did not answer|not seen on chain|ran out of time|did not reach|load failed/i.test(
      message,
    )
  ) {
    return "The testnet did not answer. Your progress is kept; try again.";
  }
  return `${message} Your progress is kept; try again.`;
}

/** The amount the sponsor's step states, when it states one, as "0.25 QOR". */
export function sponsoredAmount(view: JourneyView): string | undefined {
  const detail = view.steps.find((s) => s.key === "sponsor")?.detail;
  return detail?.match(/^Balance (\d+(?:\.\d+)? QOR)/)?.[1];
}
