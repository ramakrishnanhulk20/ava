"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { shortHash } from "../../lib/boardRules";
import { BOARD_ID, formatCount } from "../../lib/chain";
import { SHOWN_BYTES_PER_ROW, SHOWN_ROWS, hexRowsOf } from "../../lib/guest/shut";
import { Stopped } from "../../lib/guest/time";
import { runProof, type Outcome, type ProofRun } from "../../lib/proof/run";
import type { TrialKind } from "../../lib/proof/specimen";
import { Footer } from "../Footer";
import { Nav } from "../hero/Nav";
import { Cross, Tick } from "../proof/Glyphs";
import { TxHash } from "../proof/TxHash";

const LABEL = "mono text-[11px] tracking-[0.14em] text-ink-soft";
const CELL = "mono text-[11px] leading-[1.6] tracking-[0.12em]";
const REPO = "https://github.com/ramakrishnanhulk20/ava";

const WRITE_NAME: Record<string, string> = { addMember: "AN ADMISSION", removeMember: "A REMOVAL", rotateEpoch: "A KEY ROTATION", postDocument: "A PACK POST" };
const TRIAL_TEXT: Record<TrialKind, string> = {
  original: "The message it was signed for",
  other_board: "The same change, stated for the next board",
  next_nonce: "The same change, at the board's next nonce",
  other_registry: "The same change, under another contract's address",
  flipped_signature: "The right message, one bit of the signature flipped",
};

/** Why the registry refused a replay, in plain words, by the name of its refusal. The first check to fail decides the name. */
const REPLAY_WHY: Record<string, string> = {
  DocRefUsed: "The registry already holds a pack under this reference, so it will not take it twice.",
  DeadlineExpired: "The signature's deadline has passed. No signature outlives its hour.",
  BadSignature: "The board has moved on to a later nonce, so the signature no longer matches what the registry builds.",
  WrongEpoch: "The board is in a later epoch than the one this change was signed for.",
  NotMember: "The member this change removes is no longer on the board.",
  AlreadyMember: "The member this change adds is already on the board.",
};

type Phase = { state: "running" } | { state: "done" } | { state: "failed"; error: string };

/** A result that has not come back yet: a short moving line, so the row never looks empty or finished. */
function Pending() {
  return <span className="demo-track block w-24" />;
}

function Held({ outcome }: { outcome: Outcome | undefined }) {
  if (outcome === undefined) return <Pending />;
  return outcome.refused ? (
    <span className={`${CELL} flex items-center gap-2 text-ink`}>
      <Tick size={14} drawAfter={0} />
      REFUSED{outcome.name === undefined ? "" : ` · ${outcome.name}`}
    </span>
  ) : (
    <span className={`${CELL} flex items-center gap-2 text-ink`}>
      <Cross size={12} />
      NOT REFUSED
    </span>
  );
}

function Verdict({ valid, expected }: { valid: boolean | undefined; expected: boolean }) {
  if (valid === undefined) return <Pending />;
  return (
    <span className={`${CELL} flex items-center gap-2 ${valid === expected ? "text-ink" : "text-accent"}`}>
      {valid === expected ? <Tick size={14} drawAfter={0} /> : <Cross size={12} />}
      {valid ? "VALID" : "NOT VALID"}
    </span>
  );
}

function Section({ number, title, children, aside }: { number: string; title: ReactNode; children: ReactNode; aside: ReactNode }) {
  return (
    <section className="border-t border-rule py-16 lg:grid lg:grid-cols-12 lg:gap-x-8 lg:py-24">
      <div className="lg:col-span-5">
        <p className="display text-[56px] leading-none text-ink" aria-hidden="true">
          {number}
        </p>
        <h2 className="display mt-5 max-w-[14em] text-[clamp(2rem,3.2vw,3rem)] leading-[1.04] tracking-[-0.015em] text-ink">{title}</h2>
        <div className="mt-5 max-w-[44ch] text-[17px] leading-[1.6] text-ink-soft">{children}</div>
      </div>
      <div className="mt-10 lg:col-span-6 lg:col-start-7 lg:mt-2">{aside}</div>
    </section>
  );
}

function Row({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 border-t border-rule py-4 first:border-t-0">
      <p className="max-w-[34ch] text-[15px] leading-[1.45] text-ink">{label}</p>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

/**
 * The proof page: four attacks on the demo board that the visitor's own browser runs against the
 * public chain as the page loads. Every answer shown is what the chain or the blob store said a
 * moment ago; none of it passes through our server and none of it can change the board.
 */
export function ProofPage() {
  const [run, setRun] = useState<ProofRun | undefined>(undefined);
  const [phase, setPhase] = useState<Phase>({ state: "running" });
  const live = useRef<AbortController | undefined>(undefined);

  const start = useCallback(() => {
    live.current?.abort();
    const controller = new AbortController();
    live.current = controller;
    setRun(undefined);
    if (BOARD_ID === null) {
      setPhase({ state: "failed", error: "The demo board is not configured on this deployment." });
      return;
    }
    setPhase({ state: "running" });
    runProof(BOARD_ID, controller.signal, setRun)
      .then(() => {
        if (!controller.signal.aborted) setPhase({ state: "done" });
      })
      .catch((error: unknown) => {
        if (error instanceof Stopped || controller.signal.aborted) return;
        setPhase({ state: "failed", error: "The chain did not answer one of the reads. What came back before it is shown; run it again for the rest." });
      });
  }, []);

  useEffect(() => {
    start();
    return () => live.current?.abort();
  }, [start]);

  const board = run?.board;
  const specimen = run?.specimen;
  const stopped = phase.state !== "running";
  // Once the run has ended, a row with no answer says so instead of moving for ever.
  const orMissing = (node: ReactNode, known: boolean): ReactNode => (known || !stopped ? node : <span className={`${CELL} text-ink-soft`}>NOT RUN</span>);
  const packRows = run?.pack === undefined ? [] : hexRowsOf(run.pack.firstBytes, SHOWN_ROWS, SHOWN_BYTES_PER_ROW);

  return (
    <main className="w-full overflow-x-clip">
      <div className="mx-auto w-full max-w-[1440px] px-5 pt-7 pb-24 sm:px-14">
        <Nav />

        <header className="pt-[120px] pb-16">
          <p className="mono flex items-center gap-2.5 text-[12px] tracking-[0.16em] text-ink-soft">
            <span className="size-2 rounded-full bg-accent" aria-hidden="true" />[ THE PROOF · RUN FROM YOUR BROWSER, JUST NOW ]
          </p>
          <h1 className="headline display mt-6 max-w-[11em] text-[clamp(3rem,7vw,7rem)] leading-[0.94] tracking-[-0.025em] text-ink">
            Do not take our word. <span className="text-accent">Attack</span> it.
          </h1>
          <p className="mt-7 max-w-[52ch] text-[18px] leading-[1.6] text-ink-soft">
            As this page loaded, your browser made four attacks on the demo board, straight to QoreChain&apos;s public endpoint. They are reads and simulated calls: nothing is sent, nothing passes through our server, and nothing here can change the board.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-x-7 gap-y-4">
            <button type="button" onClick={start} disabled={phase.state === "running"} className="btn-primary cursor-pointer">
              {phase.state === "running" ? "Running the attacks" : "Run them again"} {phase.state === "running" ? null : <span className="arrow">→</span>}
            </button>
            <p className={LABEL} aria-live="polite">
              {board === undefined
                ? "READING THE BOARD"
                : `BOARD ${board.boardId.toString()} · EPOCH ${formatCount(board.epoch)} · NONCE ${formatCount(board.nonce)} · READ AT BLOCK ${formatCount(board.blockNumber)}`}
            </p>
          </div>
          {phase.state === "failed" ? <p className="mt-5 max-w-[52ch] text-[15px] leading-[1.5] text-ink">{phase.error}</p> : null}
        </header>

        <Section
          number="01"
          title={
            <>
              The chair&apos;s classical key is <span className="text-accent">not enough</span>.
            </>
          }
          aside={
            <div className="paper p-6 sm:p-8">
              <p className={LABEL}>[ A KEY ROTATION FOR THIS BOARD, RIGHT IN EVERY FIELD, WITH NO ML-DSA-87 SIGNATURE ]</p>
              <div className="mt-4">
                <Row label="Sent from the chair's own address">{orMissing(<Held outcome={run?.unsigned?.asChair} />, run?.unsigned !== undefined)}</Row>
                <Row label="Sent from a stranger's address">{orMissing(<Held outcome={run?.unsigned?.asStranger} />, run?.unsigned !== undefined)}</Row>
              </div>
            </div>
          }
        >
          <p>
            This board&apos;s chair{board === undefined ? "" : `, ${shortHash(board.chair)},`} is a Q-Day Drill account: its ordinary ECDSA key was handed to the drill&apos;s attacker. The registry does not care who sends a change. It asks one thing: did the chair&apos;s registered ML-DSA-87 key sign it.
          </p>
        </Section>

        <Section
          number="02"
          title={
            <>
              A change that landed cannot be <span className="text-accent">played again</span>.
            </>
          }
          aside={
            <div className="paper p-6 sm:p-8">
              <p className={LABEL}>
                {specimen === undefined
                  ? "[ FINDING THE BOARD'S NEWEST CHANGE ]"
                  : `[ ${WRITE_NAME[specimen.write.functionName] ?? "A CHANGE"} · BLOCK ${formatCount(specimen.block)} · BOARD NONCE ${formatCount(specimen.nonce)} ]`}
              </p>
              <p className={`${LABEL} mt-2 flex flex-wrap items-center gap-x-2`}>{specimen === undefined ? null : <TxHash hash={specimen.txHash} className="font-mono text-[11px]" />}</p>
              <div className="mt-4">
                <Row label="Its exact bytes, real signature and all, sent again now">{orMissing(<Held outcome={run?.replay} />, run?.replay !== undefined)}</Row>
              </div>
              {run?.replay?.refused === true && run.replay.name !== undefined && REPLAY_WHY[run.replay.name] !== undefined ? (
                <p className="mt-3 max-w-[48ch] text-[14px] leading-[1.5] text-ink-soft">{REPLAY_WHY[run.replay.name]}</p>
              ) : null}
            </div>
          }
        >
          <p>
            Your browser found the newest change to the board in the registry&apos;s own events, read its bytes back from the chain and sent them again. Each signature names one board, one nonce and a deadline at most an hour ahead, so the same bytes are worth nothing a second time.
          </p>
        </Section>

        <Section
          number="03"
          title={
            <>
              One signature fits <span className="text-accent">one message</span>.
            </>
          }
          aside={
            <div className="paper overflow-x-auto p-6 sm:p-8">
              <div className="min-w-[520px]">
                <div className="grid grid-cols-[1fr_128px_128px] items-end gap-x-4 border-b border-rule pb-3">
                  <p className={LABEL}>[ THE MESSAGE ]</p>
                  <p className={LABEL}>QORECHAIN</p>
                  <p className={LABEL}>THIS BROWSER</p>
                </div>
                {(Object.keys(TRIAL_TEXT) as TrialKind[]).map((what) => {
                  const found = run?.signatures?.find((s) => s.what === what);
                  const known = found !== undefined;
                  return (
                    <div key={what} className="grid grid-cols-[1fr_128px_128px] items-center gap-x-4 border-b border-rule py-4 last:border-b-0">
                      <p className="text-[15px] leading-[1.45] text-ink">{TRIAL_TEXT[what]}</p>
                      <div>{orMissing(<Verdict valid={found?.chain} expected={what === "original"} />, known)}</div>
                      <div>{orMissing(<Verdict valid={found?.here} expected={what === "original"} />, known)}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          }
        >
          <p>
            The same real signature, tried on five messages. The left answer is the chain&apos;s own ML-DSA-87 check, the one the registry calls. The right one is the same check run in this browser. They should agree on every row: valid once, and never again.
          </p>
        </Section>

        <Section
          number="04"
          title={
            <>
              What we store is ciphertext the chain has <span className="text-accent">pinned</span>.
            </>
          }
          aside={
            <div className="paper p-6 sm:p-8">
              <p className={LABEL}>
                {run?.pack === undefined ? "[ FETCHING THE NEWEST PACK AS STORED ]" : `[ PACK ${(run.pack.docId + 1n).toString()} AS OUR BLOB STORE HOLDS IT · ${formatCount(run.pack.size)} BYTES ]`}
              </p>
              <div className="mt-4 font-mono text-[10px] leading-[1.9] tracking-[0.06em] whitespace-nowrap text-ink/45" aria-hidden="true">
                {packRows.length > 0 ? packRows.map((row, i) => <div key={i}>{row}</div>) : <div className="h-[171px]" />}
              </div>
              <div className="mt-4">
                <Row label="SHA-256 of those bytes, computed here">
                  {orMissing(run?.pack === undefined ? <Pending /> : <span className="font-mono text-[11px] text-ink">{shortHash(run.pack.computed)}</span>, run?.pack !== undefined)}
                </Row>
                <Row label="The hash the registry recorded for the pack">
                  {orMissing(run?.pack === undefined ? <Pending /> : <span className="font-mono text-[11px] text-ink">{shortHash(run.pack.recorded)}</span>, run?.pack !== undefined)}
                </Row>
                <Row label="The same bytes, to the last one">
                  {orMissing(
                    run?.pack === undefined ? (
                      <Pending />
                    ) : (
                      <span className={`${CELL} flex items-center gap-2 text-ink`}>
                        {run.pack.same ? <Tick size={14} drawAfter={0} /> : <Cross size={12} />}
                        {run.pack.same ? "SAME" : "DIFFERENT"}
                      </span>
                    ),
                    run?.pack !== undefined,
                  )}
                </Row>
              </div>
            </div>
          }
        >
          <p>
            A pack&apos;s name and contents never go on chain: only a hash, a size and a time. What sits in our storage is the encrypted bytes that hash names, so a changed or swapped pack would not match.
          </p>
          <p className="mt-4">
            On this demo board the chair is our own bot, so our server wrote this pack. On a board you create in the board room, the pack is encrypted in your browser and we only ever hold its ciphertext.
          </p>
        </Section>

        <section className="border-t border-rule pt-16">
          <p className="max-w-[52ch] text-[18px] leading-[1.6] text-ink">
            The fifth proof needs you: join the demo board, leave it, and watch the next pack stay shut to the keys in your own browser.
          </p>
          <p className="mono mt-7 flex flex-wrap gap-x-7 gap-y-3 text-[12px] tracking-[0.12em]">
            <Link href="/demo" className="link-draw text-ink">
              [ JOIN, THEN LEAVE, THE DEMO BOARD ]
            </Link>
            <a href={`${REPO}/blob/main/docs/security/threat-model.md`} target="_blank" rel="noopener" className="link-draw text-ink">
              [ THE THREAT MODEL ]
            </a>
            <a href={`${REPO}/tree/main/security`} target="_blank" rel="noopener" className="link-draw text-ink">
              [ THE FULL ATTACK SUITE AND ITS LIVE RESULTS ]
            </a>
          </p>
        </section>
      </div>
      <Footer />
    </main>
  );
}
