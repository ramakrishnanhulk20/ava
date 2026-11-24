"use client";

import { motion, useInView } from "motion/react";
import Link from "next/link";
import { useRef, type ReactNode } from "react";
import { shortHash } from "../../lib/boardRules";
import { shortQor1 } from "../../lib/drillAccount";
import type { JourneyView } from "../../lib/guest/journey";
import type { LeaveView } from "../../lib/guest/leaveJourney";
import { useMotionMode } from "../../lib/motionMode";
import { Seal } from "../hero/Seal";
import { Tick } from "../proof/Glyphs";
import { TxHash } from "../proof/TxHash";

const EASE: [number, number, number, number] = [0.2, 0.8, 0.2, 1];
const SOFT = "rgba(247, 244, 242, 0.6)";
const BODY = "rgba(247, 244, 242, 0.72)";
const LABEL = "mono text-[10px] tracking-[0.16em]";

type LeaveBandProps = {
  view: JourneyView;
  leave: LeaveView | undefined;
  /** True while the leave or the check of the next pack is running. */
  leaving: boolean;
  onLeave: () => void;
  onStartOver: () => void;
};

function count(value: number | bigint): string {
  return value.toLocaleString("en-US");
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <p className={LABEL} style={{ color: "rgba(247, 244, 242, 0.5)" }}>
        {label}
      </p>
      <div className="mt-1.5 font-mono text-[13px] leading-[1.5] text-on-ink">{children}</div>
    </div>
  );
}

function Cross() {
  return (
    <svg width={11} height={11} viewBox="0 0 12 12" fill="none" aria-hidden="true" className="shrink-0">
      <path d="M1.5 1.5 L10.5 10.5 M10.5 1.5 L1.5 10.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function Dot({ color }: { color: string }) {
  return <span className="size-1.5 shrink-0 rounded-full" style={{ background: color }} aria-hidden="true" />;
}

/**
 * The second act of the demo, under the pack the guest opened: the offer to leave the board, and,
 * once the guest has left, what this browser could and could not open, each line read from the
 * chain or from an attempt this browser made. Nothing in it is typed in.
 */
export function LeaveBand({ view, leave, leaving, onLeave, onStartOver }: LeaveBandProps) {
  const mode = useMotionMode();
  const copyRef = useRef<HTMLDivElement>(null);
  const seen = useInView(copyRef, { once: true, amount: 0.2 });
  const hidden = mode === "full" && !seen;
  const rise = (delay: number, y: number, rotate = 0) => ({
    initial: false as const,
    animate: hidden ? { opacity: 0, y, rotate } : { opacity: 1, y: 0, rotate: 0 },
    transition: hidden ? { duration: 0 } : { duration: 0.7, ease: EASE, delay },
  });

  const shut = leave?.shut;
  const removal = leave?.removal;
  const found = leave?.found;
  const opened = view.packInfo;
  const account = view.account;
  const joinHash = view.steps.find((s) => s.key === "join")?.hash;
  // A seat that was already gone when this page looked was not left here, so the copy does not say it was.
  const leftHere = removal?.txHash !== undefined;
  const goneBefore = removal !== undefined && !leftHere;
  const mark = shut !== undefined ? "result" : "offer";

  return (
    <section id="removal" data-ink-surface className="relative w-full overflow-x-clip bg-ink py-24 text-on-ink sm:py-36">
      <div className="mx-auto w-full max-w-[1440px] px-5 sm:px-14">
        <div className="lg:grid lg:grid-cols-12 lg:items-center lg:gap-x-8">
          <div ref={copyRef} className="lg:col-span-7">
            <p className="mono flex items-center gap-2.5 text-[12px] tracking-[0.16em]" style={{ color: SOFT }}>
              <span className="size-2 rounded-full bg-accent-on-ink" aria-hidden="true" />[ ACT TWO · THE REMOVAL ]
            </p>
            <motion.h2
              key={mark}
              className="display band-settle mt-6 max-w-[12em] text-[clamp(2.5rem,4.8vw,4.75rem)] leading-none tracking-[-0.02em] text-on-ink"
              {...rise(0, 24)}
            >
              {shut !== undefined ? (
                <>
                  Pack {count(shut.docId + 1n)} stays <span className="text-accent-on-ink">shut</span>.
                </>
              ) : goneBefore || opened === undefined ? (
                <>
                  This seat is gone. Watch the pack stay <span className="text-accent-on-ink">shut</span>.
                </>
              ) : (
                <>
                  Now leave. Watch the next pack stay <span className="text-accent-on-ink">shut</span>.
                </>
              )}
            </motion.h2>
            <motion.p className="mt-6 max-w-[46ch] text-[18px] leading-[1.6]" style={{ color: BODY }} {...rise(0, 24)}>
              {shut !== undefined
                ? leftHere
                  ? `You signed your own removal. In the same transaction the chair gave the board a new key, sealed to the ${count(shut.members)} members still on it. The pack posted next is closed to every key in this browser.`
                  : "This seat was off the board before this visit. The pack the board is on now is closed to every key in this browser."
                : goneBefore || opened === undefined
                  ? "A director who is off the board must be shut out of what comes next. This browser is trying the keys it holds on the board's current pack."
                  : "Taking a director off a board only counts if the next pack is closed to them. Sign your own removal: the chair gives the board a new key in the same transaction and posts a new pack, and this browser tries to open it with the keys it still holds."}
            </motion.p>

            {shut !== undefined ? (
              <div className="mt-9 flex flex-wrap items-center gap-x-7 gap-y-4">
                <button type="button" onClick={onStartOver} className="btn-on-ink cursor-pointer">
                  Start over as a new visitor
                </button>
                <Link
                  href="/#proof"
                  className="link-draw mono text-[12px] tracking-[0.14em] text-[rgba(247,244,242,0.72)] hover:text-on-ink focus-visible:text-on-ink"
                >
                  [ SEE WHO CAN READ EACH PACK ]
                </Link>
              </div>
            ) : (
              <div className="mt-9">
                <button type="button" onClick={onLeave} disabled={leaving} className="btn-on-ink cursor-pointer">
                  {leaving ? "Leaving · see chapters 07 and 08" : opened === undefined || goneBefore ? "Check the current pack" : "Leave the board"}
                  {leaving ? null : (
                    <span className="arrow" aria-hidden="true">
                      →
                    </span>
                  )}
                </button>
              </div>
            )}

            <p className="mono mt-7 max-w-[56ch] text-[12px] leading-[1.7] tracking-[0.12em]" style={{ color: SOFT }}>
              {shut !== undefined
                ? `${opened !== undefined ? `YOU KEEP PACK ${count(opened.docId + 1n)}, AS ANY REMOVED DIRECTOR KEEPS WHAT THEY ALREADY READ. ` : ""}EACH ADDRESS IS ADMITTED ONCE, SO THIS SEAT IS SPENT.`
                : "YOU KEEP THE PACK YOU ALREADY OPENED. EACH ADDRESS IS ADMITTED ONCE, SO THIS SEAT DOES NOT COME BACK."}
            </p>
          </div>

          <div className="mt-12 lg:col-span-5 lg:col-start-8 lg:mt-0">
            <motion.div className="w-[calc(100%-24px)] max-w-[420px] lg:w-full lg:max-w-none" {...rise(0.15, 32, 2.5)}>
              <div
                className="drill-card relative rounded-lg p-7"
                style={{
                  background: "#1e1b26",
                  border: "1px solid rgba(247, 244, 242, 0.12)",
                  boxShadow: "0 30px 60px -24px rgba(0, 0, 0, 0.6)",
                }}
              >
                {shut !== undefined ? (
                  <div className="absolute -top-10 -right-10" aria-hidden="true">
                    <Seal size={56} ringText={null} state="intact" />
                  </div>
                ) : null}
                <div className="flex flex-col gap-[18px]">
                  <Row label="YOUR ACCOUNT">
                    {account === undefined ? (
                      <p>…</p>
                    ) : (
                      <>
                        <p>{shortQor1(account.qor1)}</p>
                        <p style={{ color: SOFT }}>{shortHash(account.evm)}</p>
                      </>
                    )}
                  </Row>
                  <Row label="YOUR SEAT">
                    <p className="flex items-center gap-2">
                      <Dot color={removal === undefined ? "var(--live)" : "rgba(247, 244, 242, 0.4)"} />
                      {removal !== undefined
                        ? `REMOVED · EPOCH ${count(removal.epoch)}`
                        : `MEMBER${view.epoch === undefined ? "" : ` · EPOCH ${count(view.epoch)}`}`}
                    </p>
                  </Row>
                  {opened !== undefined ? (
                    <Row label={`PACK ${count(opened.docId + 1n)} · EPOCH ${count(opened.epoch)}`}>
                      <p className="flex items-center gap-2">
                        <Tick size={13} />
                        OPENED ON THIS DEVICE
                      </p>
                    </Row>
                  ) : null}
                  <Row label={found === undefined ? "THE NEXT PACK" : `PACK ${count(found.docId + 1n)} · EPOCH ${count(found.epoch)}`}>
                    {shut !== undefined ? (
                      <>
                        <p className="flex items-center gap-2 text-accent-on-ink">
                          <Cross />
                          LOCKED
                        </p>
                        <p style={{ color: SOFT }}>
                          {shut.envelopesTried === 1
                            ? "1 ENVELOPE TRIED, NOT SEALED TO YOU"
                            : `${count(shut.envelopesTried)} ENVELOPES TRIED, NONE SEALED TO YOU`}
                        </p>
                        {shut.oldEpoch !== undefined ? (
                          <p style={{ color: SOFT }}>YOUR EPOCH {count(shut.oldEpoch)} KEY DOES NOT OPEN IT</p>
                        ) : null}
                      </>
                    ) : (
                      <p style={{ color: SOFT }}>
                        {found !== undefined ? "TRYING YOUR KEYS ON IT" : leaving ? "WAITING FOR THE CHAIR TO POST IT" : "NOT POSTED YET"}
                      </p>
                    )}
                  </Row>
                  {joinHash !== undefined ? (
                    <Row label="ADMITTED · ADDMEMBER">
                      <TxHash hash={joinHash} onInk />
                    </Row>
                  ) : null}
                  {removal?.txHash !== undefined ? (
                    <Row label="REMOVED · REMOVEMEMBER">
                      <TxHash hash={removal.txHash} onInk />
                    </Row>
                  ) : null}
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  );
}
