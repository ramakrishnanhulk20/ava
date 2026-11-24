"use client";

import { motion, useInView } from "motion/react";
import { useRef, type ReactNode } from "react";
import { formatCount } from "../../lib/chain";
import { keyText, liveText, shortQor1, useDrillAccount } from "../../lib/drillAccount";
import { shortHash } from "../../lib/boardRules";
import { useMotionMode } from "../../lib/motionMode";
import { Seal } from "../hero/Seal";

const EASE: [number, number, number, number] = [0.2, 0.8, 0.2, 1];
const SOFT = "rgba(247, 244, 242, 0.6)";
const LABEL = "mono text-[10px] tracking-[0.16em]";

type RowProps = {
  label: string;
  children: ReactNode;
};

function Row({ label, children }: RowProps) {
  return (
    <div>
      <p className={LABEL} style={{ color: "rgba(247, 244, 242, 0.5)" }}>
        {label}
      </p>
      <div className="mt-1.5 font-mono text-[13px] leading-[1.5] text-on-ink">{children}</div>
    </div>
  );
}

export function DrillBand() {
  const drill = useDrillAccount();
  const mode = useMotionMode();
  const copyRef = useRef<HTMLDivElement>(null);
  const seen = useInView(copyRef, { once: true, amount: 0.2 });
  // Before scripts run, and under reduced motion, everything simply shows. The hiding only starts once the page can also reveal it.
  const hidden = mode === "full" && !seen;

  const rise = (delay: number, y: number, rotate = 0) => ({
    initial: false as const,
    animate: hidden ? { opacity: 0, y, rotate } : { opacity: 1, y: 0, rotate: 0 },
    transition: hidden ? { duration: 0 } : { duration: 0.7, ease: EASE, delay },
  });

  const boardFailing = drill.board.status === "retrying" || drill.board.status === "down";
  const changes = liveText(
    drill.board.nonce === null ? null : `${formatCount(drill.board.nonce)}, EVERY ONE SIGNED WITH ML-DSA-87`,
    boardFailing,
  );
  const key = liveText(keyText(drill.key), drill.keyFailing);

  return (
    <section id="drill" data-ink-surface className="relative w-full overflow-x-clip bg-ink py-24 text-on-ink sm:py-40">
      <div className="mx-auto w-full max-w-[1440px] px-5 sm:px-14">
        <div className="lg:grid lg:grid-cols-12 lg:items-center lg:gap-x-8">
          <div ref={copyRef} className="lg:col-span-7">
            <p className="mono flex items-center gap-2.5 text-[12px] tracking-[0.16em]" style={{ color: SOFT }}>
              <span className="size-2 rounded-full bg-accent-on-ink" aria-hidden="true" />[ THE Q-DAY DRILL · 18 NOV ]
            </p>
            <motion.h2
              className="display mt-6 max-w-[13em] text-[clamp(2.5rem,4.8vw,4.75rem)] leading-none tracking-[-0.02em] text-on-ink"
              {...rise(0, 24)}
            >
              We handed the chair&apos;s classical key to an <span className="text-accent-on-ink">attacker</span>.
            </motion.h2>
            <motion.p
              className="mt-6 max-w-[44ch] text-[18px] leading-[1.6]"
              style={{ color: "rgba(247, 244, 242, 0.72)" }}
              {...rise(0, 24)}
            >
              On 18 November the fest ran a 24-hour drill: a bot that holds an account&apos;s classical ECDSA key tries
              everything that key allows. Ava&apos;s demo chair is one of those drill accounts. Its classical key buys
              nothing on the board, because every board change also needs the chair&apos;s ML-DSA-87 signature, and the
              chain checks it.
            </motion.p>
            <p className="mono mt-6 max-w-[52ch] text-[12px] tracking-[0.12em]" style={{ color: SOFT }}>
              THE ORGANISERS PUBLISH THE DRILL KEYS AFTER THE DRILL. WHEN THEY DO, THIS PAGE WILL LET YOU TRY THE
              CHAIR&apos;S KEY YOURSELF.{" "}
              <a
                href="https://build.qorechain.io/rules"
                target="_blank"
                rel="noopener"
                className="link-draw text-on-ink"
              >
                [ FEST RULES ]
              </a>
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
                <div className="absolute -top-10 -right-10" aria-hidden="true">
                  <Seal size={56} ringText={null} state="reformed" />
                </div>
                <div className="flex flex-col gap-[18px]">
                  <Row label="ACCOUNT">
                    <p>{shortQor1(drill.qor1)}</p>
                    <p style={{ color: SOFT }}>{shortHash(drill.evm)}</p>
                  </Row>
                  <Row label="CLASSICAL KEY (SECP256K1)">
                    <p>HANDED TO THE DRILL&apos;S ATTACKER BOT</p>
                  </Row>
                  <Row label="ML-DSA-87 KEY">
                    <p className="flex items-center gap-2">
                      <span
                        className="size-1.5 shrink-0 rounded-full"
                        style={{ background: drill.key === "proven" ? "var(--live)" : "rgba(247, 244, 242, 0.4)" }}
                        aria-hidden="true"
                      />
                      {key}
                    </p>
                  </Row>
                  <Row label={`BOARD CHANGES ON DEMO BOARD ${drill.board.id}`}>
                    <p>{changes}</p>
                  </Row>
                  <Row label="WHAT THE CLASSICAL KEY ALONE CAN CHANGE">
                    <p className="text-accent-on-ink">NOTHING</p>
                  </Row>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  );
}
