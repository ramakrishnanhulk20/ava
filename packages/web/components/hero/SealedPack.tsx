"use client";

import { motion, useSpring } from "motion/react";
import { useEffect, useRef } from "react";
import { formatCount, useDemoBoard } from "../../lib/chain";
import { useMotionMode } from "../../lib/motionMode";
import { useMediaQuery } from "../../lib/useMediaQuery";
import { publishHeroProgress } from "../../lib/scrollProgress";
import { HexRows, PackSheets } from "./PackSheets";
import { Seal, type SealState } from "./Seal";

type SealedPackProps = {
  sealState?: SealState;
  ringText?: string | null;
  onSealDone?: () => void;
  /** Shows the line about what the removed director could and could not open. */
  caption?: boolean;
};

const SMALL_QUERY = "(max-width: 639px)";

export function SealedPack({ sealState = "intact", ringText, onSealDone, caption = false }: SealedPackProps) {
  const mode = useMotionMode();
  const small = useMediaQuery(SMALL_QUERY);
  const board = useDemoBoard();
  const frameRef = useRef<HTMLDivElement>(null);
  const tiltX = useSpring(0, { stiffness: 120, damping: 20 });
  const tiltY = useSpring(0, { stiffness: 120, damping: 20 });

  useEffect(() => {
    const hero = frameRef.current?.closest<HTMLElement>("[data-hero]");
    if (!hero || mode !== "full") return;

    const stopProgress = publishHeroProgress(hero);
    const finePointer = window.matchMedia("(pointer: fine)");
    const wide = window.matchMedia("(min-width: 1024px)");

    const onMove = (event: PointerEvent) => {
      if (!finePointer.matches || !wide.matches) return;
      const box = hero.getBoundingClientRect();
      const across = Math.min(1, Math.max(0, (event.clientX - box.left) / box.width));
      const down = Math.min(1, Math.max(0, (event.clientY - box.top) / box.height));
      tiltY.set((across - 0.5) * 10);
      tiltX.set((0.5 - down) * 10);
    };
    const onLeave = () => {
      tiltX.set(0);
      tiltY.set(0);
    };

    hero.addEventListener("pointermove", onMove);
    hero.addEventListener("pointerleave", onLeave);
    return () => {
      stopProgress();
      hero.removeEventListener("pointermove", onMove);
      hero.removeEventListener("pointerleave", onLeave);
    };
  }, [mode, tiltX, tiltY]);

  const sealSize = small ? 96 : 132;
  const haveBoard = board.status === "live" || board.status === "retrying";
  const liveLine =
    haveBoard && board.epoch !== null && board.memberCount !== null
      ? `DEMO BOARD ${board.id} · EPOCH ${formatCount(board.epoch)} · SEALED TO ${formatCount(board.memberCount)}`
      : "READING THE CHAIN";

  return (
    <div className="pack-wrap relative mx-auto mt-12 w-[min(420px,78vw)] lg:mt-0 lg:w-[min(400px,calc(100%-110px))]">
      <div ref={frameRef} aria-hidden="true" className="relative aspect-[460/580] w-full">
        <div
          className="pointer-events-none absolute top-1/2 left-1/2 size-[700px] -translate-x-1/2 -translate-y-1/2"
          style={{ background: "radial-gradient(closest-side, rgba(255, 255, 255, 0.55), transparent)" }}
        />
        <div className="pack-design">
          <div className="pack-scroll relative h-full w-full">
            <div className="pack-pose pack-enter relative h-full w-full">
              <motion.div className="relative h-full w-full" style={{ rotateX: tiltX, rotateY: tiltY }}>
                <div className="pack-float relative h-full w-full">
                  <PackSheets
                    liveLine={liveLine}
                    sealSize={sealSize}
                    seal={
                      <Seal size={sealSize} ringText={ringText} state={sealState} onDone={onSealDone} pressDelay={1} />
                    }
                  >
                    <HexRows />
                  </PackSheets>
                </div>
              </motion.div>
            </div>
          </div>
        </div>
      </div>
      <div className="absolute inset-x-0 top-full mt-10 min-h-6 text-center text-[15px] leading-6">
        {caption ? (
          <motion.p
            initial={mode === "full" ? { opacity: 0, y: 8 } : false}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease: "easeOut" }}
          >
            <span className="text-ink-soft">C could open pack 3. </span>
            <span className="text-ink">Not pack 4.</span>
          </motion.p>
        ) : null}
      </div>
    </div>
  );
}
