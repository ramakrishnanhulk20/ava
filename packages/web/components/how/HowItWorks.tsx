"use client";

import { motion } from "motion/react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { useMediaQuery } from "../../lib/useMediaQuery";
import { HowStill, type StillKind } from "./HowStill";
import { HowVisual, type Stage } from "./HowVisual";

const WIDE_QUERY = "(min-width: 1024px)";
const EASE: [number, number, number, number] = [0.2, 0.8, 0.2, 1];

type Beat = {
  kind: StillKind;
  label: string;
  heading: string;
  body: ReactNode;
};

const BEATS: Beat[] = [
  {
    kind: "seal",
    label: "[ 01 · SEAL ]",
    heading: "Sealed on the chair's device.",
    body: "The chair's browser encrypts the pack before it leaves the device. Each director's copy of the key is sealed with ML-KEM-1024 to the encryption key their account published on QoreChain. The server only ever holds ciphertext.",
  },
  {
    kind: "sign",
    label: "[ 02 · SIGN ]",
    heading: "Every change is signed, and the chain checks it.",
    body: "Adding a director, posting a pack, removing someone: each is one action the chair signs with an ML-DSA-87 key. The registry checks that signature on chain with QoreChain's pqcVerify precompile. A server, a relayer or a stolen password cannot change a board.",
  },
  {
    kind: "remove",
    label: "[ 03 · REMOVE ]",
    heading: "Remove a director. The next pack stays shut.",
    body: (
      <>
        Removing a director rotates the board key to everyone who stays. They keep what they already opened, and Ava
        shows exactly what that is. Everything after is sealed to a key they{" "}
        <span className="text-accent">never receive</span>.
      </>
    ),
  },
];

const STAGES: Stage[] = ["seal", "sign", "remove"];

export function HowItWorks() {
  const wide = useMediaQuery(WIDE_QUERY);
  const beatRefs = useRef<Array<HTMLDivElement | null>>([]);
  const [active, setActive] = useState<number | null>(null);

  useEffect(() => {
    if (!wide) return;

    // Beats whose content touches the thin band at the middle of the screen. The nearest to the exact middle wins.
    const inBand = new Set<number>();
    const pickNearest = () => {
      if (inBand.size === 0) return;
      const middle = window.innerHeight / 2;
      let best = -1;
      let bestGap = Infinity;
      for (const index of inBand) {
        const box = beatRefs.current[index]?.getBoundingClientRect();
        if (!box) continue;
        const gap = Math.abs(box.top + box.height / 2 - middle);
        if (gap < bestGap) {
          best = index;
          bestGap = gap;
        }
      }
      if (best >= 0) setActive(best);
    };

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          const index = Number((entry.target as HTMLElement).dataset.beat);
          if (entry.isIntersecting) inBand.add(index);
          else inBand.delete(index);
        }
        pickNearest();
      },
      { rootMargin: "-45% 0px -45% 0px" },
    );

    for (const element of beatRefs.current) if (element) observer.observe(element);
    return () => {
      observer.disconnect();
      setActive(null);
    };
  }, [wide]);

  const stage: Stage = active === null ? "idle" : (STAGES[active] ?? "idle");

  return (
    <section id="how" className="relative mx-auto w-full max-w-[1440px] overflow-x-clip px-5 py-24 sm:px-14 lg:py-40">
      <div className="lg:grid lg:grid-cols-12 lg:gap-x-8">
        <div className="lg:col-span-7">
          <p className="mono flex items-center gap-2.5 text-[12px] tracking-[0.16em] text-ink-soft">
            <span className="size-2 rounded-full bg-accent" aria-hidden="true" />[ HOW IT WORKS ]
          </p>
          <h2 className="display mt-6 max-w-[14em] text-[clamp(2.5rem,4.8vw,4.75rem)] leading-none tracking-[-0.02em] text-ink">
            Three things happen, and the chain sees every one.
          </h2>
        </div>
      </div>

      <div className="mt-24 lg:grid lg:grid-cols-12 lg:gap-x-8">
        <div className="hidden lg:col-span-6 lg:block">
          <div className="sticky top-[calc(50vh-290px)]">
            <HowVisual stage={stage} />
          </div>
        </div>
        <div className="flex flex-col gap-24 lg:col-span-5 lg:col-start-8 lg:gap-0">
          {BEATS.map((beat, index) => (
            <div key={beat.kind} className="lg:flex lg:min-h-screen lg:items-center">
              <motion.div
                ref={(element) => {
                  beatRefs.current[index] = element;
                }}
                data-beat={index}
                className={`beat ${wide && active !== index ? "beat-dim" : ""}`}
                initial={{ y: 24 }}
                whileInView={{ y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.7, ease: EASE }}
              >
                <p className="mono text-[12px] tracking-[0.16em] text-ink-soft">{beat.label}</p>
                <h3 className="display mt-5 max-w-[13em] text-[clamp(2rem,3.2vw,3rem)] leading-[1.04] tracking-[-0.015em] text-ink">
                  {beat.heading}
                </h3>
                <p className="mt-5 max-w-[34ch] text-[18px] leading-[1.6] text-ink-soft">{beat.body}</p>
                <HowStill kind={beat.kind} />
              </motion.div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
