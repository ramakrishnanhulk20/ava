"use client";

import { motion } from "motion/react";
import { useEffect, useId, useRef, useState, type AnimationEvent, type CSSProperties } from "react";
import { useMotionMode } from "../../lib/motionMode";

export type SealState = "intact" | "breaking" | "reformed";

export const DEFAULT_RING_TEXT = "SEALED · POST-QUANTUM · AVA ·";

type Phase = "rest" | "crack" | "split" | "press";

type SealProps = {
  size: number;
  /** Text around the rim. `null` leaves the rim bare. */
  ringText?: string | null;
  monogram?: string;
  /** "intact" presses in on first mount, "reformed" is simply there, "breaking" cracks and re-forms. */
  state: SealState;
  /** Called once the re-formed seal has landed after a "breaking" run. */
  onDone?: () => void;
  /** Seconds to wait before the first press-in. */
  pressDelay?: number;
};

// The crack runs corner to corner with three kinks. The two halves are cut along the same points.
const CRACK_POINTS: Array<[number, number]> = [
  [19, 15],
  [38, 35],
  [47, 47],
  [58, 51],
  [81, 85],
];
const CRACK_PATH = CRACK_POINTS.map(([x, y], i) => `${i === 0 ? "M" : "L"} ${x} ${y}`).join(" ");
const CUT = "8% 2%, 19% 15%, 38% 35%, 47% 47%, 58% 51%, 81% 85%, 92% 98%";
const CLIP_UPPER = `polygon(${CUT}, 110% 98%, 110% -10%, 8% -10%)`;
const CLIP_LOWER = `polygon(${CUT}, 92% 110%, -10% 110%, -10% 2%)`;

const LOBES = 14;
const BLOB_PATH = (() => {
  const steps = LOBES * 12;
  const points: string[] = [];
  for (let i = 0; i < steps; i += 1) {
    const angle = (i / steps) * Math.PI * 2;
    const radius = 46 * (1 + 0.03 * Math.sin(LOBES * angle));
    const x = (50 + radius * Math.cos(angle)).toFixed(2);
    const y = (50 + radius * Math.sin(angle)).toFixed(2);
    points.push(`${i === 0 ? "M" : "L"} ${x} ${y}`);
  }
  return `${points.join(" ")} Z`;
})();

const MONO_ADVANCE = 0.6;

type ArtProps = {
  size: number;
  ring: string | null;
  monogram: string;
  clip?: string;
};

function SealArt({ size, ring, monogram, clip }: ArtProps) {
  const uid = useId().replace(/[^a-zA-Z0-9]/g, "");
  // One screen pixel, in the 100-unit drawing space.
  const px = 100 / size;
  const fontSize = 8.5 * px;
  const pathRadius = 28 - fontSize * 0.35;
  const circumference = 2 * Math.PI * pathRadius;
  const spacing = ring ? circumference / ring.length - MONO_ADVANCE * fontSize : 0;

  return (
    <svg
      viewBox="0 0 100 100"
      width={size}
      height={size}
      className="block"
      style={{ overflow: "visible", clipPath: clip }}
    >
      <defs>
        <radialGradient id={`${uid}fill`} cx="30%" cy="25%" r="85%">
          <stop offset="0" style={{ stopColor: "color-mix(in srgb, var(--accent) 82%, white)" }} />
          <stop offset="0.5" style={{ stopColor: "var(--accent)" }} />
          <stop offset="1" style={{ stopColor: "var(--accent-deep)" }} />
        </radialGradient>
        <filter id={`${uid}emboss`} x="-20%" y="-20%" width="140%" height="140%">
          <feOffset in="SourceAlpha" dy={px} result="below" />
          <feFlood floodColor="#2a0307" floodOpacity="0.55" result="darkColour" />
          <feComposite in="darkColour" in2="below" operator="in" result="dark" />
          <feOffset in="SourceAlpha" dy={-px} result="above" />
          <feFlood floodColor="#ffffff" floodOpacity="0.5" result="lightColour" />
          <feComposite in="lightColour" in2="above" operator="in" result="light" />
          <feMerge>
            <feMergeNode in="dark" />
            <feMergeNode in="light" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <path
          id={`${uid}rim`}
          d={`M 50 ${50 - pathRadius} A ${pathRadius} ${pathRadius} 0 1 1 50 ${50 + pathRadius} A ${pathRadius} ${pathRadius} 0 1 1 50 ${50 - pathRadius}`}
        />
      </defs>

      <path d={BLOB_PATH} fill={`url(#${uid}fill)`} />
      <path
        d={BLOB_PATH}
        fill="none"
        strokeWidth="1"
        vectorEffect="non-scaling-stroke"
        style={{ stroke: "var(--accent-deep)", strokeOpacity: 0.55 }}
      />
      <circle
        cx="50"
        cy="50"
        r="38"
        fill="none"
        stroke="rgba(255, 255, 255, 0.35)"
        strokeWidth="1"
        vectorEffect="non-scaling-stroke"
      />
      {ring ? (
        <text
          fill="rgba(255, 255, 255, 0.78)"
          fontSize={fontSize}
          letterSpacing={spacing}
          style={{ fontFamily: "var(--font-mono)", textTransform: "uppercase" }}
        >
          <textPath href={`#${uid}rim`}>{ring}</textPath>
        </text>
      ) : null}
      <text
        x="50"
        y="50"
        textAnchor="middle"
        dominantBaseline="central"
        fontSize="41"
        fill="rgba(255, 255, 255, 0.92)"
        filter={`url(#${uid}emboss)`}
        style={{ fontFamily: "var(--font-display)", fontStyle: "italic" }}
      >
        {monogram}
      </text>
    </svg>
  );
}

export function Seal({ size, ringText = DEFAULT_RING_TEXT, monogram = "A", state, onDone, pressDelay = 0 }: SealProps) {
  const mode = useMotionMode();
  const [phase, setPhase] = useState<Phase>("rest");
  // The first press-in is a CSS animation, so the seal shows up without waiting for scripts.
  const [intro, setIntro] = useState(state === "intact");
  const [pressKey, setPressKey] = useState(0);
  const [ripple, setRipple] = useState(false);
  const [released, setReleased] = useState(false);
  const [shownRing, setShownRing] = useState<string | null>(ringText);
  const running = useRef(false);

  // While a removal runs, the old rim text stays on the seal until the new seal presses in.
  const holdRing = state === "breaking" && !released;
  if (!holdRing && shownRing !== ringText) setShownRing(ringText);

  useEffect(() => {
    if (state === "breaking") {
      if (mode === "pending") return;
      if (mode === "reduced") {
        setReleased(true);
        onDone?.();
        return;
      }
      running.current = true;
      setIntro(false);
      setPhase("crack");
      return;
    }
    setReleased(false);
    if (running.current) {
      running.current = false;
      setPhase("rest");
    }
    // onDone is left out of the dependencies on purpose: it must fire once per state change, not once per new callback.
  }, [state, mode]);

  const landed = (event: AnimationEvent<HTMLDivElement>) => {
    if (event.target !== event.currentTarget || phase !== "press") return;
    setPhase("rest");
    setRipple(true);
    if (running.current) {
      running.current = false;
      onDone?.();
    }
  };

  const splitDone = () => {
    setReleased(true);
    setPressKey((key) => key + 1);
    setPhase("press");
  };

  const scale = size >= 96 ? 1 : size / 132;
  const shadow = `drop-shadow(0 ${10 * scale}px ${22 * scale}px var(--seal-shadow))`;
  const art = { size, ring: shownRing, monogram };
  const bodyClass = phase === "press" ? "seal-press" : intro ? "seal-press seal-press-first" : "";

  return (
    <div
      className="seal"
      style={{ width: size, height: size, filter: shadow, "--press-delay": `${pressDelay}s` } as CSSProperties}
      aria-hidden="true"
    >
      {phase === "split" ? (
        <>
          <motion.div
            className="absolute inset-0"
            initial={{ x: 0, y: 0, rotate: 0, opacity: 1 }}
            animate={{ x: 4.2, y: -4.2, rotate: -6, opacity: 0 }}
            transition={{ duration: 0.38, ease: "easeIn" }}
            onAnimationComplete={splitDone}
          >
            <SealArt {...art} clip={CLIP_UPPER} />
          </motion.div>
          <motion.div
            className="absolute inset-0"
            initial={{ x: 0, y: 0, rotate: 0, opacity: 1 }}
            animate={{ x: -4.2, y: 4.2, rotate: 6, opacity: 0 }}
            transition={{ duration: 0.38, ease: "easeIn" }}
          >
            <SealArt {...art} clip={CLIP_LOWER} />
          </motion.div>
        </>
      ) : (
        <div key={pressKey} className={`absolute inset-0 ${bodyClass}`} onAnimationEnd={landed}>
          <SealArt {...art} />
          {phase === "crack" ? (
            <svg viewBox="0 0 100 100" className="absolute inset-0" style={{ overflow: "visible" }}>
              <motion.path
                d={CRACK_PATH}
                fill="none"
                strokeWidth={(1.5 * 100) / size}
                strokeLinecap="round"
                strokeLinejoin="round"
                style={{ stroke: "var(--accent-deep)" }}
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 0.42, ease: "easeIn" }}
                onAnimationComplete={() => setPhase("split")}
              />
            </svg>
          ) : null}
        </div>
      )}
      {intro ? <span className="seal-ripple seal-ripple-intro" /> : null}
      {ripple ? <span className="seal-ripple" onAnimationEnd={() => setRipple(false)} /> : null}
    </div>
  );
}
