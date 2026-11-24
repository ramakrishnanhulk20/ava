"use client";

import { motion } from "motion/react";

type TickProps = {
  size: number;
  /** Seconds to wait before the stroke draws. Leave out for a tick that is simply there. */
  drawAfter?: number;
};

export function Tick({ size, drawAfter }: TickProps) {
  const path = "M2 7.6 L5.6 11 L12 3";
  return (
    <svg width={size} height={size} viewBox="0 0 14 14" fill="none" aria-hidden="true" className="shrink-0 text-live">
      {drawAfter === undefined ? (
        <path d={path} stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      ) : (
        <motion.path
          className="proof-tick"
          d={path}
          stroke="currentColor"
          strokeWidth="1.6"
          strokeLinecap="round"
          strokeLinejoin="round"
          initial={{ pathLength: 0 }}
          whileInView={{ pathLength: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.32, delay: drawAfter }}
        />
      )}
    </svg>
  );
}

export function Cross({ size }: { size: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 12 12" fill="none" aria-hidden="true" className="shrink-0 text-ink">
      <path d="M1.5 1.5 L10.5 10.5 M10.5 1.5 L1.5 10.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

export function Hollow() {
  return <span className="inline-block size-1.5 shrink-0 rounded-full border border-ink-soft" aria-hidden="true" />;
}
