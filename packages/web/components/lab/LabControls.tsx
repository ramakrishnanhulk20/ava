"use client";

import { useState } from "react";
import type { Accent, Serif } from "./LabShell";

type LabControlsProps = {
  serif: Serif;
  accent: Accent;
  onSerif: (value: Serif) => void;
  onAccent: (value: Accent) => void;
  onPlay: () => void;
  onReset: () => void;
};

const SERIF_OPTIONS: Array<{ value: Serif; label: string }> = [
  { value: "fraunces", label: "FRAUNCES" },
  { value: "instrument", label: "INSTRUMENT" },
  { value: "newsreader", label: "NEWSREADER" },
];

const ACCENT_OPTIONS: Array<{ value: Accent; label: string }> = [
  { value: "wax", label: "WAX RED" },
  { value: "ink", label: "DEEP INK" },
];

type SegmentedProps<T extends string> = {
  label: string;
  value: T;
  options: Array<{ value: T; label: string }>;
  onChange: (value: T) => void;
};

function Segmented<T extends string>({ label, value, options, onChange }: SegmentedProps<T>) {
  return (
    <div role="group" aria-label={label}>
      <p className="mb-1.5">{label}</p>
      <div className="flex gap-1">
        {options.map((option) => {
          const selected = option.value === value;
          return (
            <button
              key={option.value}
              type="button"
              aria-pressed={selected}
              onClick={() => onChange(option.value)}
              className={`h-7 flex-1 cursor-pointer rounded-md border px-0.5 transition-colors duration-200 ${
                selected ? "border-ink bg-ink text-on-ink" : "border-rule bg-transparent hover:border-ink"
              }`}
            >
              {option.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

export function LabControls({ serif, accent, onSerif, onAccent, onPlay, onReset }: LabControlsProps) {
  const [open, setOpen] = useState(false);

  return (
    <div className="mono fixed right-5 bottom-5 z-[100] flex flex-col items-end gap-3 text-[11px] tracking-[0.12em] text-ink">
      <div
        className={`${open ? "flex" : "hidden"} w-72 flex-col gap-3 rounded-[10px] border border-rule p-3.5`}
        style={{ background: "rgba(251, 249, 246, 0.86)", backdropFilter: "blur(10px)" }}
      >
        <Segmented label="SERIF" value={serif} options={SERIF_OPTIONS} onChange={onSerif} />
        <Segmented label="ACCENT" value={accent} options={ACCENT_OPTIONS} onChange={onAccent} />
        <button
          type="button"
          onClick={onPlay}
          className="h-8 w-full cursor-pointer rounded-lg border border-ink transition-colors duration-200 hover:bg-ink hover:text-on-ink"
        >
          PLAY REMOVAL
        </button>
        <div className="flex items-center justify-between">
          <button type="button" onClick={onReset} className="link-draw cursor-pointer text-ink-soft">
            RESET
          </button>
          <button type="button" onClick={() => setOpen(false)} className="link-draw cursor-pointer text-ink-soft">
            CLOSE
          </button>
        </div>
      </div>
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
        className="size-11 cursor-pointer rounded-full border border-ink transition-colors duration-200 hover:bg-ink hover:text-on-ink"
        style={{ background: "rgba(251, 249, 246, 0.86)", backdropFilter: "blur(10px)" }}
      >
        LAB
      </button>
    </div>
  );
}
