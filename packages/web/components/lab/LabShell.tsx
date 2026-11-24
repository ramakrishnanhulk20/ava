"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { DrillBand } from "../drill/DrillBand";
import { Footer } from "../Footer";
import { Hero } from "../hero/Hero";
import { HowItWorks } from "../how/HowItWorks";
import { ProofSection } from "../proof/ProofSection";
import { RING_AFTER, RING_BEFORE } from "../hero/rings";
import { DEFAULT_RING_TEXT, type SealState } from "../hero/Seal";
import { LabControls } from "./LabControls";

export type Serif = "fraunces" | "instrument" | "newsreader";
export type Accent = "wax" | "ink";

// The reset step has to paint before the removal starts, or the old seal would skip straight to cracking.
const REPLAY_GAP_MS = 60;

type SealRun = { state: SealState; ring: string };

type LabShellProps = {
  initialSerif: Serif;
  initialAccent: Accent;
};

export function LabShell({ initialSerif, initialAccent }: LabShellProps) {
  const router = useRouter();
  const [serif, setSerif] = useState<Serif>(initialSerif);
  const [accent, setAccent] = useState<Accent>(initialAccent);
  const [seal, setSeal] = useState<SealRun>({ state: "intact", ring: DEFAULT_RING_TEXT });
  const [caption, setCaption] = useState(false);
  const replayTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.serif = serif;
    root.dataset.accent = accent;
    return () => {
      root.dataset.serif = "fraunces";
      root.dataset.accent = "wax";
    };
  }, [serif, accent]);

  useEffect(() => () => clearTimeout(replayTimer.current), []);

  const writeQuery = (nextSerif: Serif, nextAccent: Accent) => {
    router.replace(`/lab?serif=${nextSerif}&accent=${nextAccent}`, { scroll: false });
  };

  const chooseSerif = (value: Serif) => {
    setSerif(value);
    writeQuery(value, accent);
  };

  const chooseAccent = (value: Accent) => {
    setAccent(value);
    writeQuery(serif, value);
  };

  const play = () => {
    clearTimeout(replayTimer.current);
    setCaption(false);
    setSeal({ state: "intact", ring: RING_BEFORE });
    replayTimer.current = setTimeout(() => setSeal({ state: "breaking", ring: RING_AFTER }), REPLAY_GAP_MS);
  };

  const reset = () => {
    clearTimeout(replayTimer.current);
    setSerif("fraunces");
    setAccent("wax");
    setCaption(false);
    setSeal({ state: "intact", ring: DEFAULT_RING_TEXT });
    router.replace("/lab", { scroll: false });
  };

  const sealDone = useCallback(() => {
    setSeal((run) => ({ ...run, state: "reformed" }));
    setCaption(true);
  }, []);

  return (
    <main data-serif={serif} data-accent={accent}>
      <Hero sealState={seal.state} ringText={seal.ring} onSealDone={sealDone} caption={caption} />
      <HowItWorks />
      <ProofSection />
      <DrillBand />
      <Footer />
      <LabControls
        serif={serif}
        accent={accent}
        onSerif={chooseSerif}
        onAccent={chooseAccent}
        onPlay={play}
        onReset={reset}
      />
    </main>
  );
}
