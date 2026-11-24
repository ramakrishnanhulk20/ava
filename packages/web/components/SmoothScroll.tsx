"use client";

import Lenis from "lenis";
import "lenis/dist/lenis.css";
import { useEffect } from "react";
import { registerSmoothScroll } from "../lib/smoothScroll";

export function SmoothScroll() {
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const lenis = new Lenis({ lerp: 0.1, smoothWheel: true, autoRaf: true });
    registerSmoothScroll(lenis);
    return () => {
      registerSmoothScroll(null);
      lenis.destroy();
    };
  }, []);

  return null;
}
