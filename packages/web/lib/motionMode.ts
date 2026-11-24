import { useSyncExternalStore } from "react";

export type MotionMode = "pending" | "full" | "reduced";

const QUERY = "(prefers-reduced-motion: reduce)";

function subscribe(onChange: () => void) {
  const query = window.matchMedia(QUERY);
  query.addEventListener("change", onChange);
  return () => query.removeEventListener("change", onChange);
}

function read(): MotionMode {
  return window.matchMedia(QUERY).matches ? "reduced" : "full";
}

// The server and the hydration pass both answer "pending", so an animated element never starts
// from a guessed motion preference and the markup always matches what the server sent.
export function useMotionMode(): MotionMode {
  return useSyncExternalStore(subscribe, read, () => "pending");
}
