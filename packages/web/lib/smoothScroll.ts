import type Lenis from "lenis";

let instance: Lenis | null = null;

export function registerSmoothScroll(next: Lenis | null) {
  instance = next;
}

/**
 * Glides to the target when smooth scrolling is on. Returns false when it is off, so the caller can let the browser jump.
 *
 * @param offset Pixels to stop short of the target (negative) or past it (positive).
 */
export function scrollToTarget(target: string, offset = 0): boolean {
  if (!instance) return false;
  instance.scrollTo(target, { offset, duration: 1.2 });
  return true;
}
