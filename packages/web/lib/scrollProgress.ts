/**
 * Publishes how far the reader has scrolled past the hero as the CSS variable `--hero-p`
 * (0 at the top, 1 once the hero is fully gone). Writing a style property in a frame loop keeps
 * React out of it, so scrolling never re-renders anything. Returns the stop function.
 */
export function publishHeroProgress(hero: HTMLElement): () => void {
  let frame = 0;
  let last = -1;

  const tick = () => {
    const height = hero.offsetHeight || 1;
    const p = Math.min(1, Math.max(0, window.scrollY / height));
    if (p !== last) {
      last = p;
      hero.style.setProperty("--hero-p", p.toFixed(4));
    }
    frame = requestAnimationFrame(tick);
  };

  frame = requestAnimationFrame(tick);
  return () => {
    cancelAnimationFrame(frame);
    hero.style.removeProperty("--hero-p");
  };
}
