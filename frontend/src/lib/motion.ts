// Small helpers so JS timing follows the CSS motion tokens in index.css.

export function prefersReducedMotion(): boolean {
  return window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
}

/** "200ms" -> 200, ".2s" -> 200 (the production CSS minifier rewrites ms as s). */
export function parseDuration(value: string): number | null {
  const match = /^\s*(-?[\d.]+)(ms|s)\s*$/.exec(value);
  if (!match) return null;
  const amount = Number.parseFloat(match[1]);
  if (!Number.isFinite(amount)) return null;
  return match[2] === "s" ? amount * 1000 : amount;
}

/** A duration token such as --row-exit-dur in ms (0 when the reader wants less motion). */
export function motionMs(name: string, fallback: number): number {
  if (prefersReducedMotion()) return 0;
  return parseDuration(getComputedStyle(document.documentElement).getPropertyValue(name)) ?? fallback;
}
