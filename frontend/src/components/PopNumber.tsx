import { useLayoutEffect, useRef } from "react";

/**
 * transitions.dev "number pop-in": when the value changes, the digits that changed rise in
 * with a soft blur; leading characters the old and new value share stay still, and the
 * last two trail by one stagger step. The first render does not animate.
 * Screen readers get the plain value; the per-digit spans are hidden from them.
 */
export function PopNumber({ value }: { value: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  const previous = useRef<string | null>(null);

  let same = 0;
  const before = previous.current ?? value;
  while (same < before.length && same < value.length && before[same] === value[same]) same++;

  useLayoutEffect(() => {
    const group = ref.current;
    if (group && previous.current !== null && previous.current !== value) {
      group.classList.remove("is-animating");
      void group.offsetHeight; // reflow, so the animation replays
      group.classList.add("is-animating");
    }
    previous.current = value;
  }, [value]);

  const chars = [...value];
  return (
    <>
      <span ref={ref} aria-hidden="true" className="t-digit-group">
        {chars.map((char, i) => (
          <span
            // Keyed by position and character, so a changed digit is a fresh element.
            key={`${i}-${char}`}
            className="t-digit"
            data-same={i < same ? "" : undefined}
            data-stagger={i === chars.length - 2 ? "1" : i === chars.length - 1 ? "2" : undefined}
          >
            {char}
          </span>
        ))}
      </span>
      <span className="sr-only">{value}</span>
    </>
  );
}
