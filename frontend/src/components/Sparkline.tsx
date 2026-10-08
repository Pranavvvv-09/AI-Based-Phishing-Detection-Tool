import { useWidth } from "../lib/hooks";

const HEIGHT = 36;
const PAD = 4; // room for the end dot and its ring

/**
 * A tiny trend line: the window in the de-emphasis grey, today marked with an accent dot.
 * Decorative (aria-hidden): the card's number and trend badge carry the information.
 */
export function Sparkline({ values }: { values: number[] }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const max = Math.max(1, ...values);
  const step = values.length > 1 ? (width - PAD * 2) / (values.length - 1) : 0;
  const point = (value: number, i: number) =>
    [PAD + i * step, PAD + (HEIGHT - PAD * 2) * (1 - value / max)] as const;
  const points = values.map(point);
  const last = points.at(-1);
  return (
    <div ref={ref} aria-hidden="true" className="h-9 w-full">
      {width > 0 && values.length > 1 && last && (
        <svg width={width} height={HEIGHT} className="block overflow-visible">
          <polyline
            points={points.map(([x, y]) => `${x},${y}`).join(" ")}
            fill="none"
            strokeWidth={2}
            strokeLinejoin="round"
            strokeLinecap="round"
            className="stroke-zinc-600"
          />
          <circle cx={last[0]} cy={last[1]} r={3.5} strokeWidth={2} className="fill-accent stroke-zinc-900" />
        </svg>
      )}
    </div>
  );
}
