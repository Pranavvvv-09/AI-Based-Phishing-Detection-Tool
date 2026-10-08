import type { Reason } from "../lib/api";
import { formatWeight, humanizeCode } from "../lib/format";

export type Strength = "strong" | "medium" | "weak";
type Direction = "phishing" | "safe" | "neutral";

/** Same thresholds as the backend's Reason.strength: |weight| >= 2 strong, >= 1 medium. */
export function strengthOf(weight: number): Strength {
  const size = Math.abs(weight);
  return size >= 2 ? "strong" : size >= 1 ? "medium" : "weak";
}

function directionOf(weight: number): Direction {
  return weight > 0 ? "phishing" : weight < 0 ? "safe" : "neutral";
}

// Colour = direction (red pushes towards phishing, emerald towards legitimate);
// fill = strength (solid, tinted, outline).
const STYLES: Record<Direction, Record<Strength, string>> = {
  phishing: {
    strong: "bg-red-400 text-red-950 ring-red-300",
    medium: "bg-red-500/15 text-red-200 ring-red-400/40",
    weak: "bg-transparent text-red-300 ring-red-400/30",
  },
  safe: {
    strong: "bg-emerald-400 text-emerald-950 ring-emerald-300",
    medium: "bg-emerald-500/15 text-emerald-200 ring-emerald-400/40",
    weak: "bg-transparent text-emerald-300 ring-emerald-400/30",
  },
  neutral: {
    strong: "bg-zinc-800 text-zinc-300 ring-zinc-700",
    medium: "bg-zinc-800 text-zinc-300 ring-zinc-700",
    weak: "bg-transparent text-zinc-400 ring-zinc-700",
  },
};

const SPOKEN: Record<Direction, string> = {
  phishing: "towards phishing",
  safe: "towards legitimate",
  neutral: "no effect",
};

export function SignalChip({ reason }: { reason: Reason }) {
  const direction = directionOf(reason.weight);
  const strength = strengthOf(reason.weight);
  return (
    <span
      title={reason.detail}
      data-direction={direction}
      data-strength={strength}
      className={`inline-flex max-w-full items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${STYLES[direction][strength]}`}
    >
      <span className="truncate" translate="no">
        {humanizeCode(reason.code)}
      </span>
      <span className="font-mono tabular-nums">{formatWeight(reason.weight)}</span>
      <span className="sr-only">
        , {strength} evidence {SPOKEN[direction]}
      </span>
    </span>
  );
}
