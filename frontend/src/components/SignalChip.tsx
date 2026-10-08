import { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
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
// fill = strength (solid, tinted, dashed outline). Borders stay clearly visible on zinc-950.
const STYLES: Record<Direction, Record<Strength, string>> = {
  phishing: {
    strong: "border-red-300 bg-red-400 text-red-950",
    medium: "border-red-400/70 bg-red-500/15 text-red-100",
    weak: "border-dashed border-red-400/70 text-red-300",
  },
  safe: {
    strong: "border-emerald-300 bg-emerald-400 text-emerald-950",
    medium: "border-emerald-400/70 bg-emerald-500/15 text-emerald-100",
    weak: "border-dashed border-emerald-400/70 text-emerald-300",
  },
  neutral: {
    strong: "border-zinc-600 bg-zinc-800 text-zinc-200",
    medium: "border-zinc-600 bg-zinc-800 text-zinc-200",
    weak: "border-dashed border-zinc-600 text-zinc-300",
  },
};

const DOT: Record<Direction, string> = {
  phishing: "bg-red-400",
  safe: "bg-emerald-400",
  neutral: "bg-zinc-500",
};

const SPOKEN: Record<Direction, string> = {
  phishing: "towards phishing",
  safe: "towards legitimate",
  neutral: "no effect",
};

const STRENGTH_LABEL: Record<Strength, string> = { strong: "Strong", medium: "Medium", weak: "Weak" };

interface Props {
  reason: Reason;
  /** Off where the detail is already printed next to the chip (the expanded signal list). */
  tooltip?: boolean;
}

export function SignalChip({ reason, tooltip = true }: Props) {
  const direction = directionOf(reason.weight);
  const strength = strengthOf(reason.weight);
  const id = useId();
  const ref = useRef<HTMLSpanElement>(null);
  const [anchor, setAnchor] = useState<DOMRect | null>(null);
  const hasTip = tooltip && reason.detail.trim() !== "";

  function show() {
    if (hasTip && ref.current) setAnchor(ref.current.getBoundingClientRect());
  }
  function hide() {
    setAnchor(null);
  }

  // Escape dismisses the tooltip; scrolling or resizing would leave it stranded, so hide it.
  useEffect(() => {
    if (!anchor) return;
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && setAnchor(null);
    const onMove = () => setAnchor(null);
    window.addEventListener("keydown", onKey);
    window.addEventListener("scroll", onMove, { capture: true, passive: true });
    window.addEventListener("resize", onMove);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", onMove, { capture: true });
      window.removeEventListener("resize", onMove);
    };
  }, [anchor]);

  return (
    <>
      <span
        ref={ref}
        tabIndex={hasTip ? 0 : undefined}
        aria-describedby={anchor ? id : undefined}
        onPointerEnter={show}
        onPointerLeave={hide}
        onFocus={show}
        onBlur={hide}
        data-direction={direction}
        data-strength={strength}
        className={`inline-flex max-w-full items-center gap-1.5 rounded-md border px-2 py-[3px] text-xs/4 font-medium ${
          hasTip ? "cursor-help" : ""
        } ${STYLES[direction][strength]}`}
      >
        <span className="truncate" translate="no">
          {humanizeCode(reason.code)}
        </span>
        <span className="border-l border-current/30 pl-1.5 font-mono text-[11px] tabular-nums">
          {formatWeight(reason.weight)}
        </span>
        <span className="sr-only">
          , {strength} evidence {SPOKEN[direction]}
        </span>
      </span>
      {anchor &&
        createPortal(
          <ChipTooltip id={id} anchor={anchor} reason={reason} direction={direction} strength={strength} />,
          document.body,
        )}
    </>
  );
}

const TIP_HALF_WIDTH = 152; // max-w-72 (288px) / 2 plus an 8px margin from the viewport edge

function ChipTooltip({
  id,
  anchor,
  reason,
  direction,
  strength,
}: {
  id: string;
  anchor: DOMRect;
  reason: Reason;
  direction: Direction;
  strength: Strength;
}) {
  // Above the chip when there is room under the sticky header, otherwise below it.
  const above = anchor.top > 120;
  const centre = anchor.left + anchor.width / 2;
  const left = Math.min(Math.max(centre, TIP_HALF_WIDTH), window.innerWidth - TIP_HALF_WIDTH);
  return (
    <div
      id={id}
      role="tooltip"
      style={{
        left,
        top: above ? anchor.top - 8 : anchor.bottom + 8,
        transform: above ? "translate(-50%, -100%)" : "translateX(-50%)",
      }}
      className="chip-tooltip pointer-events-none fixed z-50 w-max max-w-72 rounded-lg border border-zinc-700 bg-zinc-900/95 px-3 py-2 text-xs shadow-xl shadow-black/50 backdrop-blur-sm"
    >
      <p className="font-medium text-zinc-100 text-pretty">{reason.detail}</p>
      <p className="mt-1 flex items-center gap-1.5 text-zinc-400">
        <span aria-hidden="true" className={`size-1.5 shrink-0 rounded-full ${DOT[direction]}`} />
        {STRENGTH_LABEL[strength]} evidence {SPOKEN[direction]}, {reason.source} layer
      </p>
    </div>
  );
}
