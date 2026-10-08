import { ArrowUUpLeft, type Icon, Scan, ShieldWarning } from "@phosphor-icons/react";
import { type PointerEvent, useRef } from "react";
import type { Kpis } from "../lib/api";
import { formatCount } from "../lib/format";

/** Largest tilt in degrees. Kept small on purpose: the cards should lean, not flip. */
const MAX_TILT = 5;

type Tone = "accent" | "phishing" | "safe";

interface Card {
  label: string;
  value: number | undefined;
  note: string;
  Icon: Icon;
  tone: Tone;
}

// The icon tile carries the card's meaning: blue for volume, red for phishing held back,
// emerald for mail handed back to the inbox. Same semantics as the chips.
const TONE: Record<Tone, string> = {
  accent: "bg-accent/10 text-accent ring-accent/30",
  phishing: "bg-red-500/10 text-red-300 ring-red-400/30",
  safe: "bg-emerald-500/10 text-emerald-300 ring-emerald-400/30",
};

/**
 * Pointer position -> CSS variables. No React state, so moving the mouse never re-renders;
 * the browser does the 3D work. index.css only applies the tilt for a fine pointer with
 * motion allowed, so touch screens and reduced-motion users get flat cards.
 */
function useTilt<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const frame = useRef(0);

  function onPointerMove(event: PointerEvent<T>) {
    const card = ref.current;
    if (!card || event.pointerType !== "mouse") return;
    const box = card.getBoundingClientRect();
    const x = (event.clientX - box.left) / box.width;
    const y = (event.clientY - box.top) / box.height;
    cancelAnimationFrame(frame.current);
    frame.current = requestAnimationFrame(() => {
      card.style.setProperty("--tilt-x", `${((0.5 - y) * MAX_TILT).toFixed(2)}deg`);
      card.style.setProperty("--tilt-y", `${((x - 0.5) * MAX_TILT).toFixed(2)}deg`);
      card.style.setProperty("--glow-x", `${(x * 100).toFixed(1)}%`);
      card.style.setProperty("--glow-y", `${(y * 100).toFixed(1)}%`);
    });
  }

  function onPointerLeave() {
    const card = ref.current;
    cancelAnimationFrame(frame.current);
    if (!card) return;
    for (const name of ["--tilt-x", "--tilt-y", "--glow-x", "--glow-y"]) card.style.removeProperty(name);
  }

  return { ref, onPointerMove, onPointerLeave };
}

function StatCard({ card }: { card: Card }) {
  const tilt = useTilt<HTMLDivElement>();
  return (
    <div
      {...tilt}
      className="tilt-card flex flex-col gap-1 rounded-lg border border-zinc-800 bg-zinc-900/60 p-5 shadow-[inset_0_1px_0_0_rgb(255_255_255/0.04)] hover:border-zinc-700"
    >
      <dt className="flex items-center gap-2.5 text-sm text-zinc-400">
        <span aria-hidden="true" className={`grid size-8 place-items-center rounded-md ring-1 ring-inset ${TONE[card.tone]}`}>
          <card.Icon weight="duotone" className="size-[18px]" />
        </span>
        {card.label}
      </dt>
      <dd className="tilt-lift mt-3 font-mono text-4xl font-medium tracking-tight tabular-nums text-zinc-50">
        {card.value === undefined ? (
          <>
            <span aria-hidden="true" className="inline-block h-9 w-20 animate-pulse rounded-md bg-zinc-800 align-middle" />
            <span className="sr-only">Loading…</span>
          </>
        ) : (
          formatCount(card.value)
        )}
      </dd>
      <dd className="text-xs text-zinc-500">{card.note}</dd>
    </div>
  );
}

/** The three headline numbers as cards that lean towards the pointer. */
export function StatCards({ kpis }: { kpis: Kpis | null }) {
  const cards: Card[] = [
    { label: "Total scanned", value: kpis?.scanned, note: "by the mailbox poller", Icon: Scan, tone: "accent" },
    {
      label: "Quarantined",
      value: kpis?.quarantined,
      note: kpis ? `${formatCount(kpis.held)} still held` : "",
      Icon: ShieldWarning,
      tone: "phishing",
    },
    { label: "Restored", value: kpis?.restored, note: "released to the inbox", Icon: ArrowUUpLeft, tone: "safe" },
  ];
  return (
    <dl className="grid grid-cols-1 gap-4 sm:grid-cols-3">
      {cards.map((card) => (
        <StatCard key={card.label} card={card} />
      ))}
    </dl>
  );
}
