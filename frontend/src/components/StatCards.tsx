import {
  ArrowDownRight,
  ArrowUpRight,
  ArrowUUpLeft,
  Crosshair,
  EnvelopeSimpleOpen,
  type Icon,
  Minus,
  ShieldWarning,
} from "@phosphor-icons/react";
import { type PointerEvent, useRef } from "react";
import type { Overview } from "../lib/api";
import { formatChange, formatCount, formatPercent, formatPointChange, type Trend } from "../lib/format";
import { PopNumber } from "./PopNumber";
import { Sparkline } from "./Sparkline";

/** Largest tilt in degrees. Kept small on purpose: the cards should lean, not flip. */
const MAX_TILT = 5;

type Tone = "accent" | "phishing" | "safe" | "neutral";
/** Whether a rising number is good news, bad news, or neither (just volume). */
type Polarity = "neutral" | "up-is-bad" | "up-is-good";

interface Card {
  label: string;
  value: string | undefined;
  note: string;
  trend: Trend | undefined;
  polarity: Polarity;
  spark: number[];
  meter?: number | null; // a 0..1 ratio shown as a meter instead of a sparkline
  Icon: Icon;
  tone: Tone;
}

// The icon tile carries the card's meaning: blue for volume, red for phishing held back,
// emerald for mail handed back to the inbox. Same semantics as the chips.
const TONE: Record<Tone, string> = {
  accent: "bg-accent/10 text-accent ring-accent/30",
  phishing: "bg-red-500/10 text-red-300 ring-red-400/30",
  safe: "bg-emerald-500/10 text-emerald-300 ring-emerald-400/30",
  neutral: "bg-zinc-800 text-zinc-300 ring-zinc-700",
};

const TREND_ICON = { up: ArrowUpRight, down: ArrowDownRight, flat: Minus } as const;

const GOOD = "bg-emerald-500/10 text-emerald-200 ring-emerald-400/30";
const BAD = "bg-amber-500/10 text-amber-200 ring-amber-400/30";

function trendStyle(trend: Trend, polarity: Polarity): string {
  if (polarity === "neutral" || trend.direction === "flat") return "bg-zinc-800/70 text-zinc-300 ring-zinc-700";
  const rising = trend.direction === "up";
  return (polarity === "up-is-good") === rising ? GOOD : BAD;
}

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

function StatCard({ card, period }: { card: Card; period: string }) {
  const tilt = useTilt<HTMLDivElement>();
  const TrendIcon = card.trend ? TREND_ICON[card.trend.direction] : Minus;
  return (
    <div
      {...tilt}
      className="tilt-card flex flex-col rounded-xl border border-zinc-800 bg-zinc-900/60 p-5 shadow-[inset_0_1px_0_0_rgb(255_255_255/0.04)] hover:border-zinc-700"
    >
      <dt className="flex items-center gap-2.5 text-sm text-zinc-400">
        <span aria-hidden="true" className={`grid size-8 place-items-center rounded-md ring-1 ring-inset ${TONE[card.tone]}`}>
          <card.Icon weight="duotone" className="size-[18px]" />
        </span>
        {card.label}
      </dt>
      <dd className="tilt-lift mt-4 flex flex-wrap items-center gap-x-3 gap-y-1">
        {card.value === undefined ? (
          <>
            <span aria-hidden="true" className="inline-block h-9 w-20 animate-pulse rounded-md bg-zinc-800" />
            <span className="sr-only">Loading…</span>
          </>
        ) : (
          <span className="text-3xl font-semibold tracking-tight text-zinc-50">
            <PopNumber value={card.value} />
          </span>
        )}
        {card.trend && (
          <span
            className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium tabular-nums ring-1 ring-inset ${trendStyle(card.trend, card.polarity)}`}
          >
            <TrendIcon aria-hidden="true" weight="bold" className="size-3" />
            {card.trend.text}
            <span className="sr-only"> {period}</span>
          </span>
        )}
      </dd>
      <dd className="mt-1 text-xs text-zinc-500">{card.note}</dd>
      <dd className="mt-4">
        {card.meter !== undefined ? <Meter ratio={card.meter} /> : <Sparkline values={card.spark} />}
      </dd>
    </div>
  );
}

/** A ratio against 100%: the fill on a fainter step of the same blue. Decorative (the number says it). */
function Meter({ ratio }: { ratio: number | null }) {
  return (
    <div aria-hidden="true" className="flex h-9 items-center">
      <span className="block h-1.5 w-full overflow-hidden rounded-full bg-accent/15">
        <span
          className="block h-full origin-left rounded-full bg-accent transition-transform duration-200 ease-out"
          style={{ transform: `scaleX(${ratio ?? 0})` }}
        />
      </span>
    </div>
  );
}

const ratio = (part: number, whole: number) => (whole ? part / whole : 0);

/** Precision of the quarantine: the share of quarantined mail nobody had to release. */
const precision = (t: Overview["current"]) => (t.quarantined ? 1 - t.released / t.quarantined : null);

/** The four security headline numbers for the chosen range, each against the range before. */
export function StatCards({ overview }: { overview: Overview | null }) {
  const o = overview ?? undefined;
  const period = o ? `vs previous ${o.days} days` : "";
  const series = o?.series ?? [];
  const now = o && precision(o.current);
  const before = o && precision(o.previous);
  const cards: Card[] = [
    {
      label: "Total emails analyzed",
      value: o && formatCount(o.current.scanned),
      note: o ? `scanned in the last ${o.days} days` : "",
      trend: o && formatChange(o.current.scanned, o.previous.scanned),
      polarity: "neutral",
      spark: series.map((d) => d.scanned),
      Icon: EnvelopeSimpleOpen,
      tone: "accent",
    },
    {
      label: "False positive rate",
      value: o && formatPercent(ratio(o.current.restored, o.current.scanned)),
      note: o ? `${formatCount(o.current.restored)} restored to inbox` : "",
      trend: o && formatPointChange(ratio(o.current.restored, o.current.scanned), ratio(o.previous.restored, o.previous.scanned)),
      polarity: "up-is-bad", // every restore is a message the model got wrong
      spark: series.map((d) => ratio(d.restored, d.scanned)),
      Icon: ArrowUUpLeft,
      tone: "safe",
    },
    {
      label: "Quarantined threats",
      value: o && formatCount(o.current.quarantined),
      note: o ? `${formatCount(o.held)} active isolations` : "",
      trend: o && formatChange(o.current.quarantined, o.previous.quarantined),
      polarity: "neutral",
      spark: series.map((d) => d.quarantined),
      Icon: ShieldWarning,
      tone: "phishing",
    },
    {
      label: "Model precision",
      value: o && (now === null || now === undefined ? "n/a" : formatPercent(now)),
      note:
        o?.current.mean_score != null
          ? `${formatPercent(o.current.mean_score)} mean detection confidence`
          : "no quarantines in this range",
      trend: o && now != null && before != null ? formatPointChange(now, before) : undefined,
      polarity: "up-is-good",
      spark: [],
      meter: o ? now : undefined,
      Icon: Crosshair,
      tone: "neutral",
    },
  ];
  return (
    <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {cards.map((card) => (
        <StatCard key={card.label} card={card} period={period} />
      ))}
    </dl>
  );
}
