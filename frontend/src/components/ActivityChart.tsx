import { type KeyboardEvent, type PointerEvent, useId, useState } from "react";
import type { Overview } from "../lib/api";
import { formatCount, formatDay, niceTicks } from "../lib/format";
import { useWidth } from "../lib/hooks";

type Series = Overview["series"];

// Two panels on a shared day axis (small multiples): analyzed mail is in the hundreds,
// quarantines in single digits, so one axis would flatten the line that matters and a
// second y-axis would invent a correlation. Each panel gets its own clean scale.
const PAD = { top: 22, right: 16, left: 44 };
const AREA_H = 132; // panel 1: emails analyzed (area)
const GAP = 34; // room for panel 2's title
const BARS_H = 60; // panel 2: threats quarantined (columns)
const AXIS_H = 28; // x-axis band, included in the height so labels never clip
const HEIGHT = PAD.top + AREA_H + GAP + BARS_H + AXIS_H;
const BARS_TOP = PAD.top + AREA_H + GAP;

/**
 * Emails analyzed (area) and threats quarantined (columns) per day.
 * Hover or arrow keys move one crosshair through both panels; the tooltip lists the day.
 * The same numbers are in the table under the chart.
 */
export function ActivityChart({ series, stale }: { series: Series | null; stale: boolean }) {
  // The measured box is always rendered, so its width is known from the first paint.
  const [ref, width] = useWidth<HTMLDivElement>();
  return (
    <div ref={ref} className={`transition-opacity duration-200 ${stale ? "opacity-50" : ""}`}>
      {series ? (
        <Chart series={series} width={width} />
      ) : (
        <div aria-hidden="true" style={{ height: HEIGHT }} className="animate-pulse rounded-lg bg-zinc-900/60" />
      )}
    </div>
  );
}

/** A column with a 4px rounded data end and a square base. */
function column(x: number, w: number, base: number, h: number): string {
  if (h <= 0) return "";
  const r = Math.min(4, w / 2, h);
  const top = base - h;
  return `M${x},${base}V${top + r}Q${x},${top} ${x + r},${top}H${x + w - r}Q${x + w},${top} ${x + w},${top + r}V${base}Z`;
}

function Chart({ series, width }: { series: Series; width: number }) {
  const [active, setActive] = useState<number | null>(null);
  const titleId = useId();

  const n = series.length;
  const plotW = Math.max(0, width - PAD.left - PAD.right);
  const band = plotW / n; // each day owns one band; points and columns sit at its centre
  const x = (i: number) => PAD.left + band * (i + 0.5);

  const areaTicks = niceTicks(Math.max(0, ...series.map((d) => d.scanned)), 2);
  const barTicks = niceTicks(Math.max(0, ...series.map((d) => d.quarantined)), 2);
  const areaTop = areaTicks[areaTicks.length - 1];
  const barTop = barTicks[barTicks.length - 1];
  const yArea = (v: number) => PAD.top + AREA_H - (v / areaTop) * AREA_H;
  const yBar = (v: number) => BARS_TOP + BARS_H - (v / barTop) * BARS_H;

  const line = series.map((d, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${yArea(d.scanned).toFixed(1)}`).join("");
  const area = `${line}L${x(n - 1).toFixed(1)},${yArea(0)}L${x(0).toFixed(1)},${yArea(0)}Z`;
  const barW = Math.max(2, Math.min(24, band - 2)); // 2px surface gap between neighbours

  // Date labels: as many as fit at ~80px apart, always including the first and last day.
  const labelCount = Math.max(2, Math.min(n, Math.floor(plotW / 80)));
  const labelIdx = [...new Set(Array.from({ length: labelCount }, (_, k) => Math.round((k * (n - 1)) / (labelCount - 1))))];
  const last = series[n - 1];

  function pick(event: PointerEvent<SVGSVGElement>) {
    const box = event.currentTarget.getBoundingClientRect();
    const i = Math.floor((event.clientX - box.left - PAD.left) / band);
    setActive(Math.min(n - 1, Math.max(0, i)));
  }

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const moves: Record<string, number> = { ArrowLeft: -1, ArrowRight: 1, Home: -n, End: n };
    if (event.key === "Escape") return setActive(null);
    if (!(event.key in moves)) return;
    event.preventDefault();
    setActive((current) => Math.min(n - 1, Math.max(0, (current ?? n - 1) + moves[event.key])));
  }

  const point = active === null ? null : series[active];
  const flip = active !== null && x(active) > width / 2;

  const axisLabel = "fill-zinc-500 text-[11px] tabular-nums";
  const panelTitle = "fill-zinc-400 text-[11px] font-medium";

  return (
    <>
      <div
        role="group"
        tabIndex={0}
        aria-labelledby={titleId}
        aria-describedby={`${titleId}-hint`}
        onKeyDown={onKeyDown}
        onFocus={() => setActive((current) => current ?? n - 1)}
        onBlur={() => setActive(null)}
        className="relative rounded-lg"
      >
        <span id={titleId} className="sr-only">Mail activity per day</span>
        <span id={`${titleId}-hint`} className="sr-only">
          Use the left and right arrow keys to read each day. The table below has every value.
        </span>
        {width > 0 && (
          <svg
            width={width}
            height={HEIGHT}
            aria-hidden="true"
            className="block touch-pan-y select-none"
            onPointerMove={pick}
            onPointerDown={pick}
            onPointerLeave={() => setActive(null)}
          >
            <defs>
              <linearGradient id={`${titleId}-fill`} x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor="#468de5" stopOpacity={0.22} />
                <stop offset="100%" stopColor="#468de5" stopOpacity={0.02} />
              </linearGradient>
            </defs>

            {/* Panel titles */}
            <text x={PAD.left} y={PAD.top - 10} className={panelTitle}>Emails analyzed</text>
            <text x={PAD.left} y={BARS_TOP - 10} className={panelTitle}>Threats quarantined</text>

            {/* Hairline grid and y ticks, per panel */}
            {areaTicks.map((tick) => (
              <g key={`a${tick}`}>
                <line x1={PAD.left} x2={width - PAD.right} y1={yArea(tick)} y2={yArea(tick)} className="stroke-zinc-800" strokeWidth={1} />
                <text x={PAD.left - 10} y={yArea(tick)} dy="0.32em" textAnchor="end" className={axisLabel}>{formatCount(tick)}</text>
              </g>
            ))}
            {barTicks.map((tick) => (
              <g key={`b${tick}`}>
                <line x1={PAD.left} x2={width - PAD.right} y1={yBar(tick)} y2={yBar(tick)} className="stroke-zinc-800" strokeWidth={1} />
                <text x={PAD.left - 10} y={yBar(tick)} dy="0.32em" textAnchor="end" className={axisLabel}>{formatCount(tick)}</text>
              </g>
            ))}
            {labelIdx.map((i) => (
              <text
                key={i}
                x={x(i)}
                y={HEIGHT - 8}
                textAnchor={i === 0 ? "start" : i === n - 1 ? "end" : "middle"}
                className={axisLabel}
              >
                {formatDay(series[i].date)}
              </text>
            ))}

            {/* Crosshair behind the marks, through both panels */}
            {active !== null && (
              <line x1={x(active)} x2={x(active)} y1={PAD.top} y2={BARS_TOP + BARS_H} className="stroke-zinc-600" strokeWidth={1} />
            )}

            <path d={area} fill={`url(#${titleId}-fill)`} />
            <path d={line} fill="none" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" className="stroke-chart-scanned" />
            {series.map((d, i) => (
              <path
                key={d.date}
                d={column(x(i) - barW / 2, barW, yBar(0), yBar(0) - yBar(d.quarantined))}
                className={`fill-chart-quarantined transition-opacity duration-150 ${active !== null && active !== i ? "opacity-40" : ""}`}
              />
            ))}

            {active !== null ? (
              <circle cx={x(active)} cy={yArea(series[active].scanned)} r={4.5} strokeWidth={2} className="fill-chart-scanned stroke-zinc-950" />
            ) : (
              /* Today's analyzed count, labelled at the line end */
              <text x={x(n - 1) - 6} y={yArea(last.scanned) - 8} textAnchor="end" className="fill-zinc-300 text-[11px] font-medium tabular-nums">
                {formatCount(last.scanned)}
              </text>
            )}
          </svg>
        )}

        {point && active !== null && (
          <div
            className="pointer-events-none absolute z-10 min-w-44 rounded-lg border border-zinc-700 bg-zinc-900/95 px-3 py-2 text-xs shadow-xl shadow-black/50 backdrop-blur-sm"
            style={{
              top: PAD.top,
              left: x(active),
              transform: flip ? "translateX(calc(-100% - 12px))" : "translateX(12px)",
            }}
          >
            <p className="mb-1.5 font-medium text-zinc-400">{formatDay(point.date, true)}</p>
            <TooltipRow color="bg-chart-scanned" value={point.scanned} label="Analyzed" />
            <TooltipRow color="bg-chart-quarantined" value={point.quarantined} label="Quarantined" />
            {point.restored > 0 && <TooltipRow color="bg-zinc-500" value={point.restored} label="Restored" />}
          </div>
        )}
        <p aria-live="polite" className="sr-only">
          {point
            ? `${formatDay(point.date, true)}: ${point.scanned} analyzed, ${point.quarantined} quarantined, ${point.restored} restored.`
            : ""}
        </p>
      </div>

      <details className="group mt-3 text-sm">
        <summary className="inline-flex cursor-pointer select-none rounded-md px-1.5 py-0.5 text-xs font-medium text-zinc-400 transition-colors hover:text-zinc-200">
          Show as Table
        </summary>
        <div className="mt-2 max-h-64 overflow-auto rounded-lg border border-zinc-800">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-zinc-900 text-zinc-400">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">Day (UTC)</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Analyzed</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Quarantined</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Restored</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/80 tabular-nums text-zinc-300">
              {[...series].reverse().map((d) => (
                <tr key={d.date}>
                  <th scope="row" className="px-3 py-1.5 font-normal text-zinc-400">{formatDay(d.date, true)}</th>
                  <td className="px-3 py-1.5 text-right">{formatCount(d.scanned)}</td>
                  <td className="px-3 py-1.5 text-right">{formatCount(d.quarantined)}</td>
                  <td className="px-3 py-1.5 text-right">{formatCount(d.restored)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </>
  );
}

/** Tooltip row: a short line key in the series colour, then the value (strong) and name. */
function TooltipRow({ color, value, label }: { color: string; value: number; label: string }) {
  return (
    <p className="flex items-center gap-2 py-0.5">
      <span aria-hidden="true" className={`h-0.5 w-3 shrink-0 rounded-full ${color}`} />
      <span className="font-semibold tabular-nums text-zinc-50">{formatCount(value)}</span>
      <span className="text-zinc-400">{label}</span>
    </p>
  );
}

/** Legend for the chart's card header: area swatch for Scanned, line key for Quarantined. */
export function ActivityLegend() {
  return (
    <ul className="flex items-center gap-4 text-xs text-zinc-400">
      <li className="flex items-center gap-1.5">
        <span aria-hidden="true" className="h-2.5 w-3 rounded-sm border-t-2 border-chart-scanned bg-chart-scanned/20" />
        Analyzed
      </li>
      <li className="flex items-center gap-1.5">
        <span aria-hidden="true" className="h-2.5 w-2 rounded-t-[2px] bg-chart-quarantined" />
        Quarantined
      </li>
    </ul>
  );
}
