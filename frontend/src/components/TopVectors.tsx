import { ShieldCheck } from "@phosphor-icons/react";
import type { Overview } from "../lib/api";
import { formatCount, formatPercent, vectorName } from "../lib/format";

/**
 * The evidence seen most often in the mail quarantined during the range: each row is a
 * meter (share of quarantined messages that carried the signal), with the count written
 * out, so no value depends on colour or hover.
 */
export function TopVectors({ overview, stale }: { overview: Overview | null; stale: boolean }) {
  if (!overview) {
    return (
      <ul aria-hidden="true" className="flex flex-col gap-5">
        {[0, 1, 2, 3, 4].map((i) => (
          <li key={i} className="flex flex-col gap-2">
            <span className="h-4 w-40 animate-pulse rounded-md bg-zinc-800" />
            <span className="h-1.5 w-full animate-pulse rounded-full bg-zinc-800" />
          </li>
        ))}
      </ul>
    );
  }
  const total = overview.current.quarantined;
  if (overview.signals.length === 0) {
    return (
      <div className={`flex h-full flex-col items-center justify-center gap-2 py-10 text-center transition-opacity ${stale ? "opacity-50" : ""}`}>
        <ShieldCheck aria-hidden="true" weight="duotone" className="size-8 text-zinc-600" />
        <p className="text-sm font-medium text-zinc-300">No threats in this range</p>
        <p className="max-w-[28ch] text-sm text-zinc-500">Signals appear here once the poller quarantines a message.</p>
      </div>
    );
  }
  return (
    <ol className={`flex flex-col gap-4 transition-opacity ${stale ? "opacity-50" : ""}`}>
      {overview.signals.map((signal, rank) => {
        const share = total ? Math.min(1, signal.count / total) : 0;
        return (
          <li key={signal.code} className="flex flex-col gap-2">
            <p className="flex items-baseline gap-3 text-sm">
              <span className="w-4 shrink-0 font-mono text-xs tabular-nums text-zinc-600">{rank + 1}</span>
              <span className="min-w-0 truncate font-medium text-zinc-200" translate="no">
                {vectorName(signal.code)}
              </span>
              <span className="ml-auto shrink-0 text-xs tabular-nums text-zinc-400">
                <span className="font-medium text-zinc-200">{formatCount(signal.count)}</span> of {formatCount(total)}
                <span className="text-zinc-500"> · {formatPercent(share)}</span>
              </span>
            </p>
            {/* Meter: the track is a faint step of the fill's own red. */}
            <span aria-hidden="true" className="ml-7 block h-1.5 rounded-full bg-red-500/15">
              <span className="block h-full rounded-full bg-chart-quarantined" style={{ width: `${share * 100}%` }} />
            </span>
          </li>
        );
      })}
    </ol>
  );
}
