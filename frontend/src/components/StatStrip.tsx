import type { Kpis } from "../lib/api";
import { formatCount } from "../lib/format";

/** The three headline numbers, laid out as one strip (no card grid). */
export function StatStrip({ kpis }: { kpis: Kpis | null }) {
  const items = [
    { label: "Total scanned", value: kpis?.scanned, note: "by the mailbox poller" },
    { label: "Quarantined", value: kpis?.quarantined, note: kpis ? `${formatCount(kpis.held)} still held` : "" },
    { label: "Restored", value: kpis?.restored, note: "released to the inbox" },
  ];
  return (
    <dl className="grid grid-cols-1 divide-y divide-zinc-800 border-y border-zinc-800 sm:grid-cols-3 sm:divide-x sm:divide-y-0">
      {items.map((item) => (
        <div key={item.label} className="flex flex-col gap-1 py-5 sm:px-6 sm:first:pl-0">
          <dt className="text-sm text-zinc-400">{item.label}</dt>
          <dd className="font-mono text-3xl font-medium tabular-nums text-zinc-50">
            {item.value === undefined ? (
              <>
                <span aria-hidden="true" className="inline-block h-8 w-16 animate-pulse rounded-md bg-zinc-800 align-middle" />
                <span className="sr-only">Loading…</span>
              </>
            ) : (
              formatCount(item.value)
            )}
          </dd>
          <dd className="text-xs text-zinc-500">{item.note}</dd>
        </div>
      ))}
    </dl>
  );
}
