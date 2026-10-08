import type { RangeDays } from "../lib/api";

const OPTIONS: { value: RangeDays; label: string }[] = [
  { value: 7, label: "7 days" },
  { value: 30, label: "30 days" },
  { value: 90, label: "90 days" },
];

/** Time range for the cards, chart and signals; kept in the URL (?range=7d). */
export function RangeFilter({ value, onChange }: { value: RangeDays; onChange: (days: RangeDays) => void }) {
  return (
    <div role="group" aria-label="Time range" className="inline-flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5">
      {OPTIONS.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            aria-pressed={active}
            onClick={() => onChange(option.value)}
            className={`inline-flex h-8 items-center rounded-md px-3 text-sm font-medium transition-colors ${
              active ? "bg-zinc-800 text-zinc-50" : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
