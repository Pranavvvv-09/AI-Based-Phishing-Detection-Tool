export type Filter = "held" | "restored" | "all";

const OPTIONS: { value: Filter; label: string }[] = [
  { value: "held", label: "Held" },
  { value: "restored", label: "Restored" },
  { value: "all", label: "All" },
];

interface Props {
  value: Filter;
  counts: Record<Filter, number>;
  onChange: (value: Filter) => void;
}

/** Segmented control; the choice is kept in the URL (?status=) so it survives reloads. */
export function StatusFilter({ value, counts, onChange }: Props) {
  return (
    <div role="group" aria-label="Show messages" className="inline-flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5">
      {OPTIONS.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            aria-pressed={active}
            onClick={() => onChange(option.value)}
            className={`inline-flex h-8 items-center gap-2 rounded-md px-3 text-sm font-medium transition-colors ${
              active ? "bg-zinc-800 text-zinc-50" : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            {option.label}
            <span className="font-mono text-xs tabular-nums text-zinc-500">{counts[option.value]}</span>
          </button>
        );
      })}
    </div>
  );
}
