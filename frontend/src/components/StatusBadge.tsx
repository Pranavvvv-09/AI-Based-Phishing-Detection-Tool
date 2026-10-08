import type { RowStatus } from "../lib/api";

const LABEL: Record<RowStatus, string> = {
  held: "Held",
  restoring: "Restoring…",
  restored: "Restored",
};

const STYLE: Record<RowStatus, string> = {
  held: "bg-red-500/10 text-red-300 ring-red-400/25",
  restoring: "bg-zinc-800 text-zinc-300 ring-zinc-700",
  restored: "bg-emerald-500/10 text-emerald-300 ring-emerald-400/25",
};

export function StatusBadge({ status }: { status: RowStatus }) {
  return (
    <span
      className={`status-swap inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${STYLE[status]}`}
    >
      {LABEL[status]}
    </span>
  );
}
