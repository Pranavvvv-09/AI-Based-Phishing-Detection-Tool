import { ArrowUUpLeft, CircleNotch } from "@phosphor-icons/react";

interface Props {
  busy: boolean;
  onClick: () => void;
  label: string; // accessible name with the message's subject, for screen readers
}

/** The row action. Fixed width so the label swap to "Restoring…" doesn't shift the row. */
export function RestoreButton({ busy, onClick, label }: Props) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      aria-busy={busy}
      aria-label={busy ? `Restoring ${label}` : `Restore to Inbox: ${label}`}
      className="inline-flex h-9 min-w-[10.5rem] items-center justify-center gap-2 whitespace-nowrap rounded-lg bg-accent px-3 text-sm font-semibold text-zinc-950 transition-[background-color,transform] duration-150 hover:bg-accent-strong active:translate-y-px disabled:cursor-progress disabled:opacity-80"
    >
      {busy ? (
        <CircleNotch aria-hidden="true" weight="bold" className="size-4 animate-spin" />
      ) : (
        <ArrowUUpLeft aria-hidden="true" weight="bold" className="size-4" />
      )}
      <span>{busy ? "Restoring…" : "Restore to Inbox"}</span>
    </button>
  );
}
