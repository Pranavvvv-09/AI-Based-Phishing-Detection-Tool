import { type SyntheticEvent, useEffect, useRef } from "react";
import type { QuarantineRow } from "../lib/api";
import { formatScore } from "../lib/format";
import { motionMs } from "../lib/motion";

interface Props {
  row: QuarantineRow | null;
  onCancel: () => void;
  onConfirm: (row: QuarantineRow) => void;
}

/**
 * Releasing a message the model flagged as phishing is a risky action, so it is confirmed
 * first. Native <dialog> gives focus trapping, Esc to close and an inert background.
 * Motion: transitions.dev modal (scale 0.95 to 1 with a blurred backdrop fading in);
 * closing plays the shorter scale-down before the dialog actually closes.
 */
export function ConfirmRestoreDialog({ row, onCancel, onConfirm }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const confirmed = useRef(false);

  const closing = useRef<number | undefined>(undefined);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (row && !dialog.open) {
      confirmed.current = false;
      window.clearTimeout(closing.current);
      dialog.classList.remove("is-closing");
      dialog.showModal();
      // Next frame, so the browser paints the resting scale first and the open tweens.
      requestAnimationFrame(() => dialog.classList.add("is-open"));
    } else if (!row && dialog.open) {
      dialog.classList.remove("is-open");
      dialog.close();
    }
  }, [row]);

  function handleClose() {
    if (!row) return;
    if (confirmed.current) onConfirm(row);
    else onCancel();
  }

  function close(confirm: boolean) {
    const dialog = ref.current;
    if (!dialog || dialog.classList.contains("is-closing")) return;
    confirmed.current = confirm;
    dialog.classList.remove("is-open");
    dialog.classList.add("is-closing");
    closing.current = window.setTimeout(() => {
      dialog.classList.remove("is-closing");
      dialog.close();
    }, motionMs("--modal-close-dur", 150));
  }

  // Esc: play the same close animation instead of the browser's instant close.
  function handleCancel(event: SyntheticEvent<HTMLDialogElement>) {
    event.preventDefault();
    close(false);
  }

  return (
    <dialog
      ref={ref}
      onClose={handleClose}
      onCancel={handleCancel}
      aria-labelledby="restore-title"
      aria-describedby="restore-description"
      className="t-modal m-auto w-[min(32rem,calc(100vw-2rem))] overscroll-contain rounded-xl border border-zinc-800 bg-zinc-900 p-0 text-zinc-200 shadow-2xl shadow-black/50"
    >
      {row && (
        <div className="flex flex-col gap-5 p-6">
          <div className="flex flex-col gap-2">
            <h2 id="restore-title" className="text-lg font-semibold text-zinc-50 text-balance">
              Restore to Inbox?
            </h2>
            <p id="restore-description" className="text-sm leading-relaxed text-zinc-400 text-pretty">
              PhishGuard scored this message{" "}
              <span className="font-mono tabular-nums text-zinc-200">{formatScore(row.score)}</span>{" "}
              phishing. Restore it only if you know the sender. It will not be quarantined again.
            </p>
          </div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 text-sm">
            <dt className="text-zinc-500">From</dt>
            <dd className="min-w-0 break-words text-zinc-200">{row.from || "Unknown sender"}</dd>
            <dt className="text-zinc-500">Subject</dt>
            <dd className="min-w-0 break-words text-zinc-200">{row.subject || "(no subject)"}</dd>
          </dl>
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <button
              type="button"
              onClick={() => close(false)}
              className="h-9 rounded-lg border border-zinc-700 px-4 text-sm font-medium text-zinc-200 transition-colors hover:border-zinc-500 hover:bg-zinc-800"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => close(true)}
              className="h-9 rounded-lg bg-accent px-4 text-sm font-semibold text-zinc-950 transition-colors hover:bg-accent-strong"
            >
              Restore to Inbox
            </button>
          </div>
        </div>
      )}
    </dialog>
  );
}
