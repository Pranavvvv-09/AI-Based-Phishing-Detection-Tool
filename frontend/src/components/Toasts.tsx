import { CheckCircle, Info, WarningCircle, X } from "@phosphor-icons/react";

export interface Toast {
  id: number;
  tone: "success" | "error" | "info";
  title: string;
  body?: string;
}

const ICON = { success: CheckCircle, error: WarningCircle, info: Info };
const TONE = {
  success: "text-emerald-300",
  error: "text-red-300",
  info: "text-zinc-300",
};

/** Polite live region: screen readers announce restore results without stealing focus. */
export function Toasts({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  return (
    <div
      aria-live="polite"
      className="pointer-events-none fixed inset-x-4 bottom-4 z-50 flex flex-col items-end gap-2 sm:inset-x-auto sm:right-6"
    >
      {toasts.map((toast) => {
        const Icon = ICON[toast.tone];
        return (
          <div
            key={toast.id}
            role={toast.tone === "error" ? "alert" : "status"}
            className="pointer-events-auto flex w-full max-w-sm items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-900 p-4 shadow-xl shadow-black/30"
          >
            <Icon aria-hidden="true" weight="fill" className={`mt-0.5 size-5 shrink-0 ${TONE[toast.tone]}`} />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-zinc-100">{toast.title}</p>
              {toast.body && <p className="mt-1 break-words text-sm text-zinc-400">{toast.body}</p>}
            </div>
            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              aria-label="Dismiss notification"
              className="-m-1 rounded-md p-1 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-200"
            >
              <X aria-hidden="true" className="size-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
