import { ArrowClockwise, Eye } from "@phosphor-icons/react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ConfirmRestoreDialog } from "./components/ConfirmRestoreDialog";
import { QuarantineTable } from "./components/QuarantineTable";
import { StatStrip } from "./components/StatStrip";
import { type Filter, StatusFilter } from "./components/StatusFilter";
import { Toasts } from "./components/Toasts";
import { TopBar } from "./components/TopBar";
import { ApiError, api, type Kpis, type QuarantineRow, type Session } from "./lib/api";
import { useNow, useStatusFilter, useToasts } from "./lib/hooks";

const REFRESH_MS = 60_000;

const EMPTY_TEXT: Record<Filter, string> = {
  held: "Nothing is held right now",
  restored: "No restored messages yet",
  all: "No quarantined messages yet",
};

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [rows, setRows] = useState<QuarantineRow[] | null>(null);
  const [kpis, setKpis] = useState<Kpis | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState<ReadonlySet<string>>(new Set());
  const [rowErrors, setRowErrors] = useState<Record<string, string>>({});
  const [confirming, setConfirming] = useState<QuarantineRow | null>(null);
  const [filter, setFilter] = useStatusFilter();
  const { toasts, push, dismiss } = useToasts();
  const now = useNow();

  const load = useCallback(async () => {
    try {
      const [nextSession, data] = await Promise.all([api.session(), api.quarantine()]);
      setSession(nextSession);
      setRows(data.rows);
      setKpis(data.kpis);
      setLoadError(null);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) return; // redirecting to login
      setLoadError(error instanceof Error ? error.message : "Could not load the quarantine.");
    }
  }, []);

  // First load, then a quiet refresh every minute while the tab is visible.
  useEffect(() => {
    void load();
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void load();
    }, REFRESH_MS);
    const onVisible = () => document.visibilityState === "visible" && void load();
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [load]);

  const restore = useCallback(
    async (row: QuarantineRow) => {
      if (!session) return;
      const id = row.incident_id;
      setBusy((current) => new Set(current).add(id));
      setRowErrors(({ [id]: _drop, ...rest }) => rest);
      try {
        const result = await api.restore(id, session.csrf);
        // Update the row in place right away; the background refresh confirms it.
        setRows((current) =>
          current?.map((r) =>
            r.incident_id === id
              ? { ...r, status: "restored", restored_at: result.restored_at, restored_by: result.restored_by }
              : r,
          ) ?? current,
        );
        setKpis((current) => current && { ...current, held: current.held - 1, restored: current.restored + 1 });
        push({ tone: "success", title: "Restored to Inbox", body: row.subject || row.from });
        void load();
      } catch (error) {
        const message = error instanceof Error ? error.message : "Restore failed.";
        if (error instanceof ApiError && error.status === 409) {
          push({ tone: "info", title: "Already handled", body: message });
          void load();
        } else if (!(error instanceof ApiError && error.status === 401)) {
          setRowErrors((current) => ({ ...current, [id]: `${message} Try again in a moment.` }));
          push({ tone: "error", title: "Could not restore the message", body: message });
        }
      } finally {
        setBusy((current) => {
          const next = new Set(current);
          next.delete(id);
          return next;
        });
      }
    },
    [session, push, load],
  );

  const counts = useMemo<Record<Filter, number>>(() => {
    const all = rows ?? [];
    const restored = all.filter((r) => r.status === "restored").length;
    return { held: all.length - restored, restored, all: all.length };
  }, [rows]);

  const visible = useMemo(() => {
    if (!rows) return null;
    if (filter === "all") return rows;
    return rows.filter((r) => (filter === "restored" ? r.status === "restored" : r.status !== "restored"));
  }, [rows, filter]);

  return (
    <div className="min-h-[100dvh]">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-zinc-900 focus:px-4 focus:py-2"
      >
        Skip to Main Content
      </a>
      <TopBar session={session} />
      <main id="main" className="mx-auto flex max-w-[1400px] flex-col gap-8 px-4 py-8 sm:px-6">
        <div className="flex flex-col gap-2">
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-50 text-balance">Quarantine</h1>
          <p className="max-w-[65ch] text-sm text-zinc-400 text-pretty">
            Messages PhishGuard moved out of your inbox, with the evidence behind each verdict.
            Restore anything you know is safe.
          </p>
        </div>

        {session?.mode === "monitor" && (
          <p className="flex items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-900 p-4 text-sm text-zinc-300">
            <Eye aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-accent" />
            Monitor mode: PhishGuard reports phishing but does not move it. Set MODE=quarantine in .env
            to quarantine automatically.
          </p>
        )}

        <StatStrip kpis={kpis} />

        <section aria-labelledby="queue-title" className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 id="queue-title" className="text-base font-semibold text-zinc-100">
              Quarantined Messages
            </h2>
            <StatusFilter value={filter} counts={counts} onChange={setFilter} />
          </div>

          {loadError ? (
            <div role="alert" className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-red-500/30 bg-red-500/10 p-4">
              <p className="text-sm text-red-200">{loadError}</p>
              <button
                type="button"
                onClick={() => void load()}
                className="inline-flex h-9 items-center gap-2 rounded-lg border border-zinc-700 px-3 text-sm font-medium text-zinc-100 transition-colors hover:bg-zinc-800"
              >
                <ArrowClockwise aria-hidden="true" className="size-4" />
                Retry
              </button>
            </div>
          ) : (
            <QuarantineTable
              rows={visible}
              busy={busy}
              errors={rowErrors}
              now={now}
              emptyText={EMPTY_TEXT[filter]}
              onRestore={setConfirming}
            />
          )}

          <p className="text-xs text-zinc-500">
            Chips show the strongest signals: red pushes towards phishing, green towards legitimate.
            A solid chip is strong evidence, a tinted one medium, an outlined one weak.
          </p>
        </section>
      </main>

      <ConfirmRestoreDialog
        row={confirming}
        onCancel={() => setConfirming(null)}
        onConfirm={(row) => {
          setConfirming(null);
          void restore(row);
        }}
      />
      <Toasts toasts={toasts} onDismiss={dismiss} />
    </div>
  );
}
