import { ArrowClockwise, Eye } from "@phosphor-icons/react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ActivityChart, ActivityLegend } from "./components/ActivityChart";
import { ConfirmRestoreDialog } from "./components/ConfirmRestoreDialog";
import { QuarantineTable } from "./components/QuarantineTable";
import { QuickScanCard } from "./components/QuickScanCard";
import { RangeFilter } from "./components/RangeFilter";
import { Sidebar } from "./components/Sidebar";
import { StatCards } from "./components/StatCards";
import { type Filter, StatusFilter } from "./components/StatusFilter";
import { Toasts } from "./components/Toasts";
import { TopBar } from "./components/TopBar";
import { TopVectors } from "./components/TopVectors";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import { ApiError, api, type Overview, type QuarantineRow, type Session } from "./lib/api";
import { useActiveSection, useNow, useRange, useStatusFilter, useToasts } from "./lib/hooks";
import { SECTIONS } from "./lib/sections";
import { motionMs } from "./lib/motion";

const REFRESH_MS = 60_000;
const NONE: ReadonlySet<string> = new Set();

const EMPTY_TEXT: Record<Filter, string> = {
  held: "Nothing is held right now",
  restored: "No restored messages yet",
  all: "No quarantined messages yet",
};

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [rows, setRows] = useState<QuarantineRow[] | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState<ReadonlySet<string>>(new Set());
  // Rows that no longer match the filter but are still playing their exit transition.
  const [leaving, setLeaving] = useState<ReadonlySet<string>>(new Set());
  const [rowErrors, setRowErrors] = useState<Record<string, string>>({});
  const [confirming, setConfirming] = useState<QuarantineRow | null>(null);
  const [filter, setFilter] = useStatusFilter();
  const [range, setRange] = useRange();
  const [section, goTo] = useActiveSection(SECTIONS);
  const { toasts, push, dismiss } = useToasts();
  const now = useNow();

  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      const [nextSession, data, nextOverview] = await Promise.all([
        api.session(),
        api.quarantine(),
        api.overview(range),
      ]);
      setSession(nextSession);
      setRows(data.rows);
      setOverview(nextOverview);
      setUpdatedAt(Date.now());
      setLoadError(null);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) return; // redirecting to login
      setLoadError(error instanceof Error ? error.message : "Could not load the dashboard.");
    } finally {
      setRefreshing(false);
    }
  }, [range]);

  // First load (and again when the range changes), then a quiet refresh every minute
  // while the tab is visible.
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
        setOverview(
          (current) =>
            current && {
              ...current,
              held: current.held - 1,
              current: { ...current.current, restored: current.current.restored + 1 },
            },
        );
        // Under "Held" the row now leaves the list: keep it on screen while it fades and
        // slides out (transitions run on transform and opacity only), then drop it.
        setLeaving((current) => new Set(current).add(id));
        window.setTimeout(
          () =>
            setLeaving((current) => {
              const next = new Set(current);
              next.delete(id);
              return next;
            }),
          // A short buffer: the class lands during a busy re-render, so let the fade finish.
          motionMs("--row-exit-dur", 200) + 60,
        );
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
    return rows.filter(
      (r) =>
        leaving.has(r.incident_id) || (filter === "restored" ? r.status === "restored" : r.status !== "restored"),
    );
  }, [rows, filter, leaving]);

  // While a new range loads, the old numbers stay on screen, dimmed (no layout jump).
  const stale = overview !== null && overview.days !== range;

  return (
    <div className="relative isolate min-h-[100dvh]">
      <div aria-hidden="true" className="spotlight" />
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-zinc-900 focus:px-4 focus:py-2"
      >
        Skip to Main Content
      </a>
      <Sidebar session={session} held={overview?.held ?? null} section={section} onNavigate={goTo} />

      <div className="xl:pl-60">
        <TopBar
          session={session}
          updatedAt={updatedAt}
          now={now}
          refreshing={refreshing}
          onRefresh={() => void load()}
          section={section}
          onNavigate={goTo}
        />
        <main id="main" className="mx-auto flex max-w-[1400px] flex-col gap-6 px-4 py-8 sm:px-6 xl:px-8">
          <div id="overview" className="flex scroll-mt-24 flex-col gap-2">
            <h1 className="text-2xl font-semibold tracking-tight text-zinc-50 text-balance">Threat Overview</h1>
            <p className="max-w-[70ch] text-sm text-zinc-400 text-pretty">
              What PhishGuard caught in your mailbox, how often it was wrong, and the evidence behind every
              quarantine. Restore anything you know is safe.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <RangeFilter value={range} onChange={setRange} />
            <p className="text-xs text-zinc-500">Trends compare with the {range} days before.</p>
          </div>

          {session?.mode === "monitor" && (
            <p className="flex items-start gap-3 rounded-xl border border-zinc-800 bg-zinc-900 p-4 text-sm text-zinc-300">
              <Eye aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-accent" />
              Monitor mode: PhishGuard reports phishing but does not move it. Set MODE=quarantine in .env
              to quarantine automatically.
            </p>
          )}

          {loadError && (
            <div role="alert" className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-red-500/30 bg-red-500/10 p-4">
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
          )}

          <StatCards overview={overview} />

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <Card aria-labelledby="activity-title" className="xl:col-span-2">
              <CardHeader>
                <CardTitle id="activity-title">Mail Activity</CardTitle>
                <CardDescription>Emails analyzed and threats quarantined per day (UTC).</CardDescription>
                <CardAction>
                  <ActivityLegend />
                </CardAction>
              </CardHeader>
              <CardContent>
                <ActivityChart series={overview?.series ?? null} stale={stale} />
              </CardContent>
            </Card>
            <Card aria-labelledby="vectors-title">
              <CardHeader>
                <CardTitle id="vectors-title">Top Threat Vectors</CardTitle>
                <CardDescription>Share of quarantined mail that carried each signal.</CardDescription>
              </CardHeader>
              <CardContent className="flex-1">
                <TopVectors overview={overview} stale={stale} />
              </CardContent>
            </Card>
          </div>

          <Card id="quarantine" aria-labelledby="queue-title" className="scroll-mt-24">
            <CardHeader className="max-sm:grid-cols-1">
              <CardTitle id="queue-title">Quarantined Messages</CardTitle>
              <CardDescription>The model's evidence for each message, strongest first.</CardDescription>
              <CardAction className="max-sm:col-start-1 max-sm:row-span-1 max-sm:row-start-3 max-sm:justify-self-start max-sm:pt-2">
                <StatusFilter value={filter} counts={counts} onChange={setFilter} />
              </CardAction>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <QuarantineTable
                rows={visible}
                busy={busy}
                leaving={filter === "held" ? leaving : NONE}
                errors={rowErrors}
                now={now}
                emptyText={EMPTY_TEXT[filter]}
                onRestore={setConfirming}
              />
              <p className="text-xs text-zinc-500">
                Chips show the strongest signals: red pushes towards phishing, green towards legitimate.
                A solid chip is strong evidence, a tinted one medium, a dashed one weak. Hover or focus a
                chip to read the evidence.
              </p>
            </CardContent>
          </Card>

          <QuickScanCard csrf={session?.csrf ?? null} />
        </main>
      </div>

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
