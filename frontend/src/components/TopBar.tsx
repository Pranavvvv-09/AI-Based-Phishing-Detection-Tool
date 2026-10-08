import { ArrowClockwise, CaretRight, ShieldCheck, SignOut } from "@phosphor-icons/react";
import type { Session } from "../lib/api";
import { formatAbsolute, formatRelative } from "../lib/format";
import { useSlidingPill } from "../lib/hooks";
import type { Section } from "../lib/sections";
import { HeartbeatBadge } from "./Poller";

const TABS: { key: Section; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "quarantine", label: "Quarantine" },
  { key: "quick-scan", label: "Scan" },
];

const CRUMB: Record<Section, string> = {
  overview: "Threat Overview",
  quarantine: "Quarantine",
  "quick-scan": "Quick Scan",
};

interface Props {
  session: Session | null;
  updatedAt: number | null; // when the dashboard data last arrived
  now: number;
  refreshing: boolean;
  onRefresh: () => void;
  section: Section;
  onNavigate: (section: Section) => void;
}

/**
 * Sticky header. Wide screens (with the sidebar): breadcrumb, freshness and Refresh.
 * Narrow screens: brand, the two pages, the poller beacon and Log Out.
 */
export function TopBar({ session, updatedAt, now, refreshing, onRefresh, section, onNavigate }: Props) {
  const { bar, pill } = useSlidingPill<HTMLElement>(section, "x");
  const updated = updatedAt ? new Date(updatedAt).toISOString() : null;
  return (
    <header className="sticky top-0 z-30 border-b border-zinc-800/80 bg-zinc-950/75 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-[1400px] items-center gap-3 px-4 sm:gap-6 sm:px-6 xl:px-8">
        {/* Narrow screens */}
        <a href="/" className="flex shrink-0 items-center gap-2 font-semibold text-zinc-50 xl:hidden" translate="no">
          <ShieldCheck aria-hidden="true" weight="fill" className="size-6 text-accent" />
          <span className="max-sm:sr-only">PhishGuard</span>
        </a>
        <nav ref={bar} aria-label="Main" className="relative flex items-center gap-0.5 whitespace-nowrap text-sm xl:hidden">
          <span ref={pill} aria-hidden="true" className="t-tabs-pill h-8 w-20 rounded-lg bg-zinc-800/80" />
          {TABS.map(({ key, label }) => (
            <a
              key={key}
              href={`#${key}`}
              data-tab={key}
              aria-current={key === section ? "location" : undefined}
              onClick={() => onNavigate(key)}
              className={`t-tab rounded-lg px-2.5 py-1.5 font-medium sm:px-3 ${
                key === section ? "text-zinc-50" : "text-zinc-400 hover:text-zinc-100"
              }`}
            >
              {label}
            </a>
          ))}
        </nav>

        {/* Wide screens */}
        <p className="hidden items-center gap-2 text-sm xl:flex">
          <span className="text-zinc-500" translate="no">PhishGuard</span>
          <CaretRight aria-hidden="true" className="size-3.5 text-zinc-600" />
          <span className="font-medium text-zinc-100">{CRUMB[section]}</span>
        </p>

        <div className="ml-auto flex min-w-0 items-center gap-3 sm:gap-4">
          {session && <HeartbeatBadge session={session} />}
          {updated && (
            <p className="hidden text-xs text-zinc-500 xl:block" title={formatAbsolute(updated)}>
              Updated {formatRelative(updated, now)}
            </p>
          )}
          <button
            type="button"
            onClick={onRefresh}
            disabled={refreshing}
            aria-busy={refreshing}
            className="hidden h-9 items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 text-sm font-medium text-zinc-200 transition-colors hover:border-zinc-700 hover:text-zinc-50 disabled:cursor-progress disabled:opacity-70 xl:inline-flex"
          >
            <ArrowClockwise aria-hidden="true" className={`size-4 ${refreshing ? "animate-spin" : ""}`} />
            {refreshing ? "Refreshing…" : "Refresh"}
          </button>
          {session && (
            <form method="post" action="/logout" className="xl:hidden">
              <input type="hidden" name="csrf_token" value={session.csrf} />
              <button
                type="submit"
                aria-label="Log Out"
                className="inline-flex h-9 items-center gap-2 whitespace-nowrap rounded-lg border border-zinc-800 px-2.5 text-sm font-medium text-zinc-300 transition-colors hover:border-zinc-600 hover:text-zinc-50 sm:px-3"
              >
                <SignOut aria-hidden="true" className="size-4" />
                <span className="max-sm:sr-only">Log Out</span>
              </button>
            </form>
          )}
        </div>
      </div>
    </header>
  );
}
