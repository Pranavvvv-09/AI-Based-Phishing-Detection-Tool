import { ShieldCheck, SignOut } from "@phosphor-icons/react";
import type { Session } from "../lib/api";
import { formatAbsolute, formatRelative } from "../lib/format";

const POLLER_TONE = {
  ok: "bg-emerald-400",
  warn: "bg-amber-400",
  error: "bg-red-400",
  off: "bg-zinc-500",
} as const;

function pollerText(session: Session): string {
  const { poller } = session;
  if (poller.state === "off" || !poller.last_poll_at) return poller.text;
  const checked = `Checked ${formatRelative(poller.last_poll_at, Date.now())}`;
  return poller.error ? `${checked}. ${poller.error}` : `Watching ${poller.mailbox}. ${checked}`;
}

export function TopBar({ session }: { session: Session | null }) {
  return (
    <header className="sticky top-0 z-30 border-b border-zinc-800 bg-zinc-950/95">
      <div className="mx-auto flex h-16 max-w-[1400px] items-center gap-3 px-4 sm:gap-6 sm:px-6">
        <a href="/" className="flex shrink-0 items-center gap-2 font-semibold text-zinc-50" translate="no">
          <ShieldCheck aria-hidden="true" weight="fill" className="size-6 text-accent" />
          <span className="max-sm:sr-only">PhishGuard</span>
        </a>
        <nav aria-label="Main" className="flex items-center gap-1 whitespace-nowrap text-sm">
          <a
            href="/"
            aria-current="page"
            className="rounded-lg bg-zinc-900 px-3 py-1.5 font-medium text-zinc-50"
          >
            Quarantine
          </a>
          <a
            href="/scan"
            className="rounded-lg px-3 py-1.5 font-medium text-zinc-400 transition-colors hover:bg-zinc-900 hover:text-zinc-100"
          >
            Quick Scan
          </a>
        </nav>
        <div className="ml-auto flex min-w-0 items-center gap-4">
          {session && (
            <p
              className="hidden min-w-0 items-center gap-2 text-xs text-zinc-400 lg:flex"
              title={session.poller.last_poll_at ? `Last check ${formatAbsolute(session.poller.last_poll_at)}` : undefined}
            >
              {/* A real status light (poller health), not decoration. */}
              <span aria-hidden="true" className={`size-2 shrink-0 rounded-full ${POLLER_TONE[session.poller.state]}`} />
              <span className="truncate">{pollerText(session)}</span>
            </p>
          )}
          {session && (
            <form method="post" action="/logout">
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
