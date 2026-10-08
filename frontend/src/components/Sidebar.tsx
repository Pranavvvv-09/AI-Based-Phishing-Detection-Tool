import { type Icon, MagnifyingGlass, ShieldCheck, ShieldWarning, SignOut, SquaresFour } from "@phosphor-icons/react";
import type { Session } from "../lib/api";
import { formatAbsolute, formatCount, formatRelative } from "../lib/format";
import { useSlidingPill } from "../lib/hooks";
import type { Section } from "../lib/sections";
import { Beacon, POLLER_LABEL } from "./Poller";

const NAV: { key: Section; label: string; Icon: Icon }[] = [
  { key: "overview", label: "Threat Overview", Icon: SquaresFour },
  { key: "quarantine", label: "Quarantine", Icon: ShieldWarning },
  { key: "quick-scan", label: "Quick Scan", Icon: MagnifyingGlass },
];

interface Props {
  session: Session | null;
  held: number | null;
  section: Section; // the section in view (scroll-spy)
  onNavigate: (section: Section) => void;
}

/** Desktop navigation (xl and up). Narrow screens use the tabs in TopBar instead. */
export function Sidebar({ session, held, section, onNavigate }: Props) {
  const { bar, pill } = useSlidingPill<HTMLDivElement>(section, "y");
  return (
    <aside className="fixed inset-y-0 left-0 z-40 hidden w-60 flex-col border-r border-zinc-800/80 bg-zinc-950/80 backdrop-blur-md xl:flex">
      <a href="/" className="flex h-16 shrink-0 items-center gap-3 px-5" translate="no">
        <span className="grid size-8 place-items-center rounded-lg bg-accent/15 ring-1 ring-inset ring-accent/30">
          <ShieldCheck aria-hidden="true" weight="fill" className="size-[18px] text-accent" />
        </span>
        <span className="flex flex-col leading-tight">
          <span className="text-sm font-semibold text-zinc-50">PhishGuard</span>
          <span className="text-xs text-zinc-500">Mail security</span>
        </span>
      </a>

      <nav aria-label="Main" className="flex flex-col px-3 pt-4 text-sm">
        <p className="px-2.5 pb-2 text-xs font-medium text-zinc-500">Monitor</p>
        <div ref={bar} className="relative flex flex-col gap-0.5">
          {/* The active indicator: one pill that slides between the links. */}
          <span ref={pill} aria-hidden="true" className="t-tabs-pill h-9 w-full rounded-lg bg-zinc-900 ring-1 ring-inset ring-zinc-800" />
          {NAV.map(({ key, label, Icon }) => {
            const current = key === section;
            return (
              <a
                key={key}
                href={`#${key}`}
                data-tab={key}
                aria-current={current ? "location" : undefined}
                onClick={() => onNavigate(key)}
                className={`t-tab flex h-9 items-center gap-2.5 rounded-lg px-2.5 font-medium ${
                  current ? "text-zinc-50" : "text-zinc-400 hover:text-zinc-100"
                }`}
              >
                <Icon
                  aria-hidden="true"
                  weight={current ? "duotone" : "regular"}
                  className={`size-[18px] transition-colors duration-200 ${current ? "text-accent" : ""}`}
                />
                {label}
                {key === "quarantine" && held !== null && held > 0 && (
                  <span className="ml-auto rounded-md bg-red-500/10 px-1.5 font-mono text-xs tabular-nums text-red-300 ring-1 ring-inset ring-red-400/25">
                    {formatCount(held)}
                    <span className="sr-only"> held</span>
                  </span>
                )}
              </a>
            );
          })}
        </div>
      </nav>

      {session && (
        <section aria-label="Mailbox poller" className="mx-3 mt-6 rounded-lg border border-zinc-800 bg-zinc-900/50 p-3 text-xs">
          <p className="flex items-center gap-2.5 font-medium text-zinc-200">
            <Beacon state={session.poller.state} />
            {POLLER_LABEL[session.poller.state]}
            <span className="ml-auto rounded-md px-1.5 py-0.5 text-zinc-400 ring-1 ring-inset ring-zinc-700">
              {session.mode === "quarantine" ? "Quarantine mode" : "Monitor mode"}
            </span>
          </p>
          {session.poller.mailbox && (
            <p className="mt-2 truncate text-zinc-400" title={session.poller.mailbox} translate="no">
              {session.poller.mailbox}
            </p>
          )}
          <p className="mt-0.5 text-zinc-500" title={session.poller.last_poll_at ? formatAbsolute(session.poller.last_poll_at) : undefined}>
            {session.poller.last_poll_at
              ? `Checked ${formatRelative(session.poller.last_poll_at, Date.now())}`
              : session.poller.text}
          </p>
          {session.poller.error && <p className="mt-1 text-red-300">{session.poller.error}</p>}
        </section>
      )}

      {session && (
        <div className="mt-auto flex items-center gap-3 border-t border-zinc-800/80 p-3">
          <span aria-hidden="true" className="grid size-8 shrink-0 place-items-center rounded-full bg-zinc-800 text-sm font-semibold uppercase text-zinc-200">
            {session.user.charAt(0)}
          </span>
          <span className="flex min-w-0 flex-col leading-tight">
            <span className="truncate text-sm font-medium text-zinc-100" translate="no">{session.user}</span>
            <span className="text-xs text-zinc-500">Administrator</span>
          </span>
          <form method="post" action="/logout" className="ml-auto">
            <input type="hidden" name="csrf_token" value={session.csrf} />
            <button
              type="submit"
              aria-label="Log Out"
              title="Log Out"
              className="grid size-9 place-items-center rounded-lg text-zinc-400 transition-colors hover:bg-zinc-900 hover:text-zinc-50"
            >
              <SignOut aria-hidden="true" className="size-[18px]" />
            </button>
          </form>
        </div>
      )}
    </aside>
  );
}
