import type { Session } from "../lib/api";
import { formatRelative } from "../lib/format";

type PollerState = Session["poller"]["state"];

/** Short label for tight spaces; the full sentence comes from pollerText(). */
export const POLLER_LABEL: Record<PollerState, string> = {
  ok: "Live",
  warn: "Delayed",
  error: "Poller error",
  off: "Poller off",
};

export function pollerText(session: Session): string {
  const { poller } = session;
  if (poller.state === "off" || !poller.last_poll_at) return poller.text;
  const checked = `Checked ${formatRelative(poller.last_poll_at, Date.now())}`;
  return poller.error ? `${checked}. ${poller.error}` : `Watching ${poller.mailbox}. ${checked}`;
}

/** A real status light (poller health), not decoration. It only pulses while live. */
export function Beacon({ state }: { state: PollerState }) {
  return <span aria-hidden="true" data-state={state} className="beacon" />;
}

const HEARTBEAT: Record<PollerState, string> = {
  ok: "Watching inbox · Active",
  warn: "Watching inbox · Delayed",
  error: "Poller error",
  off: "Poller off",
};

/** Header badge: the beacon plus the poller's state in words (words hidden on phones). */
export function HeartbeatBadge({ session }: { session: Session }) {
  return (
    <p
      className="inline-flex min-w-0 items-center gap-2 rounded-full border border-zinc-800 bg-zinc-900/60 px-2.5 py-1 text-xs font-medium text-zinc-300 max-sm:border-0 max-sm:bg-transparent max-sm:px-1"
      title={pollerText(session)}
    >
      <Beacon state={session.poller.state} />
      <span className="truncate max-sm:sr-only">{HEARTBEAT[session.poller.state]}</span>
    </p>
  );
}
