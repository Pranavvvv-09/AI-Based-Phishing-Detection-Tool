import { ChatText, EnvelopeSimple, Tray } from "@phosphor-icons/react";
import { Fragment, useState } from "react";
import type { QuarantineRow } from "../lib/api";
import { formatAbsolute, formatRelative, formatScore } from "../lib/format";
import { RestoreButton } from "./RestoreButton";
import { SignalChip } from "./SignalChip";
import { StatusBadge } from "./StatusBadge";

const CHIPS_SHOWN = 3;
const COLUMNS = 7;

interface Props {
  rows: QuarantineRow[] | null; // null while the first load is running
  busy: ReadonlySet<string>;
  leaving: ReadonlySet<string>; // restored rows sliding out of the current filter
  errors: Readonly<Record<string, string>>;
  now: number;
  emptyText: string;
  onRestore: (row: QuarantineRow) => void;
}

const TYPE = {
  email: { label: "Email", Icon: EnvelopeSimple },
  sms: { label: "SMS", Icon: ChatText },
  text: { label: "Text", Icon: ChatText },
} as const;

function scoreTone(score: number | null): string {
  if (score === null) return "text-zinc-400";
  return score >= 0.8 ? "text-red-300" : score >= 0.5 ? "text-amber-300" : "text-emerald-300";
}

// Phones and tablets: rows become stacked blocks (no horizontal scrolling); lg and up: a real table.
const CELL = "px-3 py-3 align-top 2xl:px-4 max-lg:block max-lg:px-0 max-lg:py-1";

export function QuarantineTable({ rows, busy, leaving, errors, now, emptyText, onRestore }: Props) {
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());

  function toggle(id: string) {
    setOpen((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900/40">
      <table className="w-full border-collapse text-left text-sm max-lg:block">
        <caption className="sr-only">Quarantined messages with the evidence behind each verdict</caption>
        <thead className="border-b border-zinc-800 text-xs font-medium text-zinc-400 max-lg:hidden">
          <tr>
            <th scope="col" className="px-3 py-3 font-medium 2xl:px-4">Time</th>
            <th scope="col" className="px-3 py-3 font-medium 2xl:px-4">Type</th>
            <th scope="col" className="px-3 py-3 font-medium 2xl:px-4">Sender</th>
            <th scope="col" className="px-3 py-3 text-right font-medium 2xl:px-4">Score</th>
            <th scope="col" className="px-3 py-3 font-medium 2xl:px-4">Signals</th>
            <th scope="col" className="px-3 py-3 font-medium 2xl:px-4">Status</th>
            <th scope="col" className="px-3 py-3 2xl:px-4"><span className="sr-only">Action</span></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800/80 max-lg:block">
          {rows === null && <SkeletonRows />}
          {rows !== null && rows.length === 0 && (
            <tr className="max-lg:block">
              <td colSpan={COLUMNS} className="px-6 py-16 text-center max-lg:block">
                <Tray aria-hidden="true" className="mx-auto size-8 text-zinc-600" />
                <p className="mt-3 text-sm font-medium text-zinc-300">{emptyText}</p>
                <p className="mt-1 text-sm text-zinc-500">
                  New phishing appears here as soon as the mailbox poller moves it.
                </p>
              </td>
            </tr>
          )}
          {rows?.map((row) => {
            const type = TYPE[row.kind] ?? TYPE.email;
            const isOpen = open.has(row.incident_id);
            const detailId = `signals-${row.incident_id}`;
            const hidden = row.reasons.length - CHIPS_SHOWN;
            const name = row.subject || row.from || "message";
            const isLeaving = leaving.has(row.incident_id);
            return (
              <Fragment key={row.incident_id}>
                <tr
                  data-incident={row.incident_id}
                  className={`q-row hover:bg-zinc-900 max-lg:grid max-lg:gap-1 max-lg:px-4 max-lg:py-4 ${
                    isLeaving ? "is-leaving" : row.status === "restored" ? "opacity-70" : ""
                  }`}
                >
                  <td className={`${CELL} whitespace-nowrap text-zinc-400`}>
                    <time dateTime={row.quarantined_at ?? undefined} title={formatAbsolute(row.quarantined_at)}>
                      {formatRelative(row.quarantined_at, now)}
                    </time>
                  </td>
                  <td className={`${CELL} whitespace-nowrap`}>
                    <span className="inline-flex items-center gap-1.5 text-zinc-300">
                      <type.Icon aria-hidden="true" className="size-4 text-zinc-500" />
                      {type.label}
                    </span>
                  </td>
                  <td className={`${CELL} min-w-0 lg:max-w-[13rem] 2xl:max-w-[22rem]`}>
                    <div className="truncate font-medium text-zinc-100" title={row.from}>
                      {row.from || "Unknown sender"}
                    </div>
                    <div className="truncate text-zinc-500" title={row.subject}>
                      {row.subject || "(no subject)"}
                    </div>
                  </td>
                  <td className={`${CELL} whitespace-nowrap text-right max-lg:text-left`}>
                    <span className="mr-1 text-zinc-500 lg:hidden">Score</span>
                    <span className={`font-mono font-medium tabular-nums ${scoreTone(row.score)}`}>
                      {formatScore(row.score)}
                    </span>
                  </td>
                  <td className={`${CELL} lg:max-w-[26rem]`}>
                    <div className="flex flex-wrap items-center gap-1.5">
                      {row.reasons.slice(0, CHIPS_SHOWN).map((reason) => (
                        <SignalChip key={`${reason.source}-${reason.code}`} reason={reason} />
                      ))}
                      {row.reasons.length > 0 && (
                        <button
                          type="button"
                          aria-expanded={isOpen}
                          aria-controls={detailId}
                          onClick={() => toggle(row.incident_id)}
                          className="rounded-md px-1.5 py-0.5 text-xs font-medium text-accent transition-colors hover:bg-zinc-800 hover:text-accent-strong"
                        >
                          {isOpen ? "Hide details" : hidden > 0 ? `+${hidden} more` : "Details"}
                        </button>
                      )}
                      {row.reasons.length === 0 && <span className="text-xs text-zinc-500">No report on file</span>}
                    </div>
                  </td>
                  <td className={`${CELL} whitespace-nowrap`}>
                    {/* Keyed by status, so a change (Held to Restored) cross-fades in. */}
                    <StatusBadge
                      key={busy.has(row.incident_id) ? "restoring" : row.status}
                      status={busy.has(row.incident_id) ? "restoring" : row.status}
                    />
                    {row.status === "restored" && row.restored_at && (
                      <div className="mt-1 text-xs text-zinc-500" title={formatAbsolute(row.restored_at)}>
                        {formatRelative(row.restored_at, now)}
                      </div>
                    )}
                  </td>
                  <td className={`${CELL} text-right max-lg:pt-3 max-lg:text-left`}>
                    {row.status !== "restored" && (
                      <RestoreButton
                        busy={busy.has(row.incident_id) || row.status === "restoring"}
                        label={name}
                        onClick={() => onRestore(row)}
                      />
                    )}
                    {errors[row.incident_id] && (
                      <p role="alert" className="mt-2 max-w-[16rem] text-left text-xs text-red-300 lg:ml-auto">
                        {errors[row.incident_id]}
                      </p>
                    )}
                  </td>
                </tr>
                {isOpen && (
                  <tr id={detailId} className={`q-row bg-zinc-950/60 max-lg:block ${isLeaving ? "is-leaving" : ""}`}>
                    <td colSpan={COLUMNS} className="px-4 pb-4 pt-1 max-lg:block">
                      <ReasonList row={row} />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ReasonList({ row }: { row: QuarantineRow }) {
  return (
    <div className="rounded-lg border border-zinc-800 p-4">
      <p className="mb-3 text-xs text-zinc-500">
        Every signal behind this verdict. Positive weights push towards phishing, negative towards
        legitimate (log-odds).
      </p>
      <ul className="grid gap-2">
        {row.reasons.map((reason) => (
          <li key={`${reason.source}-${reason.code}`} className="grid grid-cols-[minmax(0,14rem)_1fr_auto] items-start gap-3 max-sm:grid-cols-[1fr_auto]">
            <span className="min-w-0">
              <SignalChip reason={reason} tooltip={false} />
            </span>
            <span className="text-zinc-300 max-sm:col-span-2 max-sm:row-start-2">{reason.detail}</span>
            <span className="whitespace-nowrap text-right font-mono text-xs text-zinc-500">
              {reason.source} layer
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function SkeletonRows() {
  return (
    <>
      {Array.from({ length: 4 }, (_, i) => (
        <tr key={i} aria-hidden="true" className="max-lg:block max-lg:px-4 max-lg:py-4">
          {["w-20", "w-14", "w-48", "w-12", "w-56", "w-14", "w-36"].map((width, j) => (
            <td key={j} className={CELL}>
              <span className={`block h-4 ${width} max-w-full animate-pulse rounded-md bg-zinc-800`} />
            </td>
          ))}
        </tr>
      ))}
      <tr className="sr-only">
        <td>Loading quarantined messages…</td>
      </tr>
    </>
  );
}
