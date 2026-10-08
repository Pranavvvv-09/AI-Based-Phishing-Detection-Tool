import { ArrowRight, Flask } from "@phosphor-icons/react";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";

/**
 * A test bench on the dashboard: posts straight to the server-rendered Quick Scan page
 * (/scan, with the session's CSRF token), which shows the verdict and its evidence.
 */
export function QuickScanCard({ csrf }: { csrf: string | null }) {
  return (
    <Card id="quick-scan" aria-labelledby="quick-scan-title" className="scroll-mt-24">
      <CardHeader>
        <CardTitle id="quick-scan-title" className="flex items-center gap-2">
          <Flask aria-hidden="true" weight="duotone" className="size-[18px] text-accent" />
          Quick Scan Sandbox
        </CardTitle>
        <CardDescription>
          Paste a suspicious email or SMS to see the verdict and the evidence behind it. Nothing is stored and no link is opened.
        </CardDescription>
        <CardAction>
          <a
            href="/scan"
            className="inline-flex h-8 items-center gap-1.5 rounded-lg px-2.5 text-sm font-medium text-accent transition-colors hover:bg-zinc-800 hover:text-accent-strong"
          >
            Upload .eml
            <ArrowRight aria-hidden="true" className="size-4" />
          </a>
        </CardAction>
      </CardHeader>
      <CardContent>
        <form method="post" action="/scan" encType="multipart/form-data" className="flex flex-col gap-3">
          <input type="hidden" name="csrf_token" value={csrf ?? ""} />
          <fieldset className="flex items-center gap-3">
            <legend className="sr-only">Message type</legend>
            <div className="inline-flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5 text-sm font-medium">
              {[
                { value: "email", label: "Email" },
                { value: "sms", label: "SMS" },
              ].map((option) => (
                <label
                  key={option.value}
                  className="inline-flex h-8 cursor-pointer items-center rounded-md px-3 text-zinc-400 transition-colors hover:text-zinc-200 has-[:checked]:bg-zinc-800 has-[:checked]:text-zinc-50 has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent"
                >
                  <input type="radio" name="kind" value={option.value} defaultChecked={option.value === "email"} className="sr-only" />
                  {option.label}
                </label>
              ))}
            </div>
          </fieldset>
          <label htmlFor="quick-scan-text" className="sr-only">Message to scan</label>
          <textarea
            id="quick-scan-text"
            name="text"
            required
            rows={4}
            autoComplete="off"
            spellCheck={false}
            placeholder="URGENT: your account is locked. Verify at http://paypa1-secure.example/login…"
            className="w-full resize-y rounded-lg border border-zinc-800 bg-zinc-950/70 px-3 py-2.5 font-mono text-[13px] text-zinc-100 placeholder:text-zinc-600 hover:border-zinc-700"
          />
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-zinc-500">Pasted email headers are parsed too, for SPF, DKIM and DMARC checks.</p>
            <button
              type="submit"
              disabled={!csrf}
              className="inline-flex h-9 items-center gap-2 rounded-lg bg-zinc-100 px-4 text-sm font-semibold text-zinc-950 transition-colors hover:bg-white disabled:opacity-60"
            >
              Run Scan
            </button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
