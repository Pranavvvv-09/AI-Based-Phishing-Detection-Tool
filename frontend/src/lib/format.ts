// Display helpers. Dates and numbers go through Intl (user locale), never hand formats.

const absolute = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const count = new Intl.NumberFormat();

export function formatCount(value: number): string {
  return count.format(value);
}

export function formatAbsolute(iso: string | null): string {
  return iso ? absolute.format(new Date(iso)) : "Unknown time";
}

/** "3 minutes ago", "yesterday"; the absolute time goes in a tooltip. */
export function formatRelative(iso: string | null, now: number = Date.now()): string {
  if (!iso) return "Unknown time";
  const seconds = Math.round((new Date(iso).getTime() - now) / 1000);
  // Server and browser clocks differ slightly: anything this recent reads "just now".
  if (seconds > -45) return "just now";
  const steps: [Intl.RelativeTimeFormatUnit, number][] = [
    ["second", 60], ["minute", 60], ["hour", 24], ["day", 7], ["week", 4.35], ["month", 12],
  ];
  let value = seconds;
  for (const [unit, size] of steps) {
    if (Math.abs(value) < size) return relative.format(Math.round(value), unit);
    value /= size;
  }
  return relative.format(Math.round(value), "year");
}

/** Probability as a percentage that never claims certainty (same rule as the backend). */
export function formatScore(score: number | null): string {
  if (score === null) return "n/a";
  if (score >= 0.999) return ">99.9%";
  if (score <= 0.001) return "<0.1%";
  return `${(score * 100).toFixed(1)}%`;
}

/** "dmarc_fail" -> "DMARC fail", "url_lookalike_domain" -> "URL lookalike domain". */
const ACRONYMS = new Set(["dmarc", "spf", "dkim", "url", "sms", "html", "ip", "tld", "otp", "id"]);
const WORDS: Record<string, string> = { att: "attachment" };
export function humanizeCode(code: string): string {
  const words = code.split("_").filter(Boolean).map((word) => WORDS[word] ?? word);
  return words
    .map((word, i) => {
      if (ACRONYMS.has(word)) return word.toUpperCase();
      return i === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word;
    })
    .join(" ");
}

export function formatWeight(weight: number): string {
  return `${weight > 0 ? "+" : weight < 0 ? "−" : "±"}${Math.abs(weight).toFixed(1)}`;
}

const day = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
const dayLong = new Intl.DateTimeFormat(undefined, { weekday: "short", month: "short", day: "numeric", timeZone: "UTC" });
const percent = new Intl.NumberFormat(undefined, { style: "percent", maximumFractionDigits: 1 });

/** A UTC calendar day ("2026-10-08") as "Oct 8"; long form "Thu, Oct 8". */
export function formatDay(isoDate: string, long = false): string {
  const date = new Date(`${isoDate}T00:00:00Z`);
  return (long ? dayLong : day).format(date);
}

export function formatPercent(ratio: number): string {
  return percent.format(ratio);
}

export type Trend = { direction: "up" | "down" | "flat"; text: string };

/** Change against the previous window: "+12%", "−3%", "New" (from zero) or "No change". */
export function formatChange(current: number, previous: number): Trend {
  if (current === previous) return { direction: "flat", text: "No change" };
  if (previous === 0) return { direction: "up", text: "New" };
  const change = (current - previous) / previous;
  const size = Math.abs(change) >= 0.1 ? Math.round(Math.abs(change) * 100) : Math.round(Math.abs(change) * 1000) / 10;
  return { direction: change > 0 ? "up" : "down", text: `${change > 0 ? "+" : "−"}${size}%` };
}

/** Change in a rate, in percentage points: "+1.5 pts". */
export function formatPointChange(current: number, previous: number): Trend {
  const points = Math.round((current - previous) * 1000) / 10;
  if (points === 0) return { direction: "flat", text: "No change" };
  return { direction: points > 0 ? "up" : "down", text: `${points > 0 ? "+" : "−"}${Math.abs(points)} pts` };
}

/**
 * Whole-number axis ticks from 0 in ``steps`` equal steps of 1, 2, 2.5 (from 25 up) or 5
 * x 10^n, the smallest that covers ``max``: niceTicks(430, 2) -> [0, 250, 500].
 */
export function niceTicks(max: number, steps = 4): number[] {
  for (let power = 1; ; power *= 10) {
    const options = power >= 10 ? [1, 2, 2.5, 5] : [1, 2, 5];
    const step = options.map((n) => n * power).find((n) => n * steps >= max);
    if (step !== undefined) return Array.from({ length: steps + 1 }, (_, k) => k * step);
  }
}

/** Analyst-facing names for the evidence codes most often behind a quarantine. */
const VECTORS: Record<string, string> = {
  text_model: "Phishing language (ML)",
  sms_model: "Smishing language (ML)",
  url_credential_words: "Credential harvesting link",
  url_lookalike_domain: "Lookalike link domain",
  url_punycode: "Punycode link",
  punycode_sender_domain: "Punycode spoofing",
  lookalike_sender_domain: "Lookalike sender domain",
  display_name_brand_spoof: "Brand impersonation",
  display_name_other_email: "Display-name spoofing",
  dmarc_fail: "DMARC failures",
  spf_fail: "SPF failures",
  dkim_fail: "DKIM failures",
  forged_auth_header: "Forged auth header",
  link_text_mismatch: "Deceptive link text",
  link_text_brand_mismatch: "Deceptive brand link",
  form_in_email: "Embedded login form",
  url_shortener: "Link shortener",
  url_ip_host: "Raw IP link",
  url_http_only: "Unencrypted link",
  att_executable: "Executable attachment",
  att_macro: "Macro attachment",
  att_html: "HTML attachment",
};

export function vectorName(code: string): string {
  return VECTORS[code] ?? humanizeCode(code);
}
