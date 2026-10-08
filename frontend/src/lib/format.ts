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
