import { describe, expect, it } from "vitest";
import { formatRelative, formatScore, formatWeight, humanizeCode } from "./format";

describe("format", () => {
  it("humanizes reason codes", () => {
    expect(humanizeCode("dmarc_fail")).toBe("DMARC fail");
    expect(humanizeCode("att_html")).toBe("Attachment HTML");
    expect(humanizeCode("missing_message_id")).toBe("Missing message ID");
    expect(humanizeCode("url_lookalike_domain")).toBe("URL lookalike domain");
  });

  it("never claims certainty", () => {
    expect([formatScore(0.9997), formatScore(0.0002), formatScore(0.5), formatScore(null)]).toEqual([
      ">99.9%", "<0.1%", "50.0%", "n/a",
    ]);
  });

  it("signs weights with a real minus sign", () => {
    expect([formatWeight(1.44), formatWeight(-2), formatWeight(0)]).toEqual(["+1.4", "−2.0", "±0.0"]);
  });

  it("reads clock skew as just now, older times relatively", () => {
    const now = Date.parse("2026-10-08T17:30:00Z");
    expect(formatRelative("2026-10-08T17:30:02Z", now)).toBe("just now");
    expect(formatRelative("2026-10-08T17:25:00Z", now)).toMatch(/5 minutes ago/);
  });
});
