import { describe, expect, it } from "vitest";
import { formatChange, formatPointChange, formatRelative, formatScore, formatWeight, humanizeCode, niceTicks } from "./format";

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

describe("overview helpers", () => {
  it("picks whole-number ticks", () => {
    expect(niceTicks(0)).toEqual([0, 1, 2, 3, 4]);
    expect(niceTicks(7)).toEqual([0, 2, 4, 6, 8]);
    expect(niceTicks(19)).toEqual([0, 5, 10, 15, 20]);
    expect(niceTicks(130)).toEqual([0, 50, 100, 150, 200]);
    expect(niceTicks(430, 2)).toEqual([0, 250, 500]);
    expect(niceTicks(6, 2)).toEqual([0, 5, 10]);
  });

  it("describes change against the previous window", () => {
    expect(formatChange(12, 10)).toEqual({ direction: "up", text: "+20%" });
    expect(formatChange(9, 10)).toEqual({ direction: "down", text: "−10%" });
    expect(formatChange(3, 0)).toEqual({ direction: "up", text: "New" });
    expect(formatChange(0, 0)).toEqual({ direction: "flat", text: "No change" });
    expect(formatPointChange(0.125, 0.11)).toEqual({ direction: "up", text: "+1.5 pts" });
  });
});
