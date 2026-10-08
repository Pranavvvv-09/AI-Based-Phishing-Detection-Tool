import { describe, expect, it } from "vitest";
import { parseDuration } from "./motion";

describe("parseDuration", () => {
  it("reads both units, as the minifier may rewrite 200ms to .2s", () => {
    expect(parseDuration("200ms")).toBe(200);
    expect(parseDuration(" .2s")).toBe(200);
    expect(parseDuration("0.15s")).toBe(150);
    expect(parseDuration("")).toBeNull();
    expect(parseDuration("fast")).toBeNull();
  });
});
