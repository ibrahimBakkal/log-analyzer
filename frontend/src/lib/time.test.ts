import { describe, expect, it } from "vitest";
import { chooseBucket, formatDuration, niceCeiling, rangeAround, timeTicks, toIso } from "./time";

const T0 = Date.parse("2026-09-09T00:00:00Z");
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

describe("chooseBucket", () => {
  it("uses the finest width that keeps the chart readable", () => {
    expect(chooseBucket(T0, T0 + 5 * MINUTE)).toBe("1m");
    expect(chooseBucket(T0, T0 + 3 * HOUR)).toBe("1m");
    expect(chooseBucket(T0, T0 + 3 * HOUR + 1)).toBe("5m");
    expect(chooseBucket(T0, T0 + 15 * HOUR)).toBe("5m");
    expect(chooseBucket(T0, T0 + 48 * HOUR)).toBe("1h");
  });
});

describe("toIso", () => {
  it("writes UTC without milliseconds", () => {
    expect(toIso(T0 + 1500)).toBe("2026-09-09T00:00:01Z");
  });
});

describe("rangeAround", () => {
  it("leaves at least a minute on both sides of a short alert", () => {
    expect(rangeAround("2026-09-10T02:31:40Z", "2026-09-10T02:32:33Z")).toEqual({
      start: "2026-09-10T02:30:40Z",
      end: "2026-09-10T02:33:34Z",
    });
  });

  it("includes the last event although the range end is exclusive", () => {
    const { end } = rangeAround("2026-09-10T02:34:08Z", "2026-09-10T02:34:08Z");
    expect(Date.parse(end)).toBeGreaterThan(Date.parse("2026-09-10T02:34:08Z"));
  });

  it("widens the margin for a long alert", () => {
    const range = rangeAround("2026-09-09T10:00:00Z", "2026-09-09T14:00:00Z");
    expect(range.start).toBe("2026-09-09T09:00:00Z");
    expect(range.end).toBe("2026-09-09T15:00:01Z");
  });
});

describe("timeTicks", () => {
  it("puts ticks on round times inside the range", () => {
    expect(timeTicks(T0 + 10 * MINUTE, T0 + 2 * HOUR + 50 * MINUTE, 6).map(toIso)).toEqual([
      "2026-09-09T00:30:00Z",
      "2026-09-09T01:00:00Z",
      "2026-09-09T01:30:00Z",
      "2026-09-09T02:00:00Z",
      "2026-09-09T02:30:00Z",
    ]);
  });

  it("never returns more ticks than asked for", () => {
    for (const span of [4 * MINUTE, 50 * MINUTE, 7 * HOUR, 48 * HOUR, 40 * 24 * HOUR]) {
      const ticks = timeTicks(T0, T0 + span, 8);
      expect(ticks.length).toBeLessThanOrEqual(9); // both ends can land on a tick
      expect(ticks.length).toBeGreaterThan(0);
    }
  });
});

describe("niceCeiling", () => {
  it("rounds up to a round number", () => {
    expect([0, 1, 2, 3, 5, 7, 12, 48, 173, 210, 1000, 1001].map(niceCeiling)).toEqual([
      1, 1, 2, 3, 5, 8, 20, 50, 200, 300, 1000, 2000,
    ]);
  });

  it("never leaves the tallest bar below half of the chart", () => {
    for (let value = 1; value <= 5000; value++) {
      const top = niceCeiling(value);
      expect(top).toBeGreaterThanOrEqual(value);
      expect(value / top).toBeGreaterThan(0.5);
    }
  });
});

describe("formatDuration", () => {
  it("uses the largest two units that matter", () => {
    expect(formatDuration(0)).toBe("0 sn");
    expect(formatDuration(53_000)).toBe("53 sn");
    expect(formatDuration(85_000)).toBe("1 dk 25 sn");
    expect(formatDuration(120_000)).toBe("2 dk");
    expect(formatDuration(2 * HOUR + 10 * MINUTE)).toBe("2 sa 10 dk");
    expect(formatDuration(3 * HOUR)).toBe("3 sa");
  });
});
