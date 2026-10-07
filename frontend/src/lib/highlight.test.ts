import { describe, expect, it } from "vitest";
import type { Highlight, Severity } from "../api";
import { splitByHighlights, topSeverity } from "./highlight";

const MESSAGE = "Failed password for root from 203.0.113.45 port 52744 ssh2";

function mark(start: number | null, end: number | null, severity: Severity = "high", alert_id = 1): Highlight {
  return { alert_id, rule_id: "SSH-001", severity, start, end };
}

/** [text, number of highlights covering it] for each segment. */
function shape(message: string, highlights: Highlight[]): [string, number][] {
  return splitByHighlights(message, highlights).map((segment) => [segment.text, segment.marks.length]);
}

describe("splitByHighlights", () => {
  it("returns the whole message as plain text when nothing is highlighted", () => {
    expect(shape(MESSAGE, [])).toEqual([[MESSAGE, 0]]);
  });

  it("returns no segments for an empty message", () => {
    expect(splitByHighlights("", [mark(0, 5)])).toEqual([]);
  });

  it("cuts out a highlight in the middle", () => {
    expect(shape(MESSAGE, [mark(30, 42)])).toEqual([
      ["Failed password for root from ", 0],
      ["203.0.113.45", 1],
      [" port 52744 ssh2", 0],
    ]);
  });

  it("handles highlights at the very start and the very end", () => {
    expect(shape(MESSAGE, [mark(0, 6)])).toEqual([
      ["Failed", 1],
      [MESSAGE.slice(6), 0],
    ]);
    expect(shape(MESSAGE, [mark(54, 58)])).toEqual([
      [MESSAGE.slice(0, 54), 0],
      ["ssh2", 1],
    ]);
    expect(shape(MESSAGE, [mark(0, MESSAGE.length)])).toEqual([[MESSAGE, 1]]);
  });

  it("keeps separate highlights separate, whatever order they arrive in", () => {
    const expected = [
      ["cat ", 0],
      ["/etc/shadow", 1],
      [" ", 0],
      ["/etc/sudoers", 1],
    ];
    expect(shape("cat /etc/shadow /etc/sudoers", [mark(4, 15), mark(16, 28)])).toEqual(expected);
    expect(shape("cat /etc/shadow /etc/sudoers", [mark(16, 28), mark(4, 15)])).toEqual(expected);
  });

  it("splits overlapping highlights at every edge and lists all that cover a piece", () => {
    const first = mark(0, 6, "high", 1);
    const second = mark(4, 10, "medium", 2);
    const segments = splitByHighlights("abcdefghijkl", [first, second]);
    expect(segments).toEqual([
      { text: "abcd", marks: [first] },
      { text: "ef", marks: [first, second] },
      { text: "ghij", marks: [second] },
      { text: "kl", marks: [] },
    ]);
  });

  it("gives one segment to two alerts that mark the same text", () => {
    const first = mark(30, 42, "high", 1);
    const second = mark(30, 42, "critical", 2);
    const segments = splitByHighlights(MESSAGE, [first, second]);
    expect(segments[1]).toEqual({ text: "203.0.113.45", marks: [first, second] });
    expect(segments).toHaveLength(3);
  });

  it("joins touching highlights of the same alert into one piece only if they are the same mark", () => {
    const whole = mark(0, 4);
    expect(shape("abcdef", [whole, whole])).toEqual([
      ["abcd", 2],
      ["ef", 0],
    ]);
    expect(shape("abcdef", [mark(0, 2), mark(2, 4)])).toEqual([
      ["ab", 1],
      ["cd", 1],
      ["ef", 0],
    ]);
  });

  it("clips ranges that reach outside the message", () => {
    expect(shape("abcdef", [mark(-3, 2), mark(4, 99)])).toEqual([
      ["ab", 1],
      ["cd", 0],
      ["ef", 1],
    ]);
  });

  it("ignores empty, reversed and out-of-range highlights", () => {
    expect(shape("abcdef", [mark(3, 3), mark(5, 2), mark(10, 20)])).toEqual([["abcdef", 0]]);
  });

  it("marks no text for a highlight without a range", () => {
    expect(shape("abcdef", [mark(null, null)])).toEqual([["abcdef", 0]]);
  });

  it("counts code points like the backend, not UTF-16 units", () => {
    // "😀" is one code point but two UTF-16 units; "ş" and "ı" are one of each.
    expect(shape("😀 şifre yanlış", [mark(2, 7)])).toEqual([
      ["😀 ", 0],
      ["şifre", 1],
      [" yanlış", 0],
    ]);
  });

  it("always adds up to the original message", () => {
    const highlights = [mark(3, 9), mark(7, 20), mark(0, 1), mark(50, 400), mark(null, null), mark(12, 12)];
    const text = splitByHighlights(MESSAGE, highlights)
      .map((segment) => segment.text)
      .join("");
    expect(text).toBe(MESSAGE);
  });
});

describe("topSeverity", () => {
  it("is null without highlights", () => {
    expect(topSeverity([])).toBeNull();
  });

  it("picks the most severe highlight", () => {
    expect(topSeverity([mark(0, 1, "medium"), mark(0, 1, "critical"), mark(0, 1, "low")])).toBe("critical");
    expect(topSeverity([mark(0, 1, "low"), mark(0, 1, "high")])).toBe("high");
    expect(topSeverity([mark(null, null, "low")])).toBe("low");
  });
});
