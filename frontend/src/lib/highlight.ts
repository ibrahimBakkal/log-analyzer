import type { Highlight, Severity } from "../api";

/** A run of message text and the highlights that cover all of it (none: plain text). */
export interface Segment {
  text: string;
  marks: Highlight[];
}

const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/** The most severe of the given highlights, or null if there are none. */
export function topSeverity(highlights: readonly Highlight[]): Severity | null {
  let top: Severity | null = null;
  for (const { severity } of highlights) {
    if (top === null || RANK[severity] > RANK[top]) top = severity;
  }
  return top;
}

/**
 * Cut a message into segments at the edges of its highlights, so that each
 * segment can be rendered as plain text or inside one <mark>.
 *
 * Offsets count code points, as the backend does, not UTF-16 units; the two
 * differ after an emoji. Ranges are clipped to the message, empty or reversed
 * ranges are dropped, and a highlight without a range (the line as a whole is
 * the evidence) marks no text. The segments always add up to the message.
 */
export function splitByHighlights(message: string, highlights: readonly Highlight[]): Segment[] {
  const points = Array.from(message);
  const ranged = highlights.flatMap((highlight) => {
    if (highlight.start === null || highlight.end === null) return [];
    const start = Math.max(0, highlight.start);
    const end = Math.min(points.length, highlight.end);
    return start < end ? [{ highlight, start, end }] : [];
  });
  if (points.length === 0) return [];

  const edges = new Set([0, points.length]);
  for (const { start, end } of ranged) edges.add(start).add(end);
  const cuts = [...edges].sort((a, b) => a - b);

  const segments: Segment[] = [];
  for (let index = 0; index < cuts.length - 1; index++) {
    const [from, to] = [cuts[index], cuts[index + 1]];
    const marks = ranged
      .filter(({ start, end }) => start <= from && to <= end)
      .map(({ highlight }) => highlight);
    const text = points.slice(from, to).join("");
    const previous = segments.at(-1);
    if (previous && sameMarks(previous.marks, marks)) {
      previous.text += text;
    } else {
      segments.push({ text, marks });
    }
  }
  return segments;
}

function sameMarks(a: readonly Highlight[], b: readonly Highlight[]): boolean {
  return a.length === b.length && a.every((mark, index) => mark === b[index]);
}
