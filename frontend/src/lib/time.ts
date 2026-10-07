import type { BucketWidth } from "../api";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

const DAY = 24 * HOUR;

export const BUCKET_MS: Record<BucketWidth, number> = { "1m": MINUTE, "5m": 5 * MINUTE, "1h": HOUR, "1d": DAY };

/** The finest bucket width that keeps a time range at 180 bars or fewer (days beyond that). */
export function chooseBucket(startMs: number, endMs: number): BucketWidth {
  const span = endMs - startMs;
  if (span <= 180 * MINUTE) return "1m";
  if (span <= 180 * 5 * MINUTE) return "5m";
  if (span <= 180 * HOUR) return "1h";
  return "1d";
}

/** ISO 8601 in UTC without the milliseconds the API never sends: 2026-09-10T02:31:00Z. */
export function toIso(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * A time range around an alert: its own duration plus a margin on both sides,
 * so the burst is seen in the middle of what happened just before and after.
 */
export function rangeAround(firstSeen: string, lastSeen: string): { start: string; end: string } {
  const first = Date.parse(firstSeen);
  const last = Date.parse(lastSeen);
  const margin = Math.max(MINUTE, Math.round((last - first) * 0.25));
  return { start: toIso(first - margin), end: toIso(last + margin + 1000) };
}

// All times are shown in UTC, the zone the backend stores them in.
const TIME = new Intl.DateTimeFormat("tr-TR", { timeZone: "UTC", hour: "2-digit", minute: "2-digit", second: "2-digit" });
const SHORT_TIME = new Intl.DateTimeFormat("tr-TR", { timeZone: "UTC", hour: "2-digit", minute: "2-digit" });
const DAY_FORMAT = new Intl.DateTimeFormat("tr-TR", { timeZone: "UTC", day: "numeric", month: "short" });

export function formatTime(value: string | number): string {
  return TIME.format(new Date(value));
}

export function formatShortTime(value: string | number): string {
  return SHORT_TIME.format(new Date(value));
}

export function formatDay(value: string | number): string {
  return DAY_FORMAT.format(new Date(value));
}

export function formatDateTime(value: string | number): string {
  return `${formatDay(value)} ${formatTime(value)}`;
}

/** "42 sn", "3 dk 5 sn", "2 sa 10 dk": how long something lasted. */
export function formatDuration(ms: number): string {
  const seconds = Math.max(0, Math.round(ms / 1000));
  if (seconds < 60) return `${seconds} sn`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return seconds % 60 ? `${minutes} dk ${seconds % 60} sn` : `${minutes} dk`;
  const hours = Math.floor(minutes / 60);
  return minutes % 60 ? `${hours} sa ${minutes % 60} dk` : `${hours} sa`;
}

const TICK_STEPS = [MINUTE, 5 * MINUTE, 15 * MINUTE, 30 * MINUTE, HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY];

/** Round times for axis ticks: the smallest step that gives at most `maxTicks` ticks. */
export function timeTicks(startMs: number, endMs: number, maxTicks: number): number[] {
  const span = Math.max(endMs - startMs, 1);
  const fit = TICK_STEPS.find((candidate) => span / candidate <= maxTicks);
  // Longer than the table reaches: whole days, as many as needed.
  const step = fit ?? Math.ceil(span / maxTicks / DAY) * DAY;
  const ticks: number[] = [];
  for (let tick = Math.ceil(startMs / step) * step; tick <= endMs; tick += step) ticks.push(tick);
  return ticks;
}

const NICE_STEPS = [1, 2, 3, 4, 5, 6, 8, 10];

/**
 * A round number at or above `value` for the top of a count axis: 1, 2, 3, 4,
 * 5, 6 or 8 times a power of ten. Fine enough steps that the tallest bar always
 * fills more than half of the chart.
 */
export function niceCeiling(value: number): number {
  if (value <= 1) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const leading = value / magnitude;
  return (NICE_STEPS.find((step) => leading <= step) ?? 10) * magnitude;
}

const NUMBER = new Intl.NumberFormat("tr-TR");

export function formatCount(value: number): string {
  return NUMBER.format(value);
}
