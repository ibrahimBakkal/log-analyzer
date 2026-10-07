import type { BucketWidth } from "../api";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

export const BUCKET_MS: Record<BucketWidth, number> = { "1m": MINUTE, "5m": 5 * MINUTE, "1h": HOUR };

/** The finest bucket width that keeps a time range at about 180 bars or fewer. */
export function chooseBucket(startMs: number, endMs: number): BucketWidth {
  const span = endMs - startMs;
  if (span <= 3 * HOUR) return "1m";
  if (span <= 15 * HOUR) return "5m";
  return "1h";
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
const DAY = new Intl.DateTimeFormat("tr-TR", { timeZone: "UTC", day: "numeric", month: "short" });

export function formatTime(value: string | number): string {
  return TIME.format(new Date(value));
}

export function formatShortTime(value: string | number): string {
  return SHORT_TIME.format(new Date(value));
}

export function formatDay(value: string | number): string {
  return DAY.format(new Date(value));
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

const TICK_STEPS = [MINUTE, 5 * MINUTE, 15 * MINUTE, 30 * MINUTE, HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, 24 * HOUR];

/** Round times for axis ticks: the smallest step that gives at most `maxTicks` ticks. */
export function timeTicks(startMs: number, endMs: number, maxTicks: number): number[] {
  const span = Math.max(endMs - startMs, 1);
  const fit = TICK_STEPS.find((candidate) => span / candidate <= maxTicks);
  // Longer than the table reaches: whole days, as many as needed.
  const step = fit ?? Math.ceil(span / maxTicks / (24 * HOUR)) * 24 * HOUR;
  const ticks: number[] = [];
  for (let tick = Math.ceil(startMs / step) * step; tick <= endMs; tick += step) ticks.push(tick);
  return ticks;
}

/** A round number at or above `value` for the top of a count axis: 1, 2, 5, 10, 20, 50, ... */
export function niceCeiling(value: number): number {
  if (value <= 1) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const leading = value / magnitude;
  const nice = leading <= 1 ? 1 : leading <= 2 ? 2 : leading <= 5 ? 5 : 10;
  return nice * magnitude;
}

const NUMBER = new Intl.NumberFormat("tr-TR");

export function formatCount(value: number): string {
  return NUMBER.format(value);
}
