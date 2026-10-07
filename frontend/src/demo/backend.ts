// The API, answered in the browser from a recording of the sample logs.
//
// The demo build has no server. `snapshot.json` holds what the real API returns
// for the two sample logs; the functions here answer the same questions the
// server would, from that recording. `backend.test.ts` puts a list of questions
// to them whose answers were recorded from the real API (`cases.json`), so the
// two cannot drift apart unnoticed. Both files are written by `samples/build_demo.py`.

import {
  type Alert,
  type AlertList,
  type Api,
  ApiError,
  type EventPage,
  type LogEvent,
  type PortReport,
  type PortStats,
  type QueryParams,
  type RuleList,
  type Severity,
  type Stats,
  type TimelineData,
} from "../api";
import recording from "./snapshot.json?raw";

interface Snapshot {
  /** In the order the API lists them: by time, then by id. */
  events: LogEvent[];
  /** Newest first. */
  alerts: Alert[];
  rules: RuleList;
}

const snapshot = JSON.parse(recording) as Snapshot;
const TIME = new Map(snapshot.events.map((event) => [event.id, Date.parse(event.ts)]));

const BUCKET_SECONDS: Record<string, number> = { "1m": 60, "5m": 300, "1h": 3600 };
const MAX_PAGE = 500;
const MAX_PORTS = 500;
const MAX_CONNECTIONS = 2000;
const TOP_SOURCES = 5;

function text(value: QueryParams[string]): string | undefined {
  return value === undefined || value === null || value === "" ? undefined : String(value);
}

function time(value: QueryParams[string]): number | undefined {
  const given = text(value);
  if (given === undefined) return undefined;
  // As on the server, a time without an offset is UTC.
  return Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(given) ? given : `${given}Z`);
}

/** The events the filters of /events, /timeline and /stats select, oldest first. */
function select(params: QueryParams): LogEvent[] {
  const start = time(params.start);
  const end = time(params.end);
  const host = text(params.host);
  const service = text(params.service);
  const ip = text(params.ip);
  const level = text(params.level);
  const action = text(params.action);
  const parsed = text(params.parsed);
  const alert = text(params.alert_id);
  const rule = text(params.rule_id);

  return snapshot.events.filter((event) => {
    const at = TIME.get(event.id)!;
    if (start !== undefined && at < start) return false;
    if (end !== undefined && at >= end) return false;
    if (host !== undefined && event.host !== host) return false;
    if (service !== undefined && event.service !== service) return false;
    if (ip !== undefined && event.src_ip !== ip && event.dst_ip !== ip) return false;
    if (level !== undefined && event.level !== level) return false;
    if (action !== undefined && event.action !== action) return false;
    if (parsed !== undefined && String(event.parsed) !== parsed) return false;
    if (alert !== undefined && !event.highlights.some((mark) => String(mark.alert_id) === alert)) return false;
    if (rule !== undefined && !event.highlights.some((mark) => mark.rule_id === rule)) return false;
    return true;
  });
}

function events(params: QueryParams): EventPage {
  const limit = Math.min(MAX_PAGE, Math.max(1, Number(params.limit ?? 100)));
  const selected = text(params.order) === "desc" ? select(params).reverse() : select(params);
  // The cursor is the id of the last event of the page before.
  const cursor = text(params.cursor);
  const from = cursor === undefined ? 0 : selected.findIndex((event) => String(event.id) === cursor) + 1;
  const items = selected.slice(from, from + limit);
  const more = from + limit < selected.length;
  return { items, next_cursor: more ? String(items[items.length - 1].id) : null };
}

function alertsIn(params: QueryParams): Alert[] {
  const start = time(params.start);
  const end = time(params.end);
  const rule = text(params.rule_id);
  const severity = text(params.severity);
  const key = text(params.group_key);
  return snapshot.alerts.filter(
    (alert) =>
      (rule === undefined || alert.rule_id === rule) &&
      (severity === undefined || alert.severity === severity) &&
      (key === undefined || alert.group_key === key) &&
      (start === undefined || Date.parse(alert.last_seen) >= start) &&
      (end === undefined || Date.parse(alert.first_seen) < end),
  );
}

function alerts(params: QueryParams): AlertList {
  const found = alertsIn(params);
  const limit = Math.min(MAX_PAGE, Math.max(1, Number(params.limit ?? 100)));
  return { items: found.slice(0, limit), total: found.length };
}

/** 2026-09-09T03:00:00Z, the way the server writes times. */
function stamp(ms: number): string {
  return new Date(ms).toISOString().replace(".000Z", "Z");
}

function timeline(params: QueryParams): TimelineData {
  const seconds = BUCKET_SECONDS[text(params.bucket) ?? "5m"];
  if (!seconds) throw new ApiError("Geçersiz kova genişliği.", 422);
  const width = seconds * 1000;
  const buckets = new Map<number, { count: number; warnings: number }>();
  for (const event of select(params)) {
    const first = Math.floor(TIME.get(event.id)! / width) * width;
    const bucket = buckets.get(first) ?? { count: 0, warnings: 0 };
    bucket.count += 1;
    if (event.level === "warning") bucket.warnings += 1;
    buckets.set(first, bucket);
  }
  return {
    bucket_seconds: seconds,
    buckets: [...buckets.entries()].sort(([a], [b]) => a - b).map(([first, bucket]) => ({ ts: stamp(first), ...bucket })),
  };
}

function stats(params: QueryParams): Stats {
  const selected = select({ start: params.start, end: params.end });
  const parsed = selected.filter((event) => event.parsed).length;
  const actions: Record<string, number> = {};
  const sources = new Map<string, { events: number; failures: number }>();
  for (const event of selected) {
    if (event.action) actions[event.action] = (actions[event.action] ?? 0) + 1;
    if (event.src_ip) {
      const source = sources.get(event.src_ip) ?? { events: 0, failures: 0 };
      source.events += 1;
      if (event.action === "auth_fail") source.failures += 1;
      sources.set(event.src_ip, source);
    }
  }
  const severities: Partial<Record<Severity, number>> = {};
  const found = alertsIn({ start: params.start, end: params.end });
  for (const alert of found) severities[alert.severity] = (severities[alert.severity] ?? 0) + 1;

  return {
    events: selected.length,
    parsed,
    unparsed: selected.length - parsed,
    unparsed_ratio: selected.length ? Math.round(((selected.length - parsed) / selected.length) * 10000) / 10000 : 0,
    first_event: selected.length ? selected[0].ts : null,
    last_event: selected.length ? selected[selected.length - 1].ts : null,
    sources: sources.size,
    actions,
    alerts: found.length,
    alerts_by_severity: severities,
    top_sources: [...sources.entries()]
      .map(([src_ip, source]) => ({ src_ip, ...source }))
      .sort((a, b) => b.failures - a.failures || b.events - a.events || (a.src_ip < b.src_ip ? -1 : 1))
      .slice(0, TOP_SOURCES),
  };
}

function ports(params: QueryParams): PortReport {
  const ip = text(params.ip);
  if (ip === undefined) throw new ApiError("Bir IP adresi gerekli.", 422);
  const start = time(params.start);
  const end = time(params.end);
  const packets = snapshot.events.filter((event) => {
    const at = TIME.get(event.id)!;
    return event.src_ip === ip && event.dst_port !== null && (start === undefined || at >= start) && (end === undefined || at < end);
  });

  const perPort = new Map<number, PortStats>();
  let blocked = 0;
  let allowed = 0;
  for (const packet of packets) {
    const port = packet.dst_port!;
    const entry = perPort.get(port) ?? { port, count: 0, blocked: 0, allowed: 0, first_seen: packet.ts, last_seen: packet.ts };
    entry.count += 1;
    entry.last_seen = packet.ts; // packets come in time order
    if (packet.action === "conn_block") {
      entry.blocked += 1;
      blocked += 1;
    } else if (packet.action === "conn_allow") {
      entry.allowed += 1;
      allowed += 1;
    }
    perPort.set(port, entry);
  }
  return {
    ip,
    total: packets.length,
    blocked,
    allowed,
    distinct_ports: perPort.size,
    ports: [...perPort.values()].sort((a, b) => b.count - a.count || a.port - b.port).slice(0, MAX_PORTS),
    connections: packets.slice(0, MAX_CONNECTIONS).map((packet) => ({ ts: packet.ts, port: packet.dst_port!, action: packet.action })),
    truncated: packets.length > MAX_CONNECTIONS,
  };
}

/** Run an answer as a request would: later, and failing as a rejected promise. */
function answer<T>(compute: () => T): Promise<T> {
  return new Promise((resolve, reject) => {
    try {
      resolve(compute());
    } catch (error) {
      reject(error);
    }
  });
}

export const demoApi: Api = {
  events: (params) => answer(() => events(params)),
  alerts: (params = {}) => answer(() => alerts(params)),
  timeline: (params) => answer(() => timeline(params)),
  stats: (params = {}) => answer(() => stats(params)),
  ports: (params) => answer(() => ports(params)),
  rules: () => answer(() => snapshot.rules),
  // The rules cannot change here, so running them again finds the same alerts.
  reloadRules: () =>
    answer(() => ({ ...snapshot.rules, alerts: { total: snapshot.alerts.length, created: 0, updated: 0, removed: 0 } })),
  follow: () => answer(() => ({ following: [] })),
  ingest: () => Promise.reject(new ApiError("Demoda log yüklenemez: örnek loglar sayfanın içine gömülüdür.")),
};
