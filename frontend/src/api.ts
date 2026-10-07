// Types and calls for the backend API. See the backend's /docs for the full contract.

export const API_URL: string = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000";

/** The demo build: no server, the sample logs come with the page (see src/demo/backend.ts). */
export const DEMO: boolean = import.meta.env.MODE === "demo";

export type Severity = "low" | "medium" | "high" | "critical";
export type Level = "info" | "warning";
export type BucketWidth = "1m" | "5m" | "1h";

/** Why an event is evidence for an alert; start/end index the message in code points. */
export interface Highlight {
  alert_id: number;
  rule_id: string;
  severity: Severity;
  start: number | null;
  end: number | null;
}

export interface LogEvent {
  id: number;
  ts: string;
  host: string | null;
  service: string | null;
  level: Level;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  user: string | null;
  action: string | null;
  message: string;
  raw: string;
  source_file: string;
  line_no: number;
  parsed: boolean;
  highlights: Highlight[];
}

export interface EventPage {
  items: LogEvent[];
  next_cursor: string | null;
}

export interface Alert {
  id: number;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  group_by: string;
  group_key: string;
  first_seen: string;
  last_seen: string;
  count: number;
  summary: string;
}

export interface AlertList {
  items: Alert[];
  total: number;
}

export interface TimelineBucket {
  ts: string;
  count: number;
  warnings: number;
}

export interface TimelineData {
  bucket_seconds: number;
  buckets: TimelineBucket[];
}

export interface Stats {
  events: number;
  parsed: number;
  unparsed: number;
  unparsed_ratio: number;
  first_event: string | null;
  last_event: string | null;
  sources: number;
  actions: Record<string, number>;
  alerts: number;
  alerts_by_severity: Partial<Record<Severity, number>>;
  top_sources: { src_ip: string; events: number; failures: number }[];
}

/** Field values an event must have for a rule to look at it. An empty list accepts anything. */
export interface EventFilter {
  action: string[];
  service: string[];
  host: string[];
  user: string[];
  level: Level[];
  dst_port: number[];
}

interface RuleCommon {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  enabled: boolean;
  group_by: string;
  cooldown_seconds: number;
  match: EventFilter;
}

export type Rule =
  | (RuleCommon & { type: "keyword"; keywords: string[]; regex: string | null })
  | (RuleCommon & { type: "threshold"; threshold: number; window_seconds: number })
  | (RuleCommon & { type: "sequence"; steps: { match: EventFilter; count: number }[]; within_seconds: number })
  | (RuleCommon & { type: "port_scan"; min_ports: number; window_seconds: number })
  | (RuleCommon & { type: "rare_port"; mode: "watchlist" | "allowlist"; ports: number[] });

export interface RuleList {
  rules: Rule[];
  errors: { file: string; message: string }[];
}

export interface RuleReload extends RuleList {
  alerts: { total: number; created: number; updated: number; removed: number };
}

export interface IngestReport {
  source_file: string;
  lines: number;
  parsed: number;
  unparsed: number;
  duplicates: number;
  conflicts: number;
  alerts: number;
}

export interface PortStats {
  port: number;
  count: number;
  blocked: number;
  allowed: number;
  first_seen: string;
  last_seen: string;
}

export interface PortConnection {
  ts: string;
  port: number;
  action: string | null;
}

/** The destination ports one source address tried. `ports` and `connections` are capped, the totals are not. */
export interface PortReport {
  ip: string;
  total: number;
  blocked: number;
  allowed: number;
  distinct_ports: number;
  ports: PortStats[];
  connections: PortConnection[];
  truncated: boolean;
}

/** A log file the server reads as it grows. */
export interface FollowedFile {
  path: string;
  /** "following", "waiting" (the file does not exist yet) or "error". */
  state: string;
  detail: string | null;
  /** The name the file's lines are stored under, once the first one has been read. */
  source: string | null;
  lines: number;
  read_at: string | null;
}

export interface FollowStatus {
  following: FollowedFile[];
}

export type QueryParams = Record<string, string | number | boolean | null | undefined>;

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

/** Build a query string, leaving out empty values. "+" in time offsets is encoded. */
export function toQuery(params: QueryParams): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(API_URL + path, init);
  } catch {
    throw new ApiError(`API'ye ulaşılamıyor (${API_URL}). Sunucu çalışıyor mu?`);
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const detail = typeof body?.detail === "string" ? body.detail : `İstek başarısız oldu (${response.status}).`;
    throw new ApiError(detail, response.status);
  }
  return response.json() as Promise<T>;
}

export interface Api {
  events(params: QueryParams): Promise<EventPage>;
  alerts(params?: QueryParams): Promise<AlertList>;
  timeline(params: QueryParams): Promise<TimelineData>;
  stats(params?: QueryParams): Promise<Stats>;
  ports(params: QueryParams): Promise<PortReport>;
  rules(): Promise<RuleList>;
  reloadRules(): Promise<RuleReload>;
  follow(): Promise<FollowStatus>;
  ingest(file: File, options: { year?: string; tz?: string }): Promise<IngestReport>;
}

const server: Api = {
  events: (params) => request<EventPage>(`/events${toQuery(params)}`),
  alerts: (params = {}) => request<AlertList>(`/alerts${toQuery(params)}`),
  timeline: (params) => request<TimelineData>(`/timeline${toQuery(params)}`),
  stats: (params = {}) => request<Stats>(`/stats${toQuery(params)}`),
  ports: (params) => request<PortReport>(`/ports${toQuery(params)}`),
  rules: () => request<RuleList>("/rules"),
  reloadRules: () => request<RuleReload>("/rules/reload", { method: "POST" }),
  follow: () => request<FollowStatus>("/follow"),
  ingest: (file, options) => {
    const form = new FormData();
    form.set("file", file);
    if (options.year) form.set("year", options.year);
    if (options.tz) form.set("tz", options.tz);
    return request<IngestReport>("/ingest", { method: "POST", body: form });
  },
};

/** The demo's stand-in for the server. Loaded on first use; no other build contains it. */
function demo(): Promise<Api> {
  return import("./demo/backend").then((module) => module.demoApi);
}

// Written out with the literal comparison, so that a regular build can tell at
// compile time that it never needs the demo and leaves it (and its data) out.
export const api: Api =
  import.meta.env.MODE === "demo"
    ? {
        events: (params) => demo().then((backend) => backend.events(params)),
        alerts: (params) => demo().then((backend) => backend.alerts(params)),
        timeline: (params) => demo().then((backend) => backend.timeline(params)),
        stats: (params) => demo().then((backend) => backend.stats(params)),
        ports: (params) => demo().then((backend) => backend.ports(params)),
        rules: () => demo().then((backend) => backend.rules()),
        reloadRules: () => demo().then((backend) => backend.reloadRules()),
        follow: () => demo().then((backend) => backend.follow()),
        ingest: (file, options) => demo().then((backend) => backend.ingest(file, options)),
      }
    : server;
