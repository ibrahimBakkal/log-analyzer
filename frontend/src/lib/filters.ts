import type { Level, QueryParams } from "../api";

/**
 * What the Investigate page is showing. The filters live in the page address,
 * so a view can be bookmarked, shared and reached with the back button.
 */
export interface Filters {
  /** Start of the time range (inclusive), ISO 8601 in UTC. */
  start?: string;
  /** End of the time range (exclusive), ISO 8601 in UTC. */
  end?: string;
  ip?: string;
  service?: string;
  /** Only evidence of this rule's alerts. */
  rule?: string;
  level?: Level;
  action?: string;
  /** The alert being looked at. */
  alert?: number;
  /** With `alert`: show only that alert's evidence instead of everything in the range. */
  evidence?: boolean;
  /** List the newest lines first: for watching a log that is being followed. */
  newestFirst?: boolean;
}

// The order in which filters appear in the address.
const TEXT_KEYS = ["start", "end", "ip", "service", "rule", "level", "action"] as const;

function asTime(value: string | null): string | undefined {
  if (!value) return undefined;
  const moment = new Date(value);
  return Number.isNaN(moment.getTime()) ? undefined : moment.toISOString().replace(".000Z", "Z");
}

/** Read filters from a query string. Unknown, empty and malformed values are ignored. */
export function filtersFromSearch(search: URLSearchParams): Filters {
  const filters: Filters = {};
  const start = asTime(search.get("start"));
  const end = asTime(search.get("end"));
  if (start) filters.start = start;
  if (end) filters.end = end;
  for (const key of ["ip", "service", "rule", "action"] as const) {
    const value = search.get(key)?.trim();
    if (value) filters[key] = value;
  }
  const level = search.get("level");
  if (level === "info" || level === "warning") filters.level = level;
  const alert = Number(search.get("alert"));
  if (Number.isInteger(alert) && alert > 0) {
    filters.alert = alert;
    if (search.get("evidence") === "1") filters.evidence = true;
  }
  if (search.get("order") === "desc") filters.newestFirst = true;
  return filters;
}

/** Write filters as a query string: fixed order, nothing for filters that are unset. */
export function filtersToSearch(filters: Filters): URLSearchParams {
  const search = new URLSearchParams();
  for (const key of TEXT_KEYS) {
    const value = filters[key]?.trim();
    if (value) search.set(key, value);
  }
  if (filters.alert) {
    search.set("alert", String(filters.alert));
    if (filters.evidence) search.set("evidence", "1");
  }
  if (filters.newestFirst) search.set("order", "desc");
  return search;
}

/** The API parameters that select the events these filters describe. */
export function eventParams(filters: Filters): QueryParams {
  return {
    start: filters.start,
    end: filters.end,
    ip: filters.ip,
    service: filters.service,
    rule_id: filters.rule,
    level: filters.level,
    action: filters.action,
    alert_id: filters.alert && filters.evidence ? filters.alert : undefined,
  };
}

/** True if anything besides the time range narrows the view. */
export function hasFieldFilters(filters: Filters): boolean {
  return Boolean(filters.ip || filters.service || filters.rule || filters.level || filters.action);
}
