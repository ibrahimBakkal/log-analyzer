import { describe, expect, it } from "vitest";
import { type Filters, eventParams, filtersFromSearch, filtersToSearch, hasFieldFilters } from "./filters";

const FULL: Filters = {
  start: "2026-09-10T02:31:00Z",
  end: "2026-09-10T02:38:00Z",
  ip: "203.0.113.99",
  service: "sshd",
  rule: "SSH-001",
  level: "warning",
  action: "auth_fail",
  alert: 4,
  evidence: true,
  newestFirst: true,
};

function parse(query: string): Filters {
  return filtersFromSearch(new URLSearchParams(query));
}

describe("filters and the page address", () => {
  it("survive a round trip through the address unchanged", () => {
    expect(filtersFromSearch(filtersToSearch(FULL))).toEqual(FULL);
    expect(filtersFromSearch(filtersToSearch({}))).toEqual({});
    expect(filtersFromSearch(filtersToSearch({ ip: "2001:db8::7" }))).toEqual({ ip: "2001:db8::7" });
  });

  it("survive being pasted as the text a browser shows", () => {
    const address = filtersToSearch(FULL).toString();
    expect(parse(address)).toEqual(FULL);
  });

  it("are written in a fixed order, with nothing for unset filters", () => {
    const reordered: Filters = { alert: 4, level: "warning", ip: "203.0.113.99", start: FULL.start };
    expect(filtersToSearch(reordered).toString()).toBe(
      "start=2026-09-10T02%3A31%3A00Z&ip=203.0.113.99&level=warning&alert=4",
    );
    expect(filtersToSearch({}).toString()).toBe("");
    expect(filtersToSearch({ ip: "  ", service: "" }).toString()).toBe("");
  });

  it("keep a time offset intact when written and read back", () => {
    // "+" would turn into a space if it were not encoded.
    expect(parse("start=2026-09-10T05%3A31%3A00%2B03%3A00")).toEqual({ start: "2026-09-10T02:31:00Z" });
  });

  it("ignore values that make no sense", () => {
    expect(parse("start=yesterday&end=&level=loud&alert=abc&ip=%20")).toEqual({});
    expect(parse("alert=0")).toEqual({});
    expect(parse("alert=-3")).toEqual({});
    expect(parse("alert=2.5")).toEqual({});
  });

  it("ignore parameters they do not know", () => {
    expect(parse("ip=203.0.113.99&utm_source=mail&page=3")).toEqual({ ip: "203.0.113.99" });
  });

  it("only keep the evidence switch together with an alert", () => {
    expect(parse("evidence=1")).toEqual({});
    expect(parse("alert=4&evidence=1")).toEqual({ alert: 4, evidence: true });
    expect(parse("alert=4&evidence=yes")).toEqual({ alert: 4 });
    expect(filtersToSearch({ evidence: true }).toString()).toBe("");
  });

  it("trim surrounding spaces from typed values", () => {
    expect(parse("ip=%20203.0.113.99%20")).toEqual({ ip: "203.0.113.99" });
    expect(filtersToSearch({ service: " sshd " }).toString()).toBe("service=sshd");
  });
});

describe("eventParams", () => {
  it("names filters the way the API does", () => {
    expect(eventParams(FULL)).toEqual({
      start: FULL.start,
      end: FULL.end,
      ip: "203.0.113.99",
      service: "sshd",
      rule_id: "SSH-001",
      level: "warning",
      action: "auth_fail",
      alert_id: 4,
    });
  });

  it("selects an alert's evidence only when asked to", () => {
    expect(eventParams({ alert: 4 }).alert_id).toBeUndefined();
    expect(eventParams({ alert: 4, evidence: true }).alert_id).toBe(4);
  });
});

describe("hasFieldFilters", () => {
  it("is about filters other than the time range and the selected alert", () => {
    expect(hasFieldFilters({})).toBe(false);
    expect(hasFieldFilters({ start: FULL.start, end: FULL.end, alert: 4 })).toBe(false);
    expect(hasFieldFilters({ ip: "203.0.113.99" })).toBe(true);
    expect(hasFieldFilters({ rule: "KW-001" })).toBe(true);
  });
});

describe("the order of the log table", () => {
  it("is part of the address only when it is not the usual one", () => {
    expect(filtersToSearch({ newestFirst: true }).toString()).toBe("order=desc");
    expect(filtersToSearch({ newestFirst: false }).toString()).toBe("");
    expect(parse("order=desc")).toEqual({ newestFirst: true });
    expect(parse("order=asc")).toEqual({});
    expect(parse("order=sideways")).toEqual({});
  });

  it("is not a filter: it neither selects events nor counts as narrowing the view", () => {
    expect(eventParams({ newestFirst: true })).not.toHaveProperty("order");
    expect(hasFieldFilters({ newestFirst: true })).toBe(false);
  });
});
