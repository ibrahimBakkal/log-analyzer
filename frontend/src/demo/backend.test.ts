import { describe, expect, it } from "vitest";
import type { LogEvent, QueryParams } from "../api";
import { demoApi } from "./backend";
import recorded from "./cases.json?raw";

type Case =
  | { path: "/events"; params: QueryParams; ids: number[]; pages: number }
  | { path: "/alerts" | "/timeline" | "/stats" | "/ports" | "/rules"; params: QueryParams; response: unknown };

const cases = JSON.parse(recorded) as Case[];
const PAGE = 200;

function label(item: Case): string {
  const params = Object.entries(item.params).map(([key, value]) => `${key}=${value}`);
  return `${item.path}${params.length ? `?${params.join("&")}` : ""}`;
}

async function allEvents(params: QueryParams): Promise<{ events: LogEvent[]; pages: number }> {
  const events: LogEvent[] = [];
  let cursor: string | null | undefined;
  let pages = 0;
  do {
    const page = await demoApi.events({ ...params, limit: PAGE, cursor });
    events.push(...page.items);
    cursor = page.next_cursor;
    pages += 1;
  } while (cursor);
  return { events, pages };
}

describe("the demo answers as the real API does", () => {
  it("has a useful number of recorded answers to compare with", () => {
    expect(cases.length).toBeGreaterThan(40);
    expect(new Set(cases.map((item) => item.path))).toEqual(
      new Set(["/events", "/alerts", "/timeline", "/stats", "/ports", "/rules"]),
    );
  });

  for (const item of cases) {
    it(label(item), async () => {
      if (item.path === "/events") {
        const { events, pages } = await allEvents(item.params);
        expect(events.map((event) => event.id)).toEqual(item.ids);
        expect(pages).toBe(item.pages);
        return;
      }
      const call = {
        "/alerts": demoApi.alerts,
        "/timeline": demoApi.timeline,
        "/stats": demoApi.stats,
        "/ports": demoApi.ports,
        "/rules": demoApi.rules,
      }[item.path];
      expect(await call(item.params)).toEqual(item.response);
    });
  }
});

describe("the demo's own behaviour", () => {
  it("pages without repeating or skipping an event", async () => {
    const first = await demoApi.events({ limit: 3 });
    const second = await demoApi.events({ limit: 3, cursor: first.next_cursor });
    const both = await demoApi.events({ limit: 6 });
    expect([...first.items, ...second.items]).toEqual(both.items);
  });

  it("carries highlights on evidence lines", async () => {
    const { items } = await demoApi.events({ rule_id: "NET-001", limit: 1 });
    const marked = items[0].highlights.map((mark) => items[0].message.slice(mark.start!, mark.end!));
    expect(marked).toEqual(["198.51.100.150", String(items[0].dst_port)]);
  });

  it("reads a time without an offset as UTC", async () => {
    const withZone = await demoApi.events({ start: "2026-09-10T00:00:00Z", limit: 5 });
    const without = await demoApi.events({ start: "2026-09-10T00:00:00", limit: 5 });
    expect(without).toEqual(withZone);
  });

  it("refuses uploads with a message that says why", async () => {
    await expect(demoApi.ingest(new File([], "auth.log"), {})).rejects.toThrow("Demoda log yüklenemez");
  });

  it("finds the same alerts when the rules are run again", async () => {
    const reloaded = await demoApi.reloadRules();
    expect(reloaded.alerts).toEqual({ total: 8, created: 0, updated: 0, removed: 0 });
    expect(reloaded.rules).toHaveLength(5);
  });

  it("rejects a question it cannot answer instead of throwing", async () => {
    await expect(demoApi.ports({})).rejects.toThrow("IP adresi");
    await expect(demoApi.timeline({ bucket: "2h" })).rejects.toThrow("kova");
  });
});
