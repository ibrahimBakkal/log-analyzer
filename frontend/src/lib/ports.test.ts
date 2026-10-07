import { describe, expect, it } from "vitest";
import { MAX_PORT, PORT_TICKS, type Packet, clusterPackets, markRadius, nearest, portLabel, portPosition, serviceName, verdictOf } from "./ports";

describe("portPosition", () => {
  it("runs from 0 at port 1 to 1 at the highest port", () => {
    expect(portPosition(1)).toBe(0);
    expect(portPosition(MAX_PORT)).toBe(1);
  });

  it("spaces the decades evenly", () => {
    const steps = [10, 100, 1000, 10000].map((port) => portPosition(port) - portPosition(port / 10));
    for (const step of steps) expect(step).toBeCloseTo(steps[0], 10);
  });

  it("gives the well-known ports more than half of the axis", () => {
    expect(portPosition(1023)).toBeGreaterThan(0.6);
    expect(portPosition(22)).toBeLessThan(portPosition(80));
    expect(portPosition(443)).toBeLessThan(portPosition(3389));
  });

  it("keeps impossible ports on the axis", () => {
    expect(portPosition(0)).toBe(0);
    expect(portPosition(-5)).toBe(0);
    expect(portPosition(70000)).toBe(1);
  });

  it("has ticks in ascending order that end at the highest port", () => {
    expect(PORT_TICKS).toEqual([...PORT_TICKS].sort((a, b) => a - b));
    expect(PORT_TICKS.at(-1)).toBe(MAX_PORT);
  });
});

describe("portLabel", () => {
  it("names the service of a well-known port", () => {
    expect(serviceName(22)).toBe("SSH");
    expect(portLabel(3389)).toBe("3389 (RDP)");
  });

  it("is the bare number for any other port, without digit grouping", () => {
    expect(serviceName(40000)).toBeUndefined();
    expect(portLabel(40000)).toBe("40000");
  });
});

describe("nearest", () => {
  const points = [
    { x: 10, y: 10 },
    { x: 50, y: 10 },
    { x: 50, y: 40 },
  ];

  it("finds the closest point", () => {
    expect(nearest(points, 12, 9, 14)).toBe(0);
    expect(nearest(points, 48, 30, 14)).toBe(2);
  });

  it("finds nothing beyond its reach", () => {
    expect(nearest(points, 30, 80, 14)).toBe(-1);
    expect(nearest([], 0, 0, 14)).toBe(-1);
  });

  it("counts a point exactly at the edge of its reach", () => {
    expect(nearest(points, 24, 10, 14)).toBe(0);
    expect(nearest(points, 24.1, 10, 14)).toBe(-1);
  });

  it("prefers the later of two points at the same place", () => {
    expect(nearest([...points, { x: 10, y: 10 }], 10, 10, 14)).toBe(3);
  });
});

describe("verdictOf", () => {
  it("reads the firewall's verdict from the event's action", () => {
    expect(verdictOf("conn_allow")).toBe("allowed");
    expect(verdictOf("conn_block")).toBe("blocked");
    expect(verdictOf(null)).toBe("unknown");
    expect(verdictOf("auth_fail")).toBe("unknown");
  });
});

describe("clusterPackets", () => {
  // One pixel per second, ports drawn at their own number.
  const cluster = (packets: Packet[], cell = 6) =>
    clusterPackets(packets, (ms) => ms / 1000, (port) => port, cell);
  const packet = (second: number, port = 22, verdict: Packet["verdict"] = "allowed"): Packet => ({ ms: second * 1000, port, verdict });

  it("keeps packets that are far enough apart as marks of their own", () => {
    const marks = cluster([packet(0), packet(10), packet(20)]);
    expect(marks.map((mark) => [mark.x, mark.count])).toEqual([
      [0, 1],
      [10, 1],
      [20, 1],
    ]);
  });

  it("merges packets to one port that fall on the same spot, and remembers how many and when", () => {
    const [mark, later] = cluster([packet(0), packet(2), packet(4), packet(30)]);
    expect(mark).toEqual({ x: 2, y: 22, port: 22, verdict: "allowed", count: 3, firstMs: 0, lastMs: 4000 });
    expect(later.count).toBe(1);
  });

  it("never merges different ports or different verdicts", () => {
    const marks = cluster([packet(0, 22), packet(0, 23), packet(1, 22, "blocked"), packet(1, 22)]);
    expect(marks.map((mark) => [mark.port, mark.verdict, mark.count])).toEqual([
      [22, "allowed", 2],
      [23, "allowed", 1],
      [22, "blocked", 1],
    ]);
  });

  it("accounts for every packet", () => {
    const packets = Array.from({ length: 500 }, (_, index) => packet(index * 0.7, index % 7, index % 3 ? "blocked" : "allowed"));
    expect(cluster(packets).reduce((sum, mark) => sum + mark.count, 0)).toBe(500);
  });

  it("merges more as the cells grow", () => {
    const packets = [packet(0), packet(5), packet(10), packet(15)];
    expect(cluster(packets, 1)).toHaveLength(4);
    expect(cluster(packets, 12)).toHaveLength(2);
    expect(cluster(packets, 100)).toHaveLength(1);
  });

  it("returns nothing for nothing", () => {
    expect(cluster([])).toEqual([]);
  });
});

describe("markRadius", () => {
  it("is 4 px for a single packet and grows slowly up to 8 px", () => {
    expect(markRadius(1)).toBe(4);
    expect(markRadius(10)).toBe(6);
    expect(markRadius(100)).toBe(8);
    expect(markRadius(100000)).toBe(8);
  });

  it("never shrinks below the size of one packet", () => {
    expect(markRadius(0)).toBe(4);
  });
});
