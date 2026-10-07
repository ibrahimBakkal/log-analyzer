// Destination ports: where they sit on an axis, what usually listens on them.

export const MAX_PORT = 65535;

/** Axis ticks for a logarithmic port axis: each decade and the highest port. */
export const PORT_TICKS = [1, 10, 100, 1000, 10000, MAX_PORT];

/**
 * Where a port sits on a logarithmic axis from 1 to 65535: 0 at the bottom,
 * 1 at the top. The well-known ports are few and low, so a linear axis would
 * press all of them against the bottom edge.
 */
export function portPosition(port: number): number {
  const clamped = Math.min(MAX_PORT, Math.max(1, port));
  return Math.log(clamped) / Math.log(MAX_PORT);
}

const SERVICES: Record<number, string> = {
  20: "FTP",
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  111: "RPC",
  123: "NTP",
  135: "MS RPC",
  139: "NetBIOS",
  143: "IMAP",
  161: "SNMP",
  389: "LDAP",
  443: "HTTPS",
  445: "SMB",
  465: "SMTPS",
  587: "SMTP",
  993: "IMAPS",
  995: "POP3S",
  1433: "MS SQL",
  1521: "Oracle",
  2049: "NFS",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  5900: "VNC",
  6379: "Redis",
  8080: "HTTP",
  8443: "HTTPS",
  9200: "Elasticsearch",
  27017: "MongoDB",
};

/** The service that usually listens on a port, if it is a well-known one. */
export function serviceName(port: number): string | undefined {
  return SERVICES[port];
}

/** "3389 (RDP)" for a well-known port, "40000" for any other. Ports are names, not amounts: no digit grouping. */
export function portLabel(port: number): string {
  const service = serviceName(port);
  return service ? `${port} (${service})` : String(port);
}

/**
 * The index of the point nearest to (x, y), or -1 if none lies within `reach`.
 * Of points at the same distance the later one wins: it is the one drawn on top.
 */
export function nearest(points: readonly { x: number; y: number }[], x: number, y: number, reach: number): number {
  let best = -1;
  let bestDistance = reach * reach;
  points.forEach((point, index) => {
    const distance = (point.x - x) ** 2 + (point.y - y) ** 2;
    if (distance <= bestDistance) {
      best = index;
      bestDistance = distance;
    }
  });
  return best;
}

export type Verdict = "allowed" | "blocked" | "unknown";

/** What the firewall did with a packet, from the event's action. */
export function verdictOf(action: string | null): Verdict {
  return action === "conn_allow" ? "allowed" : action === "conn_block" ? "blocked" : "unknown";
}

export interface Packet {
  ms: number;
  port: number;
  verdict: Verdict;
}

/** Packets drawn as one mark: same port, same verdict, and too close in time to tell apart. */
export interface Cluster {
  x: number;
  y: number;
  port: number;
  verdict: Verdict;
  count: number;
  firstMs: number;
  lastMs: number;
}

/**
 * Merge packets that would land on top of each other. Zoomed out, a minute of
 * packets to one port falls on a single pixel; one larger mark that knows how
 * many it stands for says more than fifty marks of which only the last shows.
 *
 * Packets must be in time order. A cluster sits at the average position of its members.
 */
export function clusterPackets(
  packets: readonly Packet[],
  xOf: (ms: number) => number,
  yOf: (port: number) => number,
  cell = 6,
): Cluster[] {
  const clusters = new Map<string, Cluster & { sum: number }>();
  for (const packet of packets) {
    const x = xOf(packet.ms);
    const key = `${packet.port}:${packet.verdict}:${Math.floor(x / cell)}`;
    const cluster = clusters.get(key);
    if (cluster) {
      cluster.count += 1;
      cluster.sum += x;
      cluster.x = cluster.sum / cluster.count;
      cluster.lastMs = packet.ms;
    } else {
      clusters.set(key, { x, y: yOf(packet.port), port: packet.port, verdict: packet.verdict, count: 1, firstMs: packet.ms, lastMs: packet.ms, sum: x });
    }
  }
  return [...clusters.values()].map(({ sum: _sum, ...cluster }) => cluster);
}

/** How large to draw a mark that stands for `count` packets: 4 px for one, growing slowly to 8 px for a hundred or more. */
export function markRadius(count: number): number {
  return 4 + 4 * Math.min(1, Math.log10(Math.max(1, count)) / 2);
}
