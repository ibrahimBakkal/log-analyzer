import { memo, useMemo, useState } from "react";
import type { PortReport, PortStats } from "../api";
import { type Cluster, PORT_TICKS, type Verdict, clusterPackets, markRadius, nearest, portLabel, portPosition, serviceName, verdictOf } from "../lib/ports";
import { formatCount, formatDateTime, formatDay, formatTime, toIso } from "../lib/time";
import { useWidth } from "../lib/useWidth";
import { usePorts } from "../queries";
import { Notice, Panel } from "./Layout";
import { TimeAxis } from "./TimeAxis";

const HEIGHT = 208;
// Left and right match the timeline's: drawn at the same width, the two time axes line up.
const MARGIN = { top: 24, right: 12, bottom: 34, left: 44 };
const REACH = 14; // how near the pointer has to be to a mark to read it, in pixels
const TOP_PORTS = 8;
const OPEN_PORTS = 12;

const VERDICT_TEXT: Record<Verdict, string> = {
  allowed: "geçirildi",
  blocked: "engellendi",
  unknown: "ne olduğu bilinmiyor",
};

/**
 * One packet, or several that fall on the same spot (a larger mark). Allowed
 * and blocked differ in shape as well as colour, and every mark sits on a ring
 * of the surface colour so that neighbours stay apart.
 */
function Mark({ x, y, verdict, count = 1, dimmed = false }: { x: number; y: number; verdict: Verdict; count?: number; dimmed?: boolean }) {
  const opacity = dimmed ? 0.16 : 1;
  const radius = markRadius(count);
  if (verdict === "blocked") {
    const arm = radius - 0.5;
    const cross = `M${x - arm},${y - arm}L${x + arm},${y + arm}M${x - arm},${y + arm}L${x + arm},${y - arm}`;
    return (
      <g opacity={opacity} strokeLinecap="round" fill="none">
        <path d={cross} stroke="var(--surface)" strokeWidth={radius / 2 + 3.5} />
        <path d={cross} stroke="var(--series-suspicious)" strokeWidth={radius / 2} />
      </g>
    );
  }
  if (verdict === "allowed") {
    return <circle cx={x} cy={y} r={radius} opacity={opacity} fill="var(--series-events)" stroke="var(--surface)" strokeWidth={4} paintOrder="stroke" />;
  }
  return (
    <g opacity={opacity}>
      <circle cx={x} cy={y} r={radius + 1.5} fill="var(--surface)" />
      <circle cx={x} cy={y} r={radius - 0.5} fill="none" stroke="var(--ink-3)" strokeWidth={1.5} />
    </g>
  );
}

function Glyph({ verdict }: { verdict: Verdict }) {
  return (
    <svg width={12} height={12} viewBox="0 0 12 12" aria-hidden="true" className="shrink-0">
      <Mark x={6} y={6} verdict={verdict} />
    </svg>
  );
}

/** All marks at once. Kept apart from the hover state so that moving the pointer does not redraw them. */
const Marks = memo(function Marks({ clusters, onlyPort }: { clusters: Cluster[]; onlyPort: number | null }) {
  return (
    <>
      {clusters.map((cluster, index) => (
        <Mark
          key={index}
          x={cluster.x}
          y={cluster.y}
          verdict={cluster.verdict}
          count={cluster.count}
          dimmed={onlyPort !== null && cluster.port !== onlyPort}
        />
      ))}
    </>
  );
});

/** "9 Eyl 03:12:38" for one moment, "9 Eyl 03:12:38 – 03:14:03" for a stretch within a day. */
function formatSpan(firstMs: number, lastMs: number): string {
  if (firstMs === lastMs) return formatDateTime(firstMs);
  const sameDay = formatDay(firstMs) === formatDay(lastMs);
  return `${formatDateTime(firstMs)} – ${sameDay ? formatTime(lastMs) : formatDateTime(lastMs)}`;
}

/** When each port was tried: time runs across, the port number up, one mark per packet. */
function PortScatter({ report, startMs, endMs, onlyPort }: { report: PortReport; startMs: number; endMs: number; onlyPort: number | null }) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState(-1);

  const plotWidth = Math.max(0, width - MARGIN.left - MARGIN.right);
  const plotHeight = HEIGHT - MARGIN.top - MARGIN.bottom;
  const baseline = MARGIN.top + plotHeight;
  const y = (port: number) => baseline - portPosition(port) * plotHeight;

  const clusters = useMemo(() => {
    const span = Math.max(endMs - startMs, 1);
    const packets = report.connections
      .map((connection) => ({ ms: Date.parse(connection.ts), port: connection.port, verdict: verdictOf(connection.action) }))
      .filter((packet) => packet.ms >= startMs && packet.ms <= endMs);
    return clusterPackets(
      packets,
      (ms) => MARGIN.left + ((ms - startMs) / span) * plotWidth,
      (port) => baseline - portPosition(port) * plotHeight,
    );
  }, [report.connections, startMs, endMs, plotWidth, plotHeight, baseline]);

  const hovered = hover >= 0 ? clusters[hover] : undefined;

  return (
    <div ref={ref} className="relative min-w-0 select-none">
      {width > 0 && (
        <svg
          width={width}
          height={HEIGHT}
          role="img"
          aria-label={`${report.ip} adresinin denediği hedef portlar: ${formatCount(report.distinct_ports)} farklı port, ${formatCount(report.total)} paket`}
        >
          <text x={2} y={11} className="fill-ink-3 text-[11px]">
            Hedef port
          </text>
          {PORT_TICKS.map((port) => (
            <g key={port}>
              <line x1={MARGIN.left} x2={MARGIN.left + plotWidth} y1={y(port)} y2={y(port)} stroke={port === 1 ? "var(--rule-strong)" : "var(--rule)"} />
              <text x={MARGIN.left - 8} y={y(port)} dy="0.32em" textAnchor="end" className="figures fill-ink-3 text-[11px]">
                {port}
              </text>
            </g>
          ))}
          <TimeAxis startMs={startMs} endMs={endMs} left={MARGIN.left} plotWidth={plotWidth} baseline={baseline} />

          <Marks clusters={clusters} onlyPort={onlyPort} />

          {hovered && (
            <g>
              <line x1={hovered.x} x2={hovered.x} y1={MARGIN.top} y2={baseline} stroke="var(--ink-3)" strokeDasharray="2 3" />
              <circle cx={hovered.x} cy={hovered.y} r={markRadius(hovered.count) + 4} fill="none" stroke="var(--ink)" strokeWidth={1.5} />
            </g>
          )}

          {/* Pointer surface: reads the mark nearest to the pointer. */}
          <rect
            x={MARGIN.left - REACH}
            y={MARGIN.top - REACH}
            width={plotWidth + 2 * REACH}
            height={plotHeight + 2 * REACH}
            fill="transparent"
            onPointerMove={(event) => {
              const box = event.currentTarget.ownerSVGElement!.getBoundingClientRect();
              const index = nearest(clusters, event.clientX - box.left, event.clientY - box.top, REACH);
              if (index !== hover) setHover(index);
            }}
            onPointerLeave={() => setHover(-1)}
          />

          {clusters.length === 0 && (
            <text x={MARGIN.left + plotWidth / 2} y={MARGIN.top + plotHeight / 2} textAnchor="middle" className="fill-ink-2 text-[13px]">
              Bu aralıkta paket yok.
            </text>
          )}
        </svg>
      )}

      {hovered && (
        <div
          className="pointer-events-none absolute z-10 w-max rounded border border-rule-strong bg-surface px-2.5 py-1.5 text-[12px] shadow-sm"
          style={{
            top: Math.max(0, Math.min(hovered.y - 22, HEIGHT - 74)),
            ...(hovered.x > width / 2 ? { right: width - hovered.x + 16 } : { left: hovered.x + 16 }),
          }}
        >
          <div className="figures mb-1 text-ink-2">{formatSpan(hovered.firstMs, hovered.lastMs)}</div>
          <div className="flex items-center gap-1.5">
            <Glyph verdict={hovered.verdict} />
            <strong className="font-mono">{hovered.port}</strong>
            {serviceName(hovered.port) && <span>{serviceName(hovered.port)}</span>}
            <span className="text-ink-2">
              {hovered.count > 1 && `${formatCount(hovered.count)} paket, `}
              {VERDICT_TEXT[hovered.verdict]}
            </span>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 pb-2 text-[12px] text-ink-2">
        <span className="inline-flex items-center gap-1.5">
          <Glyph verdict="allowed" />
          Geçirilen paket
        </span>
        <span className="inline-flex items-center gap-1.5">
          <Glyph verdict="blocked" />
          Engellenen paket
        </span>
        {clusters.some((cluster) => cluster.verdict === "unknown") && (
          <span className="inline-flex items-center gap-1.5">
            <Glyph verdict="unknown" />
            Ne olduğu bilinmeyen paket
          </span>
        )}
        <span>Port ekseni logaritmik. Büyük işaret: aynı yere düşen birden çok paket.</span>
      </div>
    </div>
  );
}

/** One port as a bar: allowed packets from the baseline, blocked ones after them. */
function PortBar({ port, top, active, onHover }: { port: PortStats; top: number; active: boolean; onHover: (port: number | null) => void }) {
  const segments = [
    { key: "allowed", value: port.allowed, color: "var(--series-events)" },
    { key: "blocked", value: port.blocked, color: "var(--series-suspicious)" },
    { key: "other", value: port.count - port.allowed - port.blocked, color: "var(--ink-3)" },
  ].filter((segment) => segment.value > 0);
  const detail =
    `${portLabel(port.port)}: ${formatCount(port.allowed)} geçirilen, ${formatCount(port.blocked)} engellenen paket. ` +
    `İlk ${formatDateTime(port.first_seen)}, son ${formatDateTime(port.last_seen)}.`;

  return (
    <li
      tabIndex={0}
      title={detail}
      onMouseEnter={() => onHover(port.port)}
      onMouseLeave={() => onHover(null)}
      onFocus={() => onHover(port.port)}
      onBlur={() => onHover(null)}
      className={`grid break-inside-avoid grid-cols-[116px_minmax(0,1fr)_40px] items-center gap-2 rounded-sm px-1 py-[3px] ${active ? "bg-accent-soft" : ""}`}
    >
      <span className="truncate">
        <span className="font-mono text-[12.5px] font-semibold">{port.port}</span>
        {serviceName(port.port) && <span className="text-[12px] text-ink-2"> {serviceName(port.port)}</span>}
      </span>
      <span className="block" style={{ width: `${(port.count / top) * 100}%`, minWidth: 4 }}>
        <span className="flex h-2 gap-[2px]">
          {segments.map((segment, index) => (
            <span
              key={segment.key}
              className={`min-w-[2px] basis-0 ${index === segments.length - 1 ? "rounded-r-[4px]" : ""}`}
              style={{ flexGrow: segment.value, background: segment.color }}
            />
          ))}
        </span>
      </span>
      <span className="figures text-right text-[12.5px] font-semibold">{formatCount(port.count)}</span>
    </li>
  );
}

/** The busiest ports as bars, and the ports the firewall let this address reach. */
function PortSummary({ report, onlyPort, onHover }: { report: PortReport; onlyPort: number | null; onHover: (port: number | null) => void }) {
  const shown = report.ports.slice(0, TOP_PORTS);
  const top = Math.max(1, ...shown.map((port) => port.count));
  // Bars of equal length rank nothing: a scan that tries each port once is better said in words.
  const flat = top === 1 && report.distinct_ports > 3;
  const rest = report.distinct_ports - shown.length;

  const open = report.ports.filter((port) => port.allowed > 0).sort((a, b) => a.port - b.port);
  const listed = open.reduce((sum, port) => sum + port.allowed, 0);
  const more = Math.max(0, open.length - OPEN_PORTS);

  return (
    <div className="grid grid-cols-1 gap-x-8 gap-y-2 border-t border-rule px-3 py-2 md:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
      <div className="min-w-0">
        <h3 className="m-0 text-[12px] font-semibold text-ink-2">En çok paket alan portlar</h3>
        {flat ? (
          <p className="m-0 mt-1">Hiçbir porta birden çok paket gelmedi.</p>
        ) : (
          <>
            <ol className="m-0 mt-1 list-none columns-[260px] gap-x-8 p-0">
              {shown.map((port) => (
                <PortBar key={port.port} port={port} top={top} active={onlyPort === port.port} onHover={onHover} />
              ))}
            </ol>
            {rest > 0 && <p className="m-0 mt-1 text-[12px] text-ink-2">ve {formatCount(rest)} port daha</p>}
          </>
        )}
      </div>
      <div className="min-w-0">
        <h3 className="m-0 text-[12px] font-semibold text-ink-2">Güvenlik duvarının geçirdiği portlar</h3>
        {open.length === 0 ? (
          <p className="m-0 mt-1">Yok: bu adresin bütün paketleri engellendi.</p>
        ) : (
          <p className="m-0 mt-1">
            {open.slice(0, OPEN_PORTS).map((port, index) => (
              <span
                key={port.port}
                tabIndex={0}
                onMouseEnter={() => onHover(port.port)}
                onMouseLeave={() => onHover(null)}
                onFocus={() => onHover(port.port)}
                onBlur={() => onHover(null)}
                className={`rounded-sm ${onlyPort === port.port ? "bg-accent-soft" : ""}`}
              >
                {index > 0 && ", "}
                <span className="font-mono text-[12.5px] font-semibold">{port.port}</span>
                {serviceName(port.port) && <span className="text-ink-2"> {serviceName(port.port)}</span>}
              </span>
            ))}
            {(more > 0 || listed < report.allowed) && <span className="text-ink-2"> ve başka portlar</span>}
          </p>
        )}
      </div>
    </div>
  );
}

function Figure({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="px-4 py-2">
      <dt className="text-[12px] font-semibold text-ink-2">{label}</dt>
      <dd className="figures m-0 text-[17px] leading-tight font-bold">{children}</dd>
    </div>
  );
}

/**
 * The destination ports one source address tried in a time range, from the
 * firewall's packet log. Draws nothing for an address the firewall never logged.
 */
export function PortView({ ip, startMs, endMs }: { ip: string; startMs: number; endMs: number }) {
  const ports = usePorts({ ip, start: toIso(startMs), end: toIso(endMs) });
  const [onlyPort, setOnlyPort] = useState<number | null>(null);
  const report = ports.data;

  if (ports.isError) {
    return (
      <Panel title={`Hedef portlar: ${ip}`}>
        <Notice tone="error">{ports.error.message}</Notice>
      </Panel>
    );
  }
  // While another address loads, the previous one's report is still at hand: not this one's.
  if (!report || report.ip !== ip || report.total === 0) return null;

  return (
    <Panel title={`Hedef portlar: ${ip}`}>
      <dl className="m-0 flex flex-wrap divide-x divide-rule border-b border-rule">
        <Figure label="Farklı port">{formatCount(report.distinct_ports)}</Figure>
        <Figure label="Paket">{formatCount(report.total)}</Figure>
        <Figure label="Engellenen">{formatCount(report.blocked)}</Figure>
        <Figure label="Geçirilen">{formatCount(report.allowed)}</Figure>
      </dl>
      <div className="pt-2">
        <PortScatter report={report} startMs={startMs} endMs={endMs} onlyPort={onlyPort} />
        {report.truncated && (
          <p className="m-0 px-3 pb-2 text-[12px] text-ink-2">
            Yalnızca ilk {formatCount(report.connections.length)} paket çizildi. Devamını görmek için zaman aralığını daralt.
          </p>
        )}
      </div>
      <PortSummary report={report} onlyPort={onlyPort} onHover={setOnlyPort} />
    </Panel>
  );
}
