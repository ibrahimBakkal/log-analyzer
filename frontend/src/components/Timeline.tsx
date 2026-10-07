import { useState } from "react";
import type { Alert, TimelineData } from "../api";
import { formatCount, formatDateTime, formatDay, formatShortTime, niceCeiling, toIso } from "../lib/time";
import { useWidth } from "../lib/useWidth";
import { SEVERITY_LABEL } from "./Severity";
import { TimeAxis } from "./TimeAxis";

const HEIGHT = 176;
const MARGIN = { top: 22, right: 12, bottom: 34, left: 44 };
const MAX_BAR = 24; // bars never fill their slot: the leftover is air
const GAP = 2; // surface-coloured gap between touching marks
const RADIUS = 4;

interface Props {
  data: TimelineData | undefined;
  startMs: number;
  endMs: number;
  alerts: Alert[];
  selectedAlertId?: number;
  /** Called with an ISO range when a stretch of the chart is dragged over. */
  onSelectRange: (start: string, end: string) => void;
  onSelectAlert: (alert: Alert) => void;
}

/** A column segment with a rounded top (the data end) and a square bottom. */
function roundedTop(x: number, y: number, width: number, height: number): string {
  const r = Math.min(RADIUS, width / 2, height);
  return `M${x},${y + height}V${y + r}Q${x},${y} ${x + r},${y}H${x + width - r}Q${x + width},${y} ${x + width},${y + r}V${y + height}Z`;
}

/**
 * Event density over time as stacked columns: ordinary events below, suspicious
 * (warning-level) ones on top. Alerts run along the top edge for as long as they
 * lasted. Dragging across the chart selects that stretch of time.
 */
export function Timeline({ data, startMs, endMs, alerts, selectedAlertId, onSelectRange, onSelectAlert }: Props) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState<number | null>(null);
  const [drag, setDrag] = useState<{ from: number; to: number } | null>(null);

  const plotWidth = Math.max(0, width - MARGIN.left - MARGIN.right);
  const plotHeight = HEIGHT - MARGIN.top - MARGIN.bottom;
  const baseline = MARGIN.top + plotHeight;
  const span = Math.max(endMs - startMs, 1);
  const x = (ms: number) => MARGIN.left + ((ms - startMs) / span) * plotWidth;
  const timeAt = (px: number) => startMs + ((px - MARGIN.left) / Math.max(plotWidth, 1)) * span;
  const clampX = (px: number) => Math.min(MARGIN.left + plotWidth, Math.max(MARGIN.left, px));

  const bucketMs = (data?.bucket_seconds ?? 60) * 1000;
  const buckets = (data?.buckets ?? [])
    .map((bucket) => ({ ...bucket, ms: Date.parse(bucket.ts) }))
    .filter((bucket) => bucket.ms + bucketMs > startMs && bucket.ms < endMs);
  const top = niceCeiling(Math.max(1, ...buckets.map((bucket) => bucket.count)));
  const y = (count: number) => baseline - (count / top) * plotHeight;
  const slot = (bucketMs / span) * plotWidth;
  const barWidth = Math.max(1, Math.min(MAX_BAR, slot - GAP));
  const hovered = hover === null ? undefined : buckets.find((bucket) => bucket.ms === hover);
  const visibleAlerts = alerts.filter(
    (alert) => Date.parse(alert.last_seen) >= startMs && Date.parse(alert.first_seen) < endMs,
  );

  function pointerX(event: React.PointerEvent<SVGRectElement>): number {
    const box = event.currentTarget.ownerSVGElement!.getBoundingClientRect();
    return clampX(event.clientX - box.left);
  }

  function finishDrag() {
    if (drag && Math.abs(drag.to - drag.from) >= 5) {
      const [from, to] = [Math.min(drag.from, drag.to), Math.max(drag.from, drag.to)];
      onSelectRange(toIso(timeAt(from)), toIso(timeAt(to)));
    }
    setDrag(null);
  }

  const total = buckets.reduce((sum, bucket) => sum + bucket.count, 0);

  return (
    <div ref={ref} className="relative select-none">
      {width > 0 && (
        <svg
          width={width}
          height={HEIGHT}
          role="img"
          aria-label={`Zaman çizelgesi: ${formatDateTime(startMs)} ile ${formatDateTime(endMs)} arasında ${formatCount(total)} olay`}
        >
          {/* Count axis: hairlines and round numbers. */}
          {[0, top / 2, top].map((value) =>
            Number.isInteger(value) ? (
              <g key={value}>
                <line x1={MARGIN.left} x2={MARGIN.left + plotWidth} y1={y(value)} y2={y(value)} stroke={value === 0 ? "var(--rule-strong)" : "var(--rule)"} />
                <text x={MARGIN.left - 8} y={y(value)} dy="0.32em" textAnchor="end" className="figures fill-ink-3 text-[11px]">
                  {formatCount(value)}
                </text>
              </g>
            ) : null,
          )}

          <TimeAxis startMs={startMs} endMs={endMs} left={MARGIN.left} plotWidth={plotWidth} baseline={baseline} />

          {hovered && !drag && (
            <rect x={x(hovered.ms)} y={MARGIN.top} width={Math.max(slot, 1)} height={plotHeight} fill="var(--ink)" opacity={0.07} />
          )}

          {buckets.map((bucket) => {
            const left = x(bucket.ms) + (slot - barWidth) / 2;
            const ordinary = bucket.count - bucket.warnings;
            const ordinaryTop = y(ordinary);
            const fullTop = y(bucket.count);
            // The gap between the two segments is taken from the upper one.
            const suspiciousHeight = ordinaryTop - fullTop - (ordinary > 0 && ordinaryTop - fullTop > GAP + 1 ? GAP : 0);
            return (
              <g key={bucket.ms}>
                {ordinary > 0 &&
                  (bucket.warnings > 0 ? (
                    <rect x={left} y={ordinaryTop} width={barWidth} height={baseline - ordinaryTop} fill="var(--series-events)" />
                  ) : (
                    <path d={roundedTop(left, ordinaryTop, barWidth, baseline - ordinaryTop)} fill="var(--series-events)" />
                  ))}
                {bucket.warnings > 0 && suspiciousHeight > 0 && (
                  <path d={roundedTop(left, fullTop, barWidth, suspiciousHeight)} fill="var(--series-suspicious)" />
                )}
              </g>
            );
          })}

          {drag && (
            <rect
              x={Math.min(drag.from, drag.to)}
              y={MARGIN.top}
              width={Math.abs(drag.to - drag.from)}
              height={plotHeight}
              fill="var(--accent)"
              opacity={0.16}
            />
          )}

          {/* Pointer surface: hovering reads a column, dragging selects a time range. */}
          <rect
            x={MARGIN.left}
            y={MARGIN.top}
            width={plotWidth}
            height={plotHeight}
            fill="transparent"
            className="cursor-crosshair"
            onPointerDown={(event) => {
              event.currentTarget.setPointerCapture(event.pointerId);
              setDrag({ from: pointerX(event), to: pointerX(event) });
            }}
            onPointerMove={(event) => {
              const px = pointerX(event);
              if (drag) setDrag({ from: drag.from, to: px });
              setHover(Math.floor(timeAt(px) / bucketMs) * bucketMs);
            }}
            onPointerUp={finishDrag}
            onPointerCancel={() => setDrag(null)}
            onPointerLeave={() => setHover(null)}
          />

          {/* Alerts, drawn last so they stay clickable above the pointer surface. */}
          {visibleAlerts.map((alert) => {
            const from = clampX(x(Date.parse(alert.first_seen)));
            const to = clampX(x(Date.parse(alert.last_seen)));
            const selected = alert.id === selectedAlertId;
            return (
              <rect
                key={alert.id}
                x={Math.min(from, MARGIN.left + plotWidth - 10)}
                y={selected ? 4 : 6}
                width={Math.max(10, to - from)}
                height={selected ? 10 : 6}
                rx={selected ? 5 : 3}
                fill={`var(--sev-${alert.severity})`}
                stroke={selected ? "var(--ink)" : "var(--surface)"}
                strokeWidth={selected ? 2 : 1}
                role="button"
                tabIndex={0}
                className="cursor-pointer"
                onClick={() => onSelectAlert(alert)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelectAlert(alert);
                  }
                }}
              >
                <title>{`${SEVERITY_LABEL[alert.severity]} · ${alert.rule_id}: ${alert.summary}`}</title>
              </rect>
            );
          })}

          {data && buckets.length === 0 && (
            <text x={MARGIN.left + plotWidth / 2} y={MARGIN.top + plotHeight / 2} textAnchor="middle" className="fill-ink-2 text-[13px]">
              Bu aralıkta olay yok.
            </text>
          )}
        </svg>
      )}

      {hovered && !drag && (
        <div
          className="pointer-events-none absolute z-10 w-max rounded border border-rule-strong bg-surface px-2.5 py-1.5 text-[12px] shadow-sm"
          style={{
            top: MARGIN.top,
            ...(x(hovered.ms) > width / 2 ? { right: width - x(hovered.ms) + 8 } : { left: x(hovered.ms) + Math.max(slot, 1) + 8 }),
          }}
        >
          <div className="figures mb-1 text-ink-2">
            {bucketMs >= 86_400_000 ? formatDay(hovered.ms) : `${formatDateTime(hovered.ms)} – ${formatShortTime(hovered.ms + bucketMs)}`}
          </div>
          <TooltipRow color="var(--series-suspicious)" value={hovered.warnings} label="şüpheli olay" />
          <TooltipRow color="var(--series-events)" value={hovered.count - hovered.warnings} label="diğer olay" />
        </div>
      )}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 pb-2 text-[12px] text-ink-2">
        <LegendKey color="var(--series-events)" label="Olaylar" />
        <LegendKey color="var(--series-suspicious)" label="Şüpheli olaylar (başarısız giriş, geçersiz kullanıcı, reddedilen sudo, engellenen paket)" />
        <span>Üst kenardaki işaretler: uyarılar. Aralık seçmek için çizelgede sürükle.</span>
      </div>
    </div>
  );
}

function LegendKey({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="inline-block h-2.5 w-2.5 rounded-[2px]" style={{ background: color }} />
      {label}
    </span>
  );
}

function TooltipRow({ color, value, label }: { color: string; value: number; label: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="inline-block h-2.5 w-2.5 rounded-[2px]" style={{ background: color }} />
      <strong className="figures">{formatCount(value)}</strong>
      <span className="text-ink-2">{label}</span>
    </div>
  );
}
