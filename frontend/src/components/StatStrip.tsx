import type { Stats } from "../api";
import { formatCount, formatDateTime } from "../lib/time";
import { SEVERITY_LABEL, SEVERITY_ORDER, SeverityIcon } from "./Severity";

function Figure({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-32 grow border-t border-l border-rule px-4 py-3 lg:grow-0">
      <dt className="text-[12px] font-semibold text-ink-2">{label}</dt>
      <dd className="figures m-0 mt-0.5 text-[20px] leading-tight font-bold">{children}</dd>
    </div>
  );
}

/** The headline numbers of what has been loaded, as one row of figures. */
export function StatStrip({ stats }: { stats: Stats }) {
  const parsedShare = stats.events ? Math.round((stats.parsed / stats.events) * 100) : 0;
  const severities = SEVERITY_ORDER.filter((severity) => stats.alerts_by_severity[severity]);
  return (
    // Every figure draws a line above and to its left; the outermost of those are
    // pushed out of sight, so the lines sit between figures however the row wraps.
    <div className="overflow-hidden">
      <dl className="m-0 -mt-px -ml-px flex flex-wrap">
        <Figure label="Olay">{formatCount(stats.events)}</Figure>
        <Figure label="Ayrıştırılan">
          %{parsedShare}
          <span className="ml-2 text-[12px] font-normal text-ink-2">{formatCount(stats.unparsed)} satır tanınmadı</span>
        </Figure>
        <Figure label="Kaynak adres">{formatCount(stats.sources)}</Figure>
        <Figure label="Uyarı">
          {formatCount(stats.alerts)}
          {severities.map((severity) => (
            <span key={severity} className="ml-3 inline-flex items-center gap-1 text-[12px] font-normal text-ink-2">
              <SeverityIcon severity={severity} size={12} />
              {stats.alerts_by_severity[severity]} {SEVERITY_LABEL[severity].toLocaleLowerCase("tr")}
            </span>
          ))}
        </Figure>
        {stats.first_event && stats.last_event && (
          <Figure label="Kapsanan zaman (UTC)">
            <span className="text-[14px]">
              {formatDateTime(stats.first_event)} – {formatDateTime(stats.last_event)}
            </span>
          </Figure>
        )}
      </dl>
    </div>
  );
}
