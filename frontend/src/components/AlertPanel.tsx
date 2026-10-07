import type { Alert } from "../api";
import { formatCount, formatDateTime, formatDuration } from "../lib/time";
import { Notice } from "./Layout";
import { SeverityBadge } from "./Severity";

interface Props {
  alerts: Alert[] | undefined;
  error?: Error | null;
  selectedId?: number;
  onSelect: (alert: Alert) => void;
}

/** Alerts, newest first. Choosing one takes the timeline and the log to its moment. */
export function AlertPanel({ alerts, error, selectedId, onSelect }: Props) {
  if (error) return <Notice tone="error">{error.message}</Notice>;
  if (!alerts) return <Notice>Uyarılar yükleniyor…</Notice>;
  if (alerts.length === 0) return <Notice>Uyarı yok: kurallar bu olaylarda şüpheli bir şey bulmadı.</Notice>;

  return (
    <ul className="m-0 list-none p-0">
      {alerts.map((alert) => {
        const duration = Date.parse(alert.last_seen) - Date.parse(alert.first_seen);
        const selected = alert.id === selectedId;
        return (
          <li key={alert.id} className="border-b border-rule last:border-b-0">
            <button
              type="button"
              onClick={() => onSelect(alert)}
              aria-pressed={selected}
              data-severity-edge={alert.severity}
              className={`block w-full cursor-pointer px-3 py-2 text-left hover:bg-accent-soft ${selected ? "bg-accent-soft" : ""}`}
            >
              <span className="flex items-center justify-between gap-2 text-[12px]">
                <SeverityBadge severity={alert.severity} />
                <span className="font-semibold text-ink-2">{alert.rule_id}</span>
              </span>
              <span className="mt-0.5 block font-semibold">{alert.summary}</span>
              <span className="figures mt-0.5 block text-[12px] text-ink-2">
                {formatDateTime(alert.first_seen)}
                {duration > 0 && `, ${formatDuration(duration)} sürdü`} · {formatCount(alert.count)} satır
              </span>
              {alert.rule_author && (
                <span className="mt-0.5 block text-[12px] text-ink-2">Kuralı yazan: {alert.rule_author}</span>
              )}
            </button>
          </li>
        );
      })}
    </ul>
  );
}
