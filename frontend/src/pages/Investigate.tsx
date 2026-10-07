import { useMemo } from "react";
import { useSearchParams } from "react-router";
import type { Alert } from "../api";
import { AlertPanel } from "../components/AlertPanel";
import { FilterBar } from "../components/FilterBar";
import { Notice, Panel } from "../components/Layout";
import { LogTable } from "../components/LogTable";
import { PortView } from "../components/PortView";
import { SeverityBadge } from "../components/Severity";
import { Timeline } from "../components/Timeline";
import { type Filters, eventParams, filtersFromSearch, filtersToSearch } from "../lib/filters";
import { chooseBucket, formatCount, formatDateTime, rangeAround, toIso } from "../lib/time";
import { useAlerts, useRules, useStats, useTimeline } from "../queries";
import { fullRange } from "./Dashboard";

export function Investigate() {
  const [search, setSearch] = useSearchParams();
  const filters = useMemo(() => filtersFromSearch(search), [search]);
  const update = (patch: Partial<Filters>) => setSearch(filtersToSearch({ ...filters, ...patch }));

  const stats = useStats();
  const rules = useRules();
  const alerts = useAlerts();
  const whole = fullRange(stats.data);
  const startMs = filters.start ? Date.parse(filters.start) : whole?.startMs;
  const endMs = filters.end ? Date.parse(filters.end) : whole?.endMs;
  const ready = startMs !== undefined && endMs !== undefined && endMs > startMs;

  const params = eventParams(filters);
  const timeline = useTimeline(
    ready ? { ...params, start: toIso(startMs), end: toIso(endMs), bucket: chooseBucket(startMs, endMs) } : {},
    ready,
  );
  const selected = alerts.data?.items.find((alert) => alert.id === filters.alert);
  // The address whose ports are worth a look: the one filtered by, or the one the chosen alert is about.
  const focusIp = filters.ip ?? (selected?.group_by === "src_ip" ? selected.group_key : undefined);
  const selectAlert = (alert: Alert) =>
    update({ alert: alert.id, evidence: undefined, ...rangeAround(alert.first_seen, alert.last_seen) });

  if (stats.isError) {
    return (
      <Panel>
        <Notice tone="error">{stats.error.message}</Notice>
      </Panel>
    );
  }
  if (stats.data?.events === 0) {
    return (
      <Panel>
        <Notice>Henüz olay yok. Özet sayfasından bir log dosyası yükleyerek başla.</Notice>
      </Panel>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <Panel>
        <FilterBar filters={filters} rules={rules.data?.rules ?? []} onChange={update} onClear={() => setSearch(filtersToSearch({ newestFirst: filters.newestFirst }))}
        />
      </Panel>

      <Panel
        title="Zaman çizelgesi"
        aside={
          (filters.start || filters.end) && (
            <button
              type="button"
              className="button"
              onClick={() => update({ start: undefined, end: undefined, alert: undefined, evidence: undefined })}
            >
              Tüm aralığı göster
            </button>
          )
        }
      >
        {ready ? (
          <Timeline
            data={timeline.data}
            startMs={startMs}
            endMs={endMs}
            alerts={alerts.data?.items ?? []}
            selectedAlertId={filters.alert}
            onSelectRange={(start, end) => update({ start, end, alert: undefined, evidence: undefined })}
            onSelectAlert={selectAlert}
          />
        ) : (
          <Notice>{filters.start && filters.end ? "Bitiş, başlangıçtan sonra olmalı." : "Yükleniyor…"}</Notice>
        )}
      </Panel>

      {ready && focusIp && <PortView ip={focusIp} startMs={startMs} endMs={endMs} />}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_360px]">
        <Panel
          title="Log satırları"
          className="min-w-0"
          aside={
            <label className="flex cursor-pointer items-center gap-1.5 text-[13px]">
              <input
                type="checkbox"
                checked={Boolean(filters.newestFirst)}
                onChange={(event) => update({ newestFirst: event.target.checked || undefined })}
              />
              En yeni satırlar üstte
            </label>
          }
        >
          {selected && (
            <div
              data-severity-edge={selected.severity}
              className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-rule px-3 py-2"
            >
              <SeverityBadge severity={selected.severity} />
              <span className="font-semibold">{selected.summary}</span>
              <span className="figures text-[12px] text-ink-2">
                {selected.rule_id} · {formatDateTime(selected.first_seen)} · {formatCount(selected.count)} kanıt satırı
              </span>
              <label className="ml-auto flex cursor-pointer items-center gap-1.5 text-[13px]">
                <input
                  type="checkbox"
                  checked={Boolean(filters.evidence)}
                  onChange={(event) => update({ evidence: event.target.checked || undefined })}
                />
                Yalnızca kanıt satırları
              </label>
            </div>
          )}
          {ready && (
            <LogTable
              params={{ ...params, start: toIso(startMs), end: toIso(endMs), order: filters.newestFirst ? "desc" : undefined }}
              onFilterIp={(ip) => update({ ip })}
            />
          )}
        </Panel>

        <Panel title={`Uyarılar${alerts.data ? ` (${formatCount(alerts.data.total)})` : ""}`} className="self-start">
          <AlertPanel alerts={alerts.data?.items} error={alerts.error} selectedId={filters.alert} onSelect={selectAlert} />
        </Panel>
      </div>
    </div>
  );
}
