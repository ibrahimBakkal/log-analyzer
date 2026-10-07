import { useNavigate } from "react-router";
import { type Alert, DEMO, type Stats } from "../api";
import { AlertPanel } from "../components/AlertPanel";
import { Notice, Panel } from "../components/Layout";
import { StatStrip } from "../components/StatStrip";
import { Timeline } from "../components/Timeline";
import { UploadForm } from "../components/UploadForm";
import { type Filters, filtersToSearch } from "../lib/filters";
import { chooseBucket, formatCount, rangeAround, toIso } from "../lib/time";
import { useAlerts, useStats, useTimeline } from "../queries";

const HOUR = 3_600_000;

/** The whole stored period, widened to full hours so the first and last bars are complete. */
export function fullRange(stats: Stats | undefined): { startMs: number; endMs: number } | null {
  if (!stats?.first_event || !stats.last_event) return null;
  return {
    startMs: Math.floor(Date.parse(stats.first_event) / HOUR) * HOUR,
    endMs: (Math.floor(Date.parse(stats.last_event) / HOUR) + 1) * HOUR,
  };
}

export function Dashboard() {
  const navigate = useNavigate();
  const stats = useStats();
  const alerts = useAlerts();
  const range = fullRange(stats.data);
  const bucket = range ? chooseBucket(range.startMs, range.endMs) : "1h";
  const timeline = useTimeline(
    range ? { bucket, start: toIso(range.startMs), end: toIso(range.endMs) } : {},
    Boolean(range),
  );

  const investigate = (filters: Filters) =>
    navigate({ pathname: "/inceleme", search: filtersToSearch(filters).toString() });
  const openAlert = (alert: Alert) =>
    investigate({ alert: alert.id, ...rangeAround(alert.first_seen, alert.last_seen) });

  if (stats.isError) {
    return (
      <Panel>
        <Notice tone="error">{stats.error.message}</Notice>
      </Panel>
    );
  }
  if (!stats.data) {
    return (
      <Panel>
        <Notice>Yükleniyor…</Notice>
      </Panel>
    );
  }
  if (stats.data.events === 0) {
    return (
      <Panel title="Henüz log yüklenmedi">
        <p className="m-0 max-w-[70ch] px-3 pt-3 text-ink-2">
          Bir sunucunun <code className="font-mono">auth.log</code> ya da <code className="font-mono">ufw.log</code>{" "}
          dosyasını yükle. Satırlar olaylara ayrılır, kurallar çalışır; zaman çizelgesi ve uyarılar bu sayfada belirir.
          Denemek için depodaki <code className="font-mono">samples/auth.log</code> ve{" "}
          <code className="font-mono">samples/ufw.log</code> dosyalarını yıl olarak 2026 vererek yükleyebilirsin.
        </p>
        <UploadForm />
      </Panel>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <Panel>
        <StatStrip stats={stats.data} />
      </Panel>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div className="flex min-w-0 flex-col gap-4">
          <Panel title="Zaman çizelgesi">
            {range && (
              <Timeline
                data={timeline.data}
                startMs={range.startMs}
                endMs={range.endMs}
                alerts={alerts.data?.items ?? []}
                onSelectRange={(start, end) => investigate({ start, end })}
                onSelectAlert={openAlert}
              />
            )}
          </Panel>

          <Panel title="En çok başarısız giriş denemesi yapan adresler">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="text-[12px] text-ink-2">
                  <th className="border-b border-rule px-3 py-1.5 font-semibold">Kaynak adres</th>
                  <th className="border-b border-rule px-3 py-1.5 text-right font-semibold">Başarısız giriş</th>
                  <th className="border-b border-rule px-3 py-1.5 text-right font-semibold">Tüm olaylar</th>
                </tr>
              </thead>
              <tbody>
                {stats.data.top_sources.map((source) => (
                  <tr key={source.src_ip} className="border-b border-rule last:border-b-0 hover:bg-accent-soft">
                    <td className="px-3 py-1.5">
                      <button
                        type="button"
                        className="cursor-pointer font-mono text-[12.5px] font-semibold text-accent"
                        onClick={() => investigate({ ip: source.src_ip })}
                      >
                        {source.src_ip}
                      </button>
                    </td>
                    <td className="figures px-3 py-1.5 text-right">{formatCount(source.failures)}</td>
                    <td className="figures px-3 py-1.5 text-right">{formatCount(source.events)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>

          {!DEMO && (
            <Panel title="Log yükle">
              <UploadForm />
            </Panel>
          )}
        </div>

        <Panel title={`Uyarılar${alerts.data ? ` (${formatCount(alerts.data.total)})` : ""}`} className="self-start">
          <AlertPanel alerts={alerts.data?.items} error={alerts.error} onSelect={openAlert} />
        </Panel>
      </div>
    </div>
  );
}
