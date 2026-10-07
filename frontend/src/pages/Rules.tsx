import type { Rule } from "../api";
import { Notice, Panel } from "../components/Layout";
import { SeverityBadge } from "../components/Severity";
import { formatCount } from "../lib/time";
import { useReloadRules, useRules } from "../queries";

const GROUP_LABEL: Record<string, string> = {
  src_ip: "kaynak adres",
  user: "kullanıcı",
  host: "makine",
  service: "program",
};

/** What a rule looks for, in a sentence. */
function condition(rule: Rule): string {
  const group = GROUP_LABEL[rule.group_by] ?? rule.group_by;
  if (rule.type === "threshold") {
    return `Aynı ${group} için ${rule.window_seconds} sn içinde ${rule.threshold} eşleşen olay`;
  }
  const texts = [...(rule.keywords ?? []), ...(rule.regex ? [`/${rule.regex}/`] : [])];
  return `Mesajında şunlardan biri geçen satır: ${texts.join(", ")}`;
}

export function Rules() {
  const rules = useRules();
  const reload = useReloadRules();

  return (
    <div className="flex flex-col gap-4">
      <Panel
        title="Kurallar"
        aside={
          <button type="button" className="button" onClick={() => reload.mutate()} disabled={reload.isPending}>
            {reload.isPending ? "Yükleniyor…" : "Kuralları yeniden yükle"}
          </button>
        }
      >
        <p className="m-0 max-w-[80ch] px-3 pt-3 text-ink-2">
          Kurallar sunucudaki <code className="font-mono">rules/</code> klasöründe duran YAML dosyalarıdır. Bir dosyayı
          değiştirdikten sonra yeniden yükle: kurallar saklanan tüm olaylar üzerinde baştan çalışır ve uyarılar güncellenir.
        </p>
        {reload.isError && <Notice tone="error">Yeniden yüklenemedi: {reload.error.message}</Notice>}
        {reload.data && (
          <p className="m-0 px-3 pt-2 font-semibold" aria-live="polite">
            Yeniden yüklendi: {formatCount(reload.data.alerts.total)} uyarı var ({formatCount(reload.data.alerts.created)}{" "}
            yeni, {formatCount(reload.data.alerts.removed)} kaldırıldı).
          </p>
        )}
        {rules.isError && <Notice tone="error">{rules.error.message}</Notice>}
        {rules.isPending && <Notice>Kurallar yükleniyor…</Notice>}
        {rules.data && rules.data.rules.length === 0 && (
          <Notice>Yüklü kural yok. rules/ klasörüne bir YAML dosyası ekleyip yeniden yükle.</Notice>
        )}
        {rules.data && rules.data.rules.length > 0 && (
          <div className="overflow-x-auto pt-3">
            <table className="w-full min-w-[720px] border-collapse text-left">
              <thead>
                <tr className="text-[12px] text-ink-2">
                  {["Kimlik", "Ad", "Önem", "Koşul", "Durum"].map((heading) => (
                    <th key={heading} className="border-y border-rule px-3 py-1.5 font-semibold">
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rules.data.rules.map((rule) => (
                  <tr key={rule.id} className="border-b border-rule align-top last:border-b-0">
                    <td className="px-3 py-2 font-mono text-[12.5px] font-semibold">{rule.id}</td>
                    <td className="px-3 py-2">
                      <div className="font-semibold">{rule.name}</div>
                      {rule.description && <div className="max-w-[60ch] text-[12px] text-ink-2">{rule.description}</div>}
                    </td>
                    <td className="px-3 py-2 text-[13px]">
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td className="px-3 py-2">{condition(rule)}</td>
                    <td className="px-3 py-2">{rule.enabled ? "Etkin" : "Kapalı"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {rules.data && rules.data.errors.length > 0 && (
        <Panel title={`Yüklenemeyen kural dosyaları (${rules.data.errors.length})`}>
          <ul className="m-0 list-none p-0">
            {rules.data.errors.map((error) => (
              <li key={error.file} data-severity-edge="critical" className="border-b border-rule px-3 py-2 last:border-b-0">
                <div className="font-mono text-[12.5px] font-semibold">{error.file}</div>
                <div className="text-ink-2">{error.message}</div>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}
