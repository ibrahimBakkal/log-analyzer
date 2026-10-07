import type { ReactNode } from "react";
import { DEMO, type Rule } from "../api";
import { Notice, Panel } from "../components/Layout";
import { SeverityBadge } from "../components/Severity";
import { describeCondition, describeMatch, shortLink, splitLinks } from "../lib/rules";
import { formatCount } from "../lib/time";
import { useReloadRules, useRules } from "../queries";

export function Rules() {
  const rules = useRules();
  const reload = useReloadRules();

  return (
    <div className="flex flex-col gap-4">
      <Panel
        title="Kurallar"
        aside={
          !DEMO && (
            <button type="button" className="button" onClick={() => reload.mutate()} disabled={reload.isPending}>
              {reload.isPending ? "Yükleniyor…" : "Kuralları yeniden yükle"}
            </button>
          )
        }
      >
        <p className="m-0 max-w-[80ch] px-3 pt-3 text-ink-2">
          Kurallar sunucudaki <code className="font-mono">rules/</code> klasöründe duran YAML dosyalarıdır.{" "}
          {DEMO
            ? "Demoda değiştirilemezler; örnek loglardaki uyarıları bu beş kural üretti."
            : "Bir dosyayı değiştirdikten sonra yeniden yükle: kurallar saklanan tüm olaylar üzerinde baştan çalışır ve uyarılar güncellenir."}
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
                    <td className="px-3 py-2 font-mono text-[12.5px] font-semibold whitespace-nowrap">{rule.id}</td>
                    <td className="px-3 py-2">
                      <div className="font-semibold">{rule.name}</div>
                      {rule.description && <div className="max-w-[60ch] text-[12px] text-ink-2">{rule.description}</div>}
                      <Origin rule={rule} />
                    </td>
                    <td className="px-3 py-2 text-[13px]">
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td className="px-3 py-2">
                      <div>{describeCondition(rule)}</div>
                      {describeMatch(rule.match) && (
                        <div className="text-[12px] text-ink-2">Bakılan olaylar: {describeMatch(rule.match)}</div>
                      )}
                    </td>
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

/** Who wrote a rule and under what terms, for rules that say so. */
function Origin({ rule }: { rule: Rule }) {
  const links = rule.source ? [rule.source, ...rule.references] : rule.references;
  if (!rule.author && !rule.license && links.length === 0 && rule.tags.length === 0 && rule.false_positives.length === 0) {
    return null;
  }
  return (
    <dl className="mt-1.5 grid max-w-[60ch] grid-cols-[max-content_1fr] gap-x-2 text-[12px] text-ink-2">
      {rule.author && <Fact name="Yazar">{rule.author}</Fact>}
      {rule.license && (
        <Fact name="Lisans">
          {splitLinks(rule.license).map((piece, index) =>
            piece.href ? <Outside key={index} href={piece.href} /> : <span key={index}>{piece.text}</span>,
          )}
        </Fact>
      )}
      {links.length > 0 && (
        <Fact name={rule.source ? "Kaynak" : "Okuma"}>
          {links.map((link) => (
            <div key={link}>
              <Outside href={link} />
            </div>
          ))}
        </Fact>
      )}
      {rule.tags.length > 0 && (
        <Fact name="Etiket">
          <span className="font-mono text-[11.5px]">{rule.tags.join(" ")}</span>
        </Fact>
      )}
      {rule.false_positives.length > 0 && <Fact name="Zararsız olabilir">{rule.false_positives.join("; ")}</Fact>}
    </dl>
  );
}

function Fact({ name, children }: { name: string; children: ReactNode }) {
  return (
    <>
      <dt className="font-semibold">{name}</dt>
      <dd className="m-0 min-w-0 break-words">{children}</dd>
    </>
  );
}

/** A link that leaves the application, shortened to where it leads. */
function Outside({ href }: { href: string }) {
  return (
    <a href={href} title={href} target="_blank" rel="noreferrer" className="text-accent underline">
      {shortLink(href)}
    </a>
  );
}
