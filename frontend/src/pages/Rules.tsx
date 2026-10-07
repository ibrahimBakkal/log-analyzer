import type { ReactNode } from "react";
import { DEMO, type Rule } from "../api";
import { Notice, Panel } from "../components/Layout";
import { SeverityBadge } from "../components/Severity";
import { describeCondition, describeMatch, keywordClauses, shortLink, splitLinks } from "../lib/rules";
import { formatCount } from "../lib/time";
import { useReloadRules, useRules } from "../queries";

// Of a long list of keywords this many are shown; the rest unfold.
const TEXTS_SHOWN = 8;

export function Rules() {
  const rules = useRules();
  const reload = useReloadRules();
  // Rules that name a source were taken from another collection; the rest were written for this installation.
  const own = rules.data?.rules.filter((rule) => !rule.source) ?? [];
  const taken = rules.data?.rules.filter((rule) => rule.source) ?? [];

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
        <p className="m-0 max-w-[80ch] px-3 py-3 text-ink-2">
          Kurallar sunucudaki <code className="font-mono">rules/</code> klasöründe duran YAML dosyalarıdır.{" "}
          {DEMO
            ? "Demoda değiştirilemezler."
            : "Bir dosyayı değiştirdikten sonra yeniden yükle: kurallar saklanan tüm olaylar üzerinde baştan çalışır ve uyarılar güncellenir."}
        </p>
        {reload.isError && <Notice tone="error">Yeniden yüklenemedi: {reload.error.message}</Notice>}
        {reload.data && (
          <p className="m-0 px-3 pb-3 font-semibold" aria-live="polite">
            Yeniden yüklendi: {formatCount(reload.data.alerts.total)} uyarı var ({formatCount(reload.data.alerts.created)}{" "}
            yeni, {formatCount(reload.data.alerts.removed)} kaldırıldı).
          </p>
        )}
        {rules.isError && <Notice tone="error">{rules.error.message}</Notice>}
        {rules.isPending && <Notice>Kurallar yükleniyor…</Notice>}
        {rules.data && rules.data.rules.length === 0 && (
          <Notice>Yüklü kural yok. rules/ klasörüne bir YAML dosyası ekleyip yeniden yükle.</Notice>
        )}
      </Panel>

      {own.length > 0 && <RuleList title={`Bu kurulumun kuralları (${own.length})`} rules={own} />}
      {taken.length > 0 && (
        <RuleList
          title={`Başka koleksiyonlardan alınan kurallar (${taken.length})`}
          note="Yazarı, özgün kuralın adresi ve lisansı her kuralın altında yazar; lisansları bunların kuralla birlikte kalmasını ister."
          rules={taken}
        />
      )}

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

function RuleList({ title, note, rules }: { title: string; note?: string; rules: Rule[] }) {
  return (
    <Panel title={title}>
      {note && (
        <div className="border-b border-rule px-3 py-2">
          <p className="m-0 max-w-[80ch] text-[12.5px] text-ink-2">{note}</p>
        </div>
      )}
      <ul className="m-0 list-none p-0">
        {rules.map((rule) => (
          <RuleEntry key={rule.id} rule={rule} />
        ))}
      </ul>
    </Panel>
  );
}

/** One rule: what it is called on the left, what it looks for on the right (below, on a narrow screen). */
function RuleEntry({ rule }: { rule: Rule }) {
  const match = describeMatch(rule.match);
  return (
    <li
      data-severity-edge={rule.enabled ? rule.severity : undefined}
      className="grid gap-x-8 gap-y-2 border-b border-rule px-3 py-3 last:border-b-0 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]"
    >
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[12px]">
          <SeverityBadge severity={rule.severity} />
          <span className="font-mono font-semibold text-ink-2">{rule.id}</span>
          {!rule.enabled && <span className="rounded-sm border border-rule-strong px-1.5 font-semibold">Kapalı</span>}
        </div>
        <h3 className="mt-1 text-[14px] font-semibold">{rule.name}</h3>
        {rule.description && <p className="m-0 max-w-[62ch] text-[12.5px] text-ink-2">{rule.description}</p>}
        <Origin rule={rule} />
      </div>
      <div className="min-w-0">
        {rule.type === "keyword" ? <Keywords rule={rule} /> : <p className="m-0">{describeCondition(rule)}</p>}
        {match && <p className="m-0 mt-1 text-[12.5px] text-ink-2">Bakılan olaylar: {match}</p>}
      </div>
    </li>
  );
}

/** The texts a keyword rule looks for, marked the way the rule marks them in a line. */
function Keywords({ rule }: { rule: Extract<Rule, { type: "keyword" }> }) {
  return (
    <div className="flex flex-col gap-1.5">
      {keywordClauses(rule).map((clause, index) => {
        const shown = clause.texts.slice(0, TEXTS_SHOWN);
        const folded = clause.texts.slice(TEXTS_SHOWN);
        return (
          <div key={index}>
            <span className={index > 0 ? "text-ink-2" : undefined}>{clause.lead}:</span> <Texts texts={shown} rule={rule} />
            {folded.length > 0 && (
              <details className="mt-1">
                <summary className="cursor-pointer text-[12.5px] font-semibold text-accent">{folded.length} metin daha</summary>
                <div className="mt-1">
                  <Texts texts={folded} rule={rule} />
                </div>
              </details>
            )}
          </div>
        );
      })}
    </div>
  );
}

function Texts({ texts, rule }: { texts: string[]; rule: Rule }) {
  return (
    <>
      {texts.map((text, index) => (
        // A keyword stays in one piece where it fits. A space at either end of it matters; the mark shows it.
        <span key={index}>
          <mark
            data-severity={rule.severity}
            className="inline-block max-w-full align-top font-mono text-[12.5px] whitespace-pre-wrap [overflow-wrap:anywhere]"
          >
            {text}
          </mark>{" "}
        </span>
      ))}
    </>
  );
}

/** Who wrote a rule and under what terms, for rules that say so. */
function Origin({ rule }: { rule: Rule }) {
  const links = rule.source ? [rule.source, ...rule.references] : rule.references;
  if (!rule.author && !rule.license && links.length === 0 && rule.tags.length === 0 && rule.false_positives.length === 0) {
    return null;
  }
  return (
    <dl className="mt-1.5 grid max-w-[62ch] grid-cols-[max-content_minmax(0,1fr)] gap-x-3 text-[12px] text-ink-2">
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
