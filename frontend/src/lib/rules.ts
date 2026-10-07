// Rules described in words, for the rules page.

import type { EventFilter, Rule } from "../api";

const GROUP_LABEL: Record<string, string> = {
  src_ip: "kaynak adres",
  user: "kullanıcı",
  host: "makine",
  service: "program",
};

const FIELD_LABEL: Record<keyof EventFilter, string> = {
  action: "eylem",
  service: "program",
  host: "makine",
  user: "kullanıcı",
  level: "düzey",
  dst_port: "hedef port",
};

/** Which events a filter lets through: "eylem conn_block veya conn_allow, hedef port 22". Empty if all of them. */
export function describeMatch(match: EventFilter | undefined): string {
  if (!match) return "";
  return (Object.keys(FIELD_LABEL) as (keyof EventFilter)[])
    .filter((field) => match[field]?.length)
    .map((field) => `${FIELD_LABEL[field]} ${match[field].join(" veya ")}`)
    .join(", ");
}

/** What a rule looks for, in a sentence. */
export function describeCondition(rule: Rule): string {
  const group = GROUP_LABEL[rule.group_by] ?? rule.group_by;
  switch (rule.type) {
    case "threshold":
      return `Aynı ${group} için ${rule.window_seconds} sn içinde ${rule.threshold} eşleşen olay`;
    case "sequence": {
      const steps = rule.steps.map((step) => `${step.count > 1 ? `${step.count} kez ` : ""}${describeMatch(step.match)}`);
      return `Aynı ${group} için ${rule.within_seconds} sn içinde sırayla: ${steps.join(", ardından ")}`;
    }
    case "port_scan":
      return `Aynı ${group} için ${rule.window_seconds} sn içinde ${rule.min_ports} farklı hedef port`;
    case "rare_port":
      return rule.mode === "watchlist"
        ? `Şu portlardan birine bağlantı: ${rule.ports.join(", ")}`
        : `Şu portların dışındaki bir porta bağlantı: ${rule.ports.join(", ")}`;
    case "keyword": {
      const texts = [...rule.keywords, ...(rule.regex ? [`/${rule.regex}/`] : [])];
      return `Mesajında şunlardan biri geçen satır: ${texts.join(", ")}`;
    }
  }
}
