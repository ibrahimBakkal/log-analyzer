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

type KeywordRule = Extract<Rule, { type: "keyword" }>;

/** What a rule looks for, in a sentence. Keyword rules have lists instead: see keywordClauses. */
export function describeCondition(rule: Exclude<Rule, KeywordRule>): string {
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
  }
}

export interface KeywordClause {
  /** How the texts take part: "Şunlardan biri geçen satır". */
  lead: string;
  texts: string[];
  /** The texts are regular expressions, not keywords. */
  pattern?: boolean;
}

/** What a keyword rule looks for, as the lists of texts it is made of, in the order they apply. */
export function keywordClauses(rule: KeywordRule): KeywordClause[] {
  const clauses: KeywordClause[] = [];
  if (rule.keywords.length > 0) {
    clauses.push({ lead: rule.keywords.length > 1 ? "Şunlardan biri geçen satır" : "Şu metnin geçtiği satır", texts: rule.keywords });
  }
  if (rule.regex) {
    clauses.push({ lead: clauses.length > 0 ? "ya da mesajı şu kalıba uyan satır" : "Mesajı şu kalıba uyan satır", texts: [rule.regex], pattern: true });
  }
  for (const entry of rule.require) {
    clauses.push({ lead: entry.length > 1 ? "ayrıca şunlardan biri" : "ayrıca şu", texts: entry });
  }
  if (rule.exclude.length > 0) {
    clauses.push({ lead: rule.exclude.length > 1 ? "şunlardan biri geçiyorsa sayılmaz" : "şu geçiyorsa sayılmaz", texts: rule.exclude });
  }
  return clauses;
}

export interface TextPiece {
  text: string;
  href?: string;
}

/** A text cut where its web addresses begin and end, so that a page can make links of them. */
export function splitLinks(text: string): TextPiece[] {
  const pieces: TextPiece[] = [];
  let rest = 0;
  for (const match of text.matchAll(/https?:\/\/[^\s<>"']+/g)) {
    // Punctuation that ends the sentence or closes a bracket is not part of the address.
    const address = match[0].replace(/[.,;:!?)\]]+$/, "");
    if (match.index > rest) pieces.push({ text: text.slice(rest, match.index) });
    pieces.push({ text: address, href: address });
    rest = match.index + address.length;
  }
  if (rest < text.length) pieces.push({ text: text.slice(rest) });
  return pieces;
}

/** A web address short enough to read: where it leads and what it ends in. "github.com/…/SSH-001.yaml" */
export function shortLink(href: string): string {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return href;
  }
  const host = url.host.replace(/^www\./, "");
  const steps = url.pathname.split("/").filter(Boolean);
  if (steps.length === 0) return host;
  return `${host}/${steps.length > 1 ? "…/" : ""}${decodeURIComponent(steps[steps.length - 1])}`;
}
