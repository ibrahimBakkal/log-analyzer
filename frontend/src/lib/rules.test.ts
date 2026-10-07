import { describe, expect, it } from "vitest";
import type { EventFilter, Rule } from "../api";
import { describeCondition, describeMatch, shortLink, splitLinks } from "./rules";

const any: EventFilter = { action: [], service: [], host: [], user: [], level: [], dst_port: [] };
const common = {
  name: "Kural",
  description: "",
  severity: "high" as const,
  enabled: true,
  group_by: "src_ip",
  cooldown_seconds: 300,
  match: any,
  author: "",
  source: "",
  license: "",
  references: [] as string[],
  tags: [] as string[],
  false_positives: [] as string[],
};

describe("describeMatch", () => {
  it("is empty for a filter that lets everything through", () => {
    expect(describeMatch(any)).toBe("");
    expect(describeMatch(undefined)).toBe("");
  });

  it("names each restricted field with its accepted values", () => {
    expect(describeMatch({ ...any, action: ["auth_fail"] })).toBe("eylem auth_fail");
    expect(describeMatch({ ...any, action: ["conn_block", "conn_allow"], dst_port: [22] })).toBe(
      "eylem conn_block veya conn_allow, hedef port 22",
    );
    expect(describeMatch({ ...any, service: ["sshd"], level: ["warning"] })).toBe("program sshd, düzey warning");
  });
});

describe("describeCondition", () => {
  it("describes a threshold", () => {
    const rule: Rule = { ...common, id: "SSH-001", type: "threshold", threshold: 5, window_seconds: 60 };
    expect(describeCondition(rule)).toBe("Aynı kaynak adres için 60 sn içinde 5 eşleşen olay");
  });

  it("describes keywords and a regular expression", () => {
    const rule: Rule = {
      ...common,
      id: "KW-001",
      type: "keyword",
      group_by: "user",
      keywords: ["/etc/shadow"],
      regex: "id_rsa$",
      require: [],
      exclude: [],
    };
    expect(describeCondition(rule)).toBe("Mesajında şunlardan biri geçen satır: /etc/shadow, /id_rsa$/");
  });

  it("adds what a keyword rule requires and what it excludes", () => {
    const rule: Rule = {
      ...common,
      id: "KW-002",
      type: "keyword",
      keywords: ["scp ", "rsync "],
      regex: null,
      require: [["@", "::"], ["COMMAND="]],
      exclude: ["--dry-run", "localhost"],
    };
    expect(describeCondition(rule)).toBe(
      "Mesajında şunlardan biri geçen satır: scp , rsync ; ayrıca şunlardan biri: @, ::; ayrıca şu: COMMAND=; şunlar geçmiyorsa: --dry-run, localhost",
    );
  });

  it("describes the steps of a sequence in order, with their counts", () => {
    const rule: Rule = {
      ...common,
      id: "SSH-002",
      type: "sequence",
      within_seconds: 600,
      steps: [
        { match: { ...any, action: ["auth_fail"] }, count: 5 },
        { match: { ...any, action: ["auth_ok"] }, count: 1 },
      ],
    };
    expect(describeCondition(rule)).toBe(
      "Aynı kaynak adres için 600 sn içinde sırayla: 5 kez eylem auth_fail, ardından eylem auth_ok",
    );
  });

  it("describes a port scan", () => {
    const rule: Rule = { ...common, id: "NET-001", type: "port_scan", min_ports: 15, window_seconds: 60 };
    expect(describeCondition(rule)).toBe("Aynı kaynak adres için 60 sn içinde 15 farklı hedef port");
  });

  it("describes both modes of an unexpected-port rule", () => {
    const watch: Rule = { ...common, id: "NET-002", type: "rare_port", mode: "watchlist", ports: [23, 3389] };
    const allow: Rule = { ...watch, mode: "allowlist", ports: [22, 80, 443] };
    expect(describeCondition(watch)).toBe("Şu portlardan birine bağlantı: 23, 3389");
    expect(describeCondition(allow)).toBe("Şu portların dışındaki bir porta bağlantı: 22, 80, 443");
  });

  it("falls back to the field name for a group it has no word for", () => {
    const rule: Rule = { ...common, id: "X-1", type: "threshold", group_by: "dst_ip", threshold: 2, window_seconds: 10 };
    expect(describeCondition(rule)).toBe("Aynı dst_ip için 10 sn içinde 2 eşleşen olay");
  });
});

describe("splitLinks", () => {
  it("separates web addresses from the text around them", () => {
    expect(splitLinks("Detection Rule License 1.1 (https://example.org/license), as is")).toEqual([
      { text: "Detection Rule License 1.1 (" },
      { text: "https://example.org/license", href: "https://example.org/license" },
      { text: "), as is" },
    ]);
  });

  it("keeps a full stop at the end of a sentence out of the address", () => {
    expect(splitLinks("See http://example.org/a.b.")).toEqual([
      { text: "See " },
      { text: "http://example.org/a.b", href: "http://example.org/a.b" },
      { text: "." },
    ]);
  });

  it("returns plain text as one piece and nothing for nothing", () => {
    expect(splitLinks("MIT")).toEqual([{ text: "MIT" }]);
    expect(splitLinks("")).toEqual([]);
  });
});

describe("shortLink", () => {
  it("keeps the site and the last step of the path", () => {
    expect(shortLink("https://github.com/SigmaHQ/sigma/blob/8a48134/rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml")).toBe(
      "github.com/…/lnx_sshd_susp_ssh.yml",
    );
    expect(shortLink("https://www.example.org/advisory/")).toBe("example.org/advisory");
    expect(shortLink("https://example.org/a%20b?page=2#top")).toBe("example.org/a b");
  });

  it("is the site alone when there is no path, and the text itself when it is no address", () => {
    expect(shortLink("https://example.org")).toBe("example.org");
    expect(shortLink("see the handbook")).toBe("see the handbook");
  });
});
