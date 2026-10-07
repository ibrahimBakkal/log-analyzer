import { useEffect, useState } from "react";
import type { Level, Rule } from "../api";
import { type Filters, hasFieldFilters } from "../lib/filters";

interface Props {
  filters: Filters;
  rules: Rule[];
  onChange: (patch: Partial<Filters>) => void;
  onClear: () => void;
}

// What a line says happened, as the table's "Eylem" column names it, and what that means.
const ACTIONS = [
  ["auth_fail", "başarısız giriş"],
  ["auth_ok", "başarılı giriş"],
  ["invalid_user", "var olmayan kullanıcı"],
  ["disconnect", "bağlantı kapandı"],
  ["sudo_exec", "sudo komutu"],
  ["sudo_denied", "reddedilen sudo"],
  ["conn_block", "engellenen paket"],
  ["conn_allow", "geçirilen bağlantı"],
] as const;

/** "2026-09-10T02:31:00Z" <-> the value of a datetime-local input, read as UTC. */
function toInput(iso: string | undefined): string {
  return iso ? iso.slice(0, 19) : "";
}
function fromInput(value: string): string | undefined {
  if (!value) return undefined;
  const moment = new Date(`${value.length === 16 ? `${value}:00` : value}Z`);
  return Number.isNaN(moment.getTime()) ? undefined : moment.toISOString().replace(".000Z", "Z");
}

/** A text field that applies its value on Enter or when it loses focus, not on every key. */
function TextFilter({ label, value, placeholder, width, onCommit }: { label: string; value: string; placeholder: string; width: string; onCommit: (value: string) => void }) {
  const [draft, setDraft] = useState(value);
  useEffect(() => setDraft(value), [value]);
  return (
    <label className="flex flex-col gap-0.5 text-[12px] font-semibold text-ink-2">
      {label}
      <input
        className={`field ${width} font-mono text-[12.5px] font-normal`}
        value={draft}
        placeholder={placeholder}
        onChange={(event) => setDraft(event.target.value)}
        onBlur={() => draft !== value && onCommit(draft.trim())}
        onKeyDown={(event) => event.key === "Enter" && onCommit(draft.trim())}
      />
    </label>
  );
}

/** One row of filters above everything they scope: time range first. */
export function FilterBar({ filters, rules, onChange, onClear }: Props) {
  const active = hasFieldFilters(filters) || filters.start || filters.end || filters.alert;
  return (
    <form className="flex flex-wrap items-end gap-3 px-3 py-2" onSubmit={(event) => event.preventDefault()}>
      <label className="flex flex-col gap-0.5 text-[12px] font-semibold text-ink-2">
        Başlangıç (UTC)
        <input
          type="datetime-local"
          step={1}
          className="field figures font-normal"
          value={toInput(filters.start)}
          onChange={(event) => onChange({ start: fromInput(event.target.value), alert: undefined, evidence: undefined })}
        />
      </label>
      <label className="flex flex-col gap-0.5 text-[12px] font-semibold text-ink-2">
        Bitiş (UTC)
        <input
          type="datetime-local"
          step={1}
          className="field figures font-normal"
          value={toInput(filters.end)}
          onChange={(event) => onChange({ end: fromInput(event.target.value), alert: undefined, evidence: undefined })}
        />
      </label>
      <TextFilter label="IP adresi" value={filters.ip ?? ""} placeholder="203.0.113.45" width="w-36" onCommit={(ip) => onChange({ ip: ip || undefined })} />
      <TextFilter label="Program" value={filters.service ?? ""} placeholder="sshd" width="w-24" onCommit={(service) => onChange({ service: service || undefined })} />
      <label className="flex flex-col gap-0.5 text-[12px] font-semibold text-ink-2">
        Eylem
        <select className="field w-48 font-normal" value={filters.action ?? ""} onChange={(event) => onChange({ action: event.target.value || undefined })}>
          <option value="">Hepsi</option>
          {ACTIONS.map(([action, meaning]) => (
            <option key={action} value={action}>
              {action} ({meaning})
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-0.5 text-[12px] font-semibold text-ink-2">
        Kural
        <select className="field font-normal" value={filters.rule ?? ""} onChange={(event) => onChange({ rule: event.target.value || undefined })}>
          <option value="">Tüm olaylar</option>
          {rules.map((rule) => (
            <option key={rule.id} value={rule.id}>
              {rule.id} kanıtları
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-0.5 text-[12px] font-semibold text-ink-2">
        Düzey
        <select
          className="field font-normal"
          value={filters.level ?? ""}
          onChange={(event) => onChange({ level: (event.target.value || undefined) as Level | undefined })}
        >
          <option value="">Hepsi</option>
          <option value="warning">Şüpheli</option>
          <option value="info">Olağan</option>
        </select>
      </label>
      <button type="button" className="button" onClick={onClear} disabled={!active}>
        Filtreleri temizle
      </button>
    </form>
  );
}
