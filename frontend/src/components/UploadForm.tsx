import { useState } from "react";
import { formatCount } from "../lib/time";
import { useIngest } from "../queries";

const ZONES = ["UTC", "Europe/Istanbul", "Europe/Berlin", "Europe/London", "America/New_York", "Asia/Tokyo"];

/** Upload a log file. Year and time zone are asked because syslog lines carry neither. */
export function UploadForm() {
  const ingest = useIngest();
  const [file, setFile] = useState<File | null>(null);
  const [year, setYear] = useState("");
  const [tz, setTz] = useState("UTC");
  const report = ingest.data;

  return (
    <form
      className="flex flex-wrap items-end gap-3 px-3 py-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (file) ingest.mutate({ file, year: year || undefined, tz });
      }}
    >
      <label className="flex flex-col gap-0.5 text-[12px] font-semibold text-ink-2">
        Log dosyası (auth.log)
        <input
          type="file"
          className="field w-72 py-1 font-normal"
          onChange={(event) => {
            setFile(event.target.files?.[0] ?? null);
            ingest.reset();
          }}
        />
      </label>
      <label className="flex flex-col gap-0.5 text-[12px] font-semibold text-ink-2">
        İlk satırın yılı
        <input
          type="number"
          min={1970}
          max={9999}
          className="field figures w-24 font-normal"
          placeholder="otomatik"
          value={year}
          onChange={(event) => setYear(event.target.value)}
        />
      </label>
      <label className="flex flex-col gap-0.5 text-[12px] font-semibold text-ink-2">
        Logu yazan makinenin saat dilimi
        <input className="field w-48 font-normal" list="zones" value={tz} onChange={(event) => setTz(event.target.value)} />
        <datalist id="zones">
          {ZONES.map((zone) => (
            <option key={zone} value={zone} />
          ))}
        </datalist>
      </label>
      <button type="submit" className="button button-primary" disabled={!file || ingest.isPending}>
        {ingest.isPending ? "Yükleniyor…" : "Log yükle"}
      </button>
      <p className="m-0 basis-full text-[13px]" aria-live="polite">
        {ingest.isError && <span className="text-[var(--sev-critical)]">Yüklenemedi: {ingest.error.message}</span>}
        {report && (
          <span>
            <strong>{report.source_file}</strong> yüklendi: {formatCount(report.lines)} satırın {formatCount(report.parsed)} tanesi
            ayrıştırıldı, {formatCount(report.unparsed)} tanesi tanınmadan saklandı
            {report.duplicates > 0 && `, ${formatCount(report.duplicates)} tanesi zaten kayıtlıydı`}
            {report.conflicts > 0 && `, ${formatCount(report.conflicts)} satır farklı içerikle kayıtlı olduğu için atlandı`}. Şu an{" "}
            {formatCount(report.alerts)} uyarı var.
          </span>
        )}
      </p>
    </form>
  );
}
