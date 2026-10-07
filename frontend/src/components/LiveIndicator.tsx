import { useEffect, useState } from "react";
import { type LiveTone, describeFile, fileName, liveSummary } from "../lib/live";
import { formatCount, formatTime } from "../lib/time";
import { useLive } from "../live";
import { useFollow } from "../queries";

const DOT: Record<LiveTone, string> = {
  live: "var(--accent)",
  waiting: "var(--sev-medium)",
  problem: "var(--sev-critical)",
  off: "var(--ink-3)",
};
const FRESH_MS = 4000; // how long "+3" stays after new lines came in

/**
 * Says whether the server is following log files right now, and shows the
 * moment new lines come in. Opens a list of the files. Absent when the server
 * follows nothing.
 */
export function LiveIndicator() {
  const live = useLive();
  const [open, setOpen] = useState(false);
  const [, tick] = useState(0);
  const summary = liveSummary(live);
  // How far each file has been read changes with every line; ask when the list is open.
  const detail = useFollow(open && summary !== null);
  const files = detail.data?.following ?? live.following;
  const fresh = live.arrived && Date.now() - live.arrived.at < FRESH_MS ? live.arrived : null;

  // Come back when the "+3" has had its time, to take it away.
  useEffect(() => {
    if (!live.arrived) return;
    const left = live.arrived.at + FRESH_MS - Date.now();
    if (left <= 0) return;
    const timer = setTimeout(() => tick((count) => count + 1), left);
    return () => clearTimeout(timer);
  }, [live.arrived]);

  if (!summary) return null;

  return (
    <div className="relative">
      <button type="button" className="button" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="relative flex h-2 w-2">
          {summary.tone === "live" && (
            <span
              className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60 motion-reduce:animate-none"
              style={{ background: DOT.live }}
            />
          )}
          <span className="relative inline-flex h-2 w-2 rounded-full" style={{ background: DOT[summary.tone] }} />
        </span>
        {summary.text}
        {fresh && summary.tone === "live" && <span className="figures font-normal text-ink-2">+{formatCount(fresh.added)}</span>}
      </button>
      {open && (
        <div className="absolute right-0 z-30 mt-1 w-[min(22rem,calc(100vw-2rem))] rounded-md border border-rule-strong bg-surface p-3 shadow-sm">
          <h2 className="m-0 text-[13px] font-bold">İzlenen log dosyaları</h2>
          <ul className="m-0 mt-1 list-none p-0">
            {files.map((file) => (
              <li key={file.path} className="border-t border-rule py-1.5 first:border-t-0">
                <div className="font-semibold">{file.source ?? fileName(file.path)}</div>
                <div className="text-[13px]">
                  {describeFile(file, formatCount)}
                  {file.read_at && file.state === "following" && `, son satır ${formatTime(file.read_at)} (UTC)`}
                </div>
                <div className="font-mono text-[12px] break-all text-ink-2">{file.path}</div>
              </li>
            ))}
          </ul>
          <p className="m-0 mt-1 border-t border-rule pt-1.5 text-[12px] text-ink-2">
            {live.connected
              ? "Dosyalara eklenen satırlar birkaç saniye içinde bu sayfada görünür."
              : "Sunucuyla bağlantı koptu; yeniden bağlanmayı deniyor. O zamana kadar sayfa kendiliğinden yenilenmez."}
          </p>
        </div>
      )}
    </div>
  );
}
