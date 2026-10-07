import { useMemo, useState } from "react";
import { List, type RowComponentProps } from "react-window";
import type { LogEvent, QueryParams } from "../api";
import { condense, splitByHighlights, topSeverity } from "../lib/highlight";
import { formatCount, formatDateTime } from "../lib/time";
import { useEvents } from "../queries";
import { Notice } from "./Layout";

const ROW_HEIGHT = 28;
// time · program · action · source · user or port · message
const COLUMNS = "132px 96px 104px 124px 96px minmax(320px, 1fr)";

interface RowData {
  events: LogEvent[];
  selectedId: number | null;
  onSelect: (event: LogEvent) => void;
}

/**
 * The message with its highlighted parts wrapped in <mark>. `condensed` shortens
 * the text around the highlights so that they fit one line of the table.
 */
export function MarkedMessage({ event, condensed = false }: { event: LogEvent; condensed?: boolean }) {
  const segments = splitByHighlights(event.message, event.highlights);
  return (
    <>
      {(condensed ? condense(segments) : segments).map((segment, index) =>
        segment.marks.length ? (
          <mark key={index} data-severity={topSeverity(segment.marks)}>
            {segment.text}
          </mark>
        ) : (
          segment.text
        ),
      )}
    </>
  );
}

function Row({ index, style, ariaAttributes, events, selectedId, onSelect }: RowComponentProps<RowData>) {
  const event = events[index];
  if (!event) {
    return (
      <div style={style} {...ariaAttributes} className="flex items-center px-3 text-ink-3">
        Devamı yükleniyor…
      </div>
    );
  }
  const severity = topSeverity(event.highlights);
  const rules = [...new Set(event.highlights.map((highlight) => highlight.rule_id))];
  return (
    <div
      style={{ ...style, gridTemplateColumns: COLUMNS }}
      {...ariaAttributes}
      data-severity-edge={severity ?? undefined}
      data-evidence={severity ? "true" : undefined}
      aria-current={event.id === selectedId ? "true" : undefined}
      onClick={() => onSelect(event)}
      className={`grid cursor-pointer items-center gap-3 border-b border-rule px-3 font-mono text-[12.5px] hover:bg-accent-soft ${
        event.id === selectedId ? "bg-accent-soft" : ""
      }`}
    >
      <span className="figures text-ink-2">{formatDateTime(event.ts)}</span>
      <span className="truncate">{event.service ?? "–"}</span>
      <span className="flex items-center gap-1.5 truncate">
        {event.level === "warning" && (
          <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--series-suspicious)]" title="Şüpheli olay" />
        )}
        {event.action ?? <span className="text-ink-3">–</span>}
      </span>
      <span className="truncate">{event.src_ip ?? ""}</span>
      <span className="truncate">{event.user ?? event.dst_port ?? ""}</span>
      <span className="flex min-w-0 items-center gap-2">
        <span className="truncate">
          <MarkedMessage event={event} condensed />
        </span>
        {rules.map((rule) => (
          <span key={rule} className="shrink-0 rounded-sm border border-rule-strong px-1 font-sans text-[11px] font-semibold text-ink-2">
            {rule}
          </span>
        ))}
      </span>
    </div>
  );
}

/**
 * The log lines that match the given API filters, oldest first. Only the rows
 * in view are rendered, and further pages are fetched as the end comes near.
 */
export function LogTable({ params, onFilterIp }: { params: QueryParams; onFilterIp?: (ip: string) => void }) {
  const query = useEvents(params);
  const [selected, setSelected] = useState<LogEvent | null>(null);
  const events = useMemo(() => query.data?.pages.flatMap((page) => page.items) ?? [], [query.data]);
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query;

  if (query.isError) return <Notice tone="error">{query.error.message}</Notice>;
  if (query.isPending) return <Notice>Olaylar yükleniyor…</Notice>;
  if (events.length === 0) return <Notice>Bu filtrelere uyan olay yok. Filtreleri gevşetmeyi ya da zaman aralığını genişletmeyi dene.</Notice>;

  return (
    <div>
      <div className="overflow-x-auto">
        <div className="min-w-[980px]">
          <div
            className="grid gap-3 border-b border-rule-strong px-3 py-1.5 text-[12px] font-semibold text-ink-2"
            style={{ gridTemplateColumns: COLUMNS }}
          >
            <span>Zaman (UTC)</span>
            <span>Program</span>
            <span>Eylem</span>
            <span>Kaynak</span>
            <span>Kullanıcı / port</span>
            <span>Mesaj</span>
          </div>
          <List
            rowComponent={Row}
            rowCount={events.length + (hasNextPage ? 1 : 0)}
            rowHeight={ROW_HEIGHT}
            rowProps={{ events, selectedId: selected?.id ?? null, onSelect: setSelected }}
            overscanCount={12}
            onRowsRendered={({ stopIndex }) => {
              if (stopIndex >= events.length - 40 && hasNextPage && !isFetchingNextPage) void fetchNextPage();
            }}
            style={{ height: "max(336px, calc(100vh - 470px))" }}
          />
        </div>
      </div>
      <div className="flex items-center justify-between border-t border-rule px-3 py-1.5 text-[12px] text-ink-2">
        <span className="figures">
          {formatCount(events.length)} satır{hasNextPage ? " yüklendi, devamı kaydırdıkça gelir" : ""}
        </span>
        {selected && (
          <button type="button" className="font-semibold text-accent" onClick={() => setSelected(null)}>
            Seçimi kaldır
          </button>
        )}
      </div>
      {selected && <EventDetail event={selected} onFilterIp={params.ip === selected.src_ip ? undefined : onFilterIp} />}
    </div>
  );
}

/** The whole line as it stands in the file, with the highlights of its message. */
function MarkedLine({ event }: { event: LogEvent }) {
  const offset = event.raw.lastIndexOf(event.message);
  if (offset < 0 || event.message === "") return <>{event.raw}</>;
  return (
    <>
      {event.raw.slice(0, offset)}
      <MarkedMessage event={event} />
      {event.raw.slice(offset + event.message.length)}
    </>
  );
}

function EventDetail({ event, onFilterIp }: { event: LogEvent; onFilterIp?: (ip: string) => void }) {
  const ip = event.src_ip;
  return (
    <div className="border-t border-rule-strong px-3 py-2">
      <div className="mb-1 flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-[12px] font-semibold text-ink-2">
        <span>
          {event.source_file}, satır {formatCount(event.line_no)}
          {!event.parsed && " · hiçbir kalıba uymadı"}
        </span>
        {ip && onFilterIp && (
          <button type="button" className="cursor-pointer font-semibold text-accent" onClick={() => onFilterIp(ip)}>
            Yalnızca {ip} adresinin olaylarını göster
          </button>
        )}
      </div>
      <pre className="m-0 font-mono text-[12.5px] break-all whitespace-pre-wrap">
        <MarkedLine event={event} />
      </pre>
    </div>
  );
}
