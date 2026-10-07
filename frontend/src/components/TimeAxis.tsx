import { formatDay, formatShortTime, timeTicks } from "../lib/time";

interface Props {
  startMs: number;
  endMs: number;
  /** Left edge and width of the plot area, in pixels. */
  left: number;
  plotWidth: number;
  /** The y position of the axis line. */
  baseline: number;
}

/** A time axis in UTC: round times, with the date repeated wherever a new day starts. */
export function TimeAxis({ startMs, endMs, left, plotWidth, baseline }: Props) {
  const span = Math.max(endMs - startMs, 1);
  const ticks = timeTicks(startMs, endMs, Math.max(2, Math.floor(plotWidth / 110)));
  return (
    <>
      {ticks.map((tick, index) => {
        const x = left + ((tick - startMs) / span) * plotWidth;
        const newDay = index === 0 || new Date(tick).getUTCHours() + new Date(tick).getUTCMinutes() === 0;
        // A label at the right edge is set flush right so that it is not cut off.
        const anchor = x > left + plotWidth - 28 ? "end" : "middle";
        return (
          <g key={tick} transform={`translate(${x},${baseline})`}>
            <line y2={4} stroke="var(--rule-strong)" />
            <text y={15} textAnchor={anchor} className="figures fill-ink-3 text-[11px]">
              {formatShortTime(tick)}
            </text>
            {newDay && (
              <text y={28} textAnchor={anchor} className="fill-ink-3 text-[11px]">
                {formatDay(tick)}
              </text>
            )}
          </g>
        );
      })}
    </>
  );
}
