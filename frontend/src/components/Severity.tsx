import type { Severity } from "../api";

export const SEVERITY_LABEL: Record<Severity, string> = {
  low: "Düşük",
  medium: "Orta",
  high: "Yüksek",
  critical: "Kritik",
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

// Each severity has its own shape, so it can be told apart without colour.
const SHAPE: Record<Severity, string> = {
  low: "M8 2.5a5.5 5.5 0 1 0 0 11a5.5 5.5 0 0 0 0-11Z", // circle
  medium: "M8 2L14.5 13.5H1.5Z", // triangle
  high: "M8 1.5L14.5 8L8 14.5L1.5 8Z", // diamond
  critical: "M5.3 1.5h5.4l3.8 3.8v5.4l-3.8 3.8H5.3l-3.8-3.8V5.3Z", // octagon
};

export function SeverityIcon({ severity, size = 14 }: { severity: Severity; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" aria-hidden="true" className="shrink-0">
      <path d={SHAPE[severity]} fill={`var(--sev-${severity})`} />
    </svg>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className="inline-flex items-center gap-1.5 font-semibold">
      <SeverityIcon severity={severity} />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}
