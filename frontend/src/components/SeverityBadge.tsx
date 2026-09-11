const SEVERITY_STYLE: Record<string, { color: string; bg: string }> = {
  low: { color: 'var(--sd-low)', bg: 'rgba(100, 116, 139, 0.12)' },
  medium: { color: 'var(--sd-medium)', bg: 'rgba(217, 164, 65, 0.12)' },
  high: { color: 'var(--sd-high)', bg: 'rgba(232, 130, 58, 0.14)' },
  critical: { color: 'var(--sd-critical)', bg: 'rgba(239, 74, 95, 0.16)' },
};

export function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_STYLE[severity] ?? SEVERITY_STYLE.low;
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide"
      style={{ color: style.color, backgroundColor: style.bg }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: style.color }} />
      {severity}
    </span>
  );
}
