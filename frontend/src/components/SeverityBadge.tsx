const COLORS: Record<string, string> = {
  low: 'bg-slate-200 text-slate-800',
  medium: 'bg-amber-200 text-amber-900',
  high: 'bg-orange-300 text-orange-950',
  critical: 'bg-red-500 text-white',
};

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = COLORS[severity] ?? COLORS.low;
  return <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${cls}`}>{severity}</span>;
}
