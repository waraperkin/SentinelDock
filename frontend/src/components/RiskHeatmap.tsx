import type { Risk, Severity } from '@/types/models';

const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical'];

const CELL_STYLE: Record<Severity, { color: string; bg: string }> = {
  low: { color: 'var(--sd-low)', bg: 'rgba(100,116,139,0.14)' },
  medium: { color: 'var(--sd-medium)', bg: 'rgba(217,164,65,0.16)' },
  high: { color: 'var(--sd-high)', bg: 'rgba(232,130,58,0.18)' },
  critical: { color: 'var(--sd-critical)', bg: 'rgba(239,74,95,0.22)' },
};

/** Category x severity risk count grid — a quick "where is the heat" view. */
export function RiskHeatmap({ risks }: { risks: Risk[] }) {
  const categories = Array.from(new Set(risks.map((r) => r.category))).sort();
  if (categories.length === 0) return null;

  const counts = new Map<string, number>();
  for (const risk of risks) {
    const key = `${risk.category}:${risk.severity}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  return (
    <div className="sd-panel sd-scrollbar overflow-x-auto mb-6">
      <table className="text-sm w-full">
        <thead>
          <tr className="border-b border-[var(--sd-border)]">
            <th className="text-left px-4 py-3 text-[11px] font-semibold uppercase tracking-wide text-[var(--sd-text-muted)]">Category</th>
            {SEVERITIES.map((s) => (
              <th key={s} className="text-center px-4 py-3 text-[11px] font-semibold uppercase tracking-wide text-[var(--sd-text-muted)]">
                {s}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {categories.map((category) => (
            <tr key={category} className="border-t border-[var(--sd-border)]">
              <td className="px-4 py-2.5 capitalize text-[var(--sd-text-primary)] font-medium">{category}</td>
              {SEVERITIES.map((severity) => {
                const count = counts.get(`${category}:${severity}`) ?? 0;
                const style = CELL_STYLE[severity];
                return (
                  <td key={severity} className="px-4 py-2.5 text-center">
                    <span
                      className="inline-flex min-w-[2rem] justify-center rounded-md px-2 py-0.5 sd-mono text-xs font-semibold"
                      style={count > 0 ? { color: style.color, backgroundColor: style.bg } : { color: 'var(--sd-text-muted)' }}
                    >
                      {count}
                    </span>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
