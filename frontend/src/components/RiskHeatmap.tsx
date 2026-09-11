import type { Risk, Severity } from '@/types/models';

const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical'];

const CELL_COLOR: Record<Severity, string> = {
  low: 'bg-slate-800 text-slate-400',
  medium: 'bg-amber-900/60 text-amber-200',
  high: 'bg-orange-900/70 text-orange-200',
  critical: 'bg-red-900/80 text-red-100',
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
    <div className="mb-6 overflow-x-auto border border-slate-800 rounded-lg">
      <table className="text-sm w-full">
        <thead className="bg-slate-900">
          <tr>
            <th className="text-left px-3 py-2 text-slate-400 font-medium">Category</th>
            {SEVERITIES.map((s) => (
              <th key={s} className="text-center px-3 py-2 text-slate-400 font-medium capitalize">
                {s}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {categories.map((category) => (
            <tr key={category} className="border-t border-slate-800">
              <td className="px-3 py-2 capitalize">{category}</td>
              {SEVERITIES.map((severity) => {
                const count = counts.get(`${category}:${severity}`) ?? 0;
                return (
                  <td key={severity} className="px-3 py-2 text-center">
                    <span className={`inline-flex min-w-[2rem] justify-center rounded px-2 py-0.5 ${count > 0 ? CELL_COLOR[severity] : 'text-slate-600'}`}>
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
