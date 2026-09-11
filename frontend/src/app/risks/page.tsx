import { apiGet } from '@/lib/api';
import type { Risk } from '@/types/models';
import { SeverityBadge } from '@/components/SeverityBadge';

export default async function RisksPage({ searchParams }: { searchParams: { severity?: string; category?: string } }) {
  const params = new URLSearchParams();
  if (searchParams.severity) params.set('severity', searchParams.severity);
  if (searchParams.category) params.set('category', searchParams.category);
  const risks = await apiGet<Risk[]>(`/risks${params.toString() ? `?${params}` : ''}`);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Risks</h1>
      <form className="flex gap-3 mb-6 text-sm">
        <select name="severity" defaultValue={searchParams.severity ?? ''} className="bg-slate-900 border border-slate-800 rounded px-2 py-1">
          <option value="">All severities</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
        <select name="category" defaultValue={searchParams.category ?? ''} className="bg-slate-900 border border-slate-800 rounded px-2 py-1">
          <option value="">All categories</option>
          <option value="exposure">Exposure</option>
          <option value="misconfiguration">Misconfiguration</option>
          <option value="segmentation">Segmentation</option>
          <option value="patching">Patching</option>
        </select>
        <button className="bg-slate-800 rounded px-3 py-1" type="submit">
          Filter
        </button>
      </form>
      <div className="space-y-3">
        {risks.map((risk) => (
          <div key={risk.id} className="border border-slate-800 rounded-lg p-4 bg-slate-900">
            <div className="flex items-center justify-between">
              <div className="font-semibold">
                {risk.asset_type}:{risk.asset_id}
              </div>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={risk.severity} />
                <span className="text-slate-400 text-sm">score {risk.score}</span>
              </div>
            </div>
            <div className="text-slate-400 text-sm mt-1">{risk.category}</div>
            <p className="text-sm mt-2">{risk.summary}</p>
          </div>
        ))}
        {risks.length === 0 && <p className="text-slate-500">No risks recorded.</p>}
      </div>
    </div>
  );
}
