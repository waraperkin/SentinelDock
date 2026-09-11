import { apiGet } from '@/lib/api';
import type { Risk } from '@/types/models';
import { SeverityBadge } from '@/components/SeverityBadge';
import { RiskHeatmap } from '@/components/RiskHeatmap';

export default async function RisksPage({ searchParams }: { searchParams: { severity?: string; category?: string } }) {
  const params = new URLSearchParams();
  if (searchParams.severity) params.set('severity', searchParams.severity);
  if (searchParams.category) params.set('category', searchParams.category);
  const [risks, allRisks] = await Promise.all([
    apiGet<Risk[]>(`/risks${params.toString() ? `?${params}` : ''}`),
    apiGet<Risk[]>('/risks'),
  ]);

  const selectClass =
    'bg-[var(--sd-surface)] border border-[var(--sd-border)] text-[var(--sd-text-primary)] rounded-lg px-3 py-2 text-sm outline-none focus:border-[var(--sd-accent)]';

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">Risks</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">Aggregated from open policy violations and known-vulnerable service versions.</p>
      </div>
      <RiskHeatmap risks={allRisks} />
      <form className="flex gap-3 mb-6 text-sm">
        <select name="severity" defaultValue={searchParams.severity ?? ''} className={selectClass}>
          <option value="">All severities</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
        <select name="category" defaultValue={searchParams.category ?? ''} className={selectClass}>
          <option value="">All categories</option>
          <option value="exposure">Exposure</option>
          <option value="vulnerability">Vulnerability</option>
          <option value="misconfiguration">Misconfiguration</option>
          <option value="segmentation">Segmentation</option>
          <option value="network">Network</option>
          <option value="container">Container</option>
          <option value="host">Host</option>
          <option value="ics">ICS/OT</option>
          <option value="cloud">Cloud</option>
          <option value="secrets">Secrets</option>
          <option value="patching">Patching</option>
        </select>
        <button className="rounded-lg px-4 py-2 text-sm font-medium bg-[var(--sd-accent)] text-[#03211f] hover:brightness-110 transition" type="submit">
          Filter
        </button>
      </form>
      <div className="space-y-3">
        {risks.map((risk) => (
          <div key={risk.id} className="sd-panel p-5">
            <div className="flex items-center justify-between gap-4">
              <div className="font-medium sd-mono text-sm text-[var(--sd-text-primary)]">
                {risk.asset_type}:{risk.asset_id}
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <SeverityBadge severity={risk.severity} />
                <span className="text-[var(--sd-text-muted)] text-xs sd-mono">score {risk.score}</span>
              </div>
            </div>
            <div className="text-[var(--sd-text-muted)] text-xs uppercase tracking-wide mt-2">{risk.category}</div>
            <p className="text-sm text-[var(--sd-text-secondary)] mt-2">{risk.summary}</p>
          </div>
        ))}
        {risks.length === 0 && <p className="text-[var(--sd-text-muted)] text-sm">No risks recorded.</p>}
      </div>
    </div>
  );
}
