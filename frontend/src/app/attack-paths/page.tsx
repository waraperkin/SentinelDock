import { apiGet } from '@/lib/api';
import type { AttackPath, AttackPathGraph } from '@/types/models';
import { SeverityBadge } from '@/components/SeverityBadge';
import { AttackPathGraphView } from '@/components/AttackPathGraph';
import { SearchableList } from '@/components/SearchableList';
import { AssetLink } from '@/components/AssetLink';

export default async function AttackPathsPage() {
  const [paths, graph] = await Promise.all([
    apiGet<AttackPath[]>('/attack-paths'),
    apiGet<AttackPathGraph>('/attack-paths/graph'),
  ]);

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">Attack Paths</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">Traversed from every at-risk exposed entry point across the dependency graph.</p>
      </div>
      <AttackPathGraphView graph={graph} />
      <div className="mt-6">
        <SearchableList
          placeholder="Search by asset id, name…"
          emptyMessage="No attack paths match."
          resultsClassName="space-y-3"
          items={paths.map((path) => ({
            id: path.id,
            severity: path.severity,
            searchText: `${path.name} ${path.entry_asset_id} ${path.target_asset_id} ${path.hops.map((h) => h.asset_id).join(' ')}`,
            content: (
              <div className="sd-panel p-5">
                <div className="flex items-center justify-between gap-4">
                  <div className="font-medium text-[var(--sd-text-primary)]">{path.name}</div>
                  <div className="flex items-center gap-3 shrink-0">
                    <SeverityBadge severity={path.severity} />
                    <span className="text-[var(--sd-text-muted)] text-xs sd-mono">blast radius {path.blast_radius}</span>
                  </div>
                </div>
                <div className="text-sm mt-2 flex items-center gap-2">
                  <AssetLink assetType={path.entry_asset_type} assetId={path.entry_asset_id} className="sd-mono" />
                  <span className="text-[var(--sd-text-muted)]">→</span>
                  <AssetLink assetType={path.target_asset_type} assetId={path.target_asset_id} className="sd-mono" />
                </div>
                {path.hops.length > 0 && (
                  <ol className="mt-3 pt-3 border-t border-[var(--sd-border)] space-y-1.5">
                    {path.hops.map((hop, i) => (
                      <li key={i} className="text-xs text-[var(--sd-text-muted)] flex items-baseline gap-2">
                        <span className="text-[var(--sd-accent)] shrink-0">{i + 1}.</span>
                        <span className="sd-mono text-[var(--sd-text-secondary)]">{hop.via} →</span>
                        <AssetLink assetType={hop.asset_type} assetId={hop.asset_id} className="sd-mono text-xs" />
                        {hop.technique && <span className="text-[var(--sd-accent-strong)]">— {hop.technique}</span>}
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            ),
          }))}
        />
      </div>
    </div>
  );
}
