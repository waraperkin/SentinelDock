import { apiGet } from '@/lib/api';
import type { AttackPath, AttackPathGraph } from '@/types/models';
import { SeverityBadge } from '@/components/SeverityBadge';
import { AttackPathGraphView } from '@/components/AttackPathGraph';

export default async function AttackPathsPage() {
  const [paths, graph] = await Promise.all([
    apiGet<AttackPath[]>('/attack-paths'),
    apiGet<AttackPathGraph>('/attack-paths/graph'),
  ]);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Attack Paths</h1>
      <AttackPathGraphView graph={graph} />
      <div className="mt-6 space-y-3">
        {paths.map((path) => (
          <div key={path.id} className="border border-slate-800 rounded-lg p-4 bg-slate-900">
            <div className="flex items-center justify-between">
              <div className="font-semibold">{path.name}</div>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={path.severity} />
                <span className="text-slate-400 text-sm">blast radius {path.blast_radius}</span>
              </div>
            </div>
            <div className="text-slate-400 text-sm mt-1">
              {path.entry_asset_type}:{path.entry_asset_id} → {path.target_asset_type}:{path.target_asset_id}
            </div>
          </div>
        ))}
        {paths.length === 0 && <p className="text-slate-500">No attack paths built yet.</p>}
      </div>
    </div>
  );
}
