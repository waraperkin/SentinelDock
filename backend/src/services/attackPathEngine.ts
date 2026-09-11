import { query } from '../db/pool.js';
import type { AttackPath, AttackPathHop, Dependency, Host, Risk, ServiceRecord, Severity } from '../types/models.js';

const SEVERITY_ORDER: Severity[] = ['low', 'medium', 'high', 'critical'];

function worseSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

/**
 * Builds AttackPath records with a simple heuristic:
 * entry = any service exposed publicly with an open risk; then follow
 * `dependencies` edges (BFS, depth <= 4) to find reachable high-criticality
 * hosts. blast_radius = number of distinct assets reachable from the entry.
 */
export async function rebuildAttackPaths(): Promise<AttackPath[]> {
  const services = await query<ServiceRecord>('SELECT * FROM services WHERE exposed_publicly = true');
  const dependencies = await query<Dependency>('SELECT * FROM dependencies');
  const hosts = await query<Host>('SELECT * FROM hosts');
  const risks = await query<Risk>('SELECT * FROM risks');

  const hostById = new Map(hosts.map((h) => [h.id, h]));
  const riskByAsset = new Map(risks.map((r) => [`${r.asset_type}:${r.asset_id}`, r]));

  const adjacency = new Map<string, Array<{ type: string; id: string; relation: string }>>();
  for (const dep of dependencies) {
    const key = `${dep.source_asset_type}:${dep.source_asset_id}`;
    const list = adjacency.get(key) ?? [];
    list.push({ type: dep.target_asset_type, id: dep.target_asset_id, relation: dep.relation });
    adjacency.set(key, list);
  }

  await query('DELETE FROM attack_paths');

  const results: AttackPath[] = [];
  const MAX_DEPTH = 4;

  for (const entry of services) {
    const entryKey = `${'service'}:${entry.id}`;
    const entryRisk = riskByAsset.get(entryKey);
    if (!entryRisk) continue; // only build paths from services that already carry risk

    const visited = new Set<string>([entryKey]);
    const hops: AttackPathHop[] = [];
    let frontier: Array<{ type: string; id: string }> = [{ type: 'service', id: entry.id }];
    let worstTarget: { type: string; id: string; severity: Severity } | null = null;
    let overallSeverity: Severity = entryRisk.severity;

    for (let depth = 0; depth < MAX_DEPTH && frontier.length > 0; depth++) {
      const next: Array<{ type: string; id: string }> = [];
      for (const node of frontier) {
        const edges = adjacency.get(`${node.type}:${node.id}`) ?? [];
        for (const edge of edges) {
          const edgeKey = `${edge.type}:${edge.id}`;
          if (visited.has(edgeKey)) continue;
          visited.add(edgeKey);
          hops.push({ asset_type: edge.type as AttackPathHop['asset_type'], asset_id: edge.id, via: edge.relation });
          next.push({ type: edge.type, id: edge.id });

          const targetRisk = riskByAsset.get(edgeKey);
          const targetCriticality = edge.type === 'host' ? hostById.get(edge.id)?.criticality : undefined;
          const targetSeverity = targetRisk?.severity ?? targetCriticality ?? 'low';
          overallSeverity = worseSeverity(overallSeverity, targetSeverity);

          if (!worstTarget || SEVERITY_ORDER.indexOf(targetSeverity) > SEVERITY_ORDER.indexOf(worstTarget.severity)) {
            worstTarget = { type: edge.type, id: edge.id, severity: targetSeverity };
          }
        }
      }
      frontier = next;
    }

    if (hops.length === 0) continue; // isolated exposed service, no lateral movement

    const target = worstTarget ?? { type: 'service', id: entry.id, severity: entryRisk.severity };
    const [row] = await query<AttackPath>(
      `INSERT INTO attack_paths (name, entry_asset_type, entry_asset_id, target_asset_type, target_asset_id, hops, blast_radius, severity)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [
        `Exposure via ${entry.name} -> ${target.type}`,
        'service',
        entry.id,
        target.type,
        target.id,
        JSON.stringify(hops),
        visited.size - 1,
        overallSeverity,
      ],
    );
    results.push(row);
  }

  return results;
}
