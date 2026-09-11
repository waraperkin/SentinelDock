import { query } from '../db/pool.js';
import type { AttackPath, SimulationCampaign } from '../types/models.js';
import { simulateAttackPath } from './sandboxEngine.js';

/**
 * GODMODE+ tier: Attack Simulation Engine — a full multi-domain
 * simulation campaign. This does NOT introduce a new simulation
 * mechanism: it batches the existing Network Sandbox Engine
 * (`simulateAttackPath` in sandboxEngine.ts, itself non-destructive pure
 * computation) across EVERY currently-persisted AttackPath in one run,
 * covering whatever domains those paths actually span (network, ICS/OT,
 * cloud, DevOps — via the multi-layer graph's `layer` classification),
 * and aggregates the results into one fleet-wide exposure summary rather
 * than requiring an operator to simulate each path one at a time.
 */
export async function runSimulationCampaign(): Promise<SimulationCampaign | null> {
  const paths = await query<AttackPath>('SELECT * FROM attack_paths');
  if (paths.length === 0) return null;

  const simulationIds: string[] = [];
  let totalProbability = 0;
  let maxProbability = -1;
  let worstAttackPathId: string | null = null;

  for (const path of paths) {
    const simulation = await simulateAttackPath(path.id);
    if (!simulation) continue;
    // node-postgres returns NUMERIC columns as strings (to avoid silent
    // precision loss) — simulation.overall_success_probability comes back
    // from a RETURNING * clause, so it must be coerced before arithmetic,
    // or `total += stringValue` silently does string concatenation instead
    // of addition and the eventual division produces NaN.
    const probability = Number(simulation.overall_success_probability);
    simulationIds.push(simulation.id);
    totalProbability += probability;
    if (probability > maxProbability) {
      maxProbability = probability;
      worstAttackPathId = path.id;
    }
  }

  if (simulationIds.length === 0) return null;
  const avgProbability = totalProbability / simulationIds.length;

  const [row] = await query<SimulationCampaign>(
    `INSERT INTO simulation_campaigns (path_count, avg_success_probability, max_success_probability, worst_attack_path_id, simulation_ids)
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [simulationIds.length, Math.round(avgProbability * 100000) / 100000, Math.round(maxProbability * 100000) / 100000, worstAttackPathId, simulationIds],
  );
  return row;
}

export async function listSimulationCampaigns(): Promise<SimulationCampaign[]> {
  return query<SimulationCampaign>('SELECT * FROM simulation_campaigns ORDER BY created_at DESC LIMIT 100');
}
