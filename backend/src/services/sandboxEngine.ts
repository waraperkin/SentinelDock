import { query, queryOne } from '../db/pool.js';
import type { AttackPath, AttackPathHop, ServiceRecord, SandboxSimulation, SandboxSimulationStep } from '../types/models.js';
import { matchService } from './vulnerabilityScanner.js';

/**
 * GODMODE tier: Network Sandbox Engine — a NON-DESTRUCTIVE attack
 * simulation. This never sends a single real network packet: it replays
 * an already-computed AttackPath (see attackPathEngine.ts) and estimates,
 * hop by hop, how likely a real attacker would be to succeed at that step,
 * using only data this platform already collected (CVE exploitability,
 * TI matches, ICS write-risk heuristics). It is pure arithmetic over
 * existing rows — safe to run against a production inventory at any time.
 */

const DEFAULT_HOP_PROBABILITY = 0.55; // generic lateral-move step (host pivot, container escape) with no stronger specific signal
const MIN_CHAIN_PROBABILITY = 0.03; // below this, the simulated attacker is modeled as giving up rather than continuing indefinitely

/** Estimates how likely a single hop is to succeed, in [0,1], from the strongest applicable signal for that hop's target asset. */
async function hopSuccessProbability(hop: { asset_type: string; asset_id: string }): Promise<number> {
  if (hop.asset_type === 'service') {
    const service = await queryOne<ServiceRecord>('SELECT * FROM services WHERE id = $1', [hop.asset_id]);
    if (service) {
      const match = matchService(service);
      if (match) return Math.min(1, match.exploitability / 10);

      const tiHit = await queryOne<{ severity: string }>(
        "SELECT severity FROM ti_matches WHERE asset_type = 'service' AND asset_id = $1 ORDER BY severity DESC LIMIT 1",
        [hop.asset_id],
      );
      if (tiHit) return tiHit.severity === 'critical' ? 0.9 : tiHit.severity === 'high' ? 0.75 : 0.6;

      const writeRisk = await queryOne<{ id: string }>("SELECT id FROM config_snapshots WHERE kind = 'ics-write-risk' AND asset_id = $1", [hop.asset_id]);
      if (writeRisk) return 0.7;
    }
  }
  return DEFAULT_HOP_PROBABILITY;
}

/**
 * Simulates traversal of a persisted AttackPath: at each hop, computes the
 * step's success probability, multiplies it into a running chain
 * probability (an attacker must succeed at every step to reach the next),
 * and models the attacker abandoning the chain once the cumulative
 * probability drops below MIN_CHAIN_PROBABILITY. Persists the run
 * (append-only — a history of simulations is useful for tracking whether
 * posture is improving over time) and returns it.
 */
export async function simulateAttackPath(attackPathId: string): Promise<SandboxSimulation | null> {
  const path = await queryOne<AttackPath>('SELECT * FROM attack_paths WHERE id = $1', [attackPathId]);
  if (!path) return null;

  const steps: SandboxSimulationStep[] = [];
  let cumulative = 1;

  for (const [index, hop] of (path.hops as AttackPathHop[]).entries()) {
    if (cumulative < MIN_CHAIN_PROBABILITY) break;
    const probability = await hopSuccessProbability(hop);
    cumulative *= probability;
    steps.push({
      hop_index: index,
      asset_type: hop.asset_type,
      asset_id: hop.asset_id,
      via: hop.via,
      success_probability: Math.round(probability * 10000) / 10000,
      cumulative_probability: Math.round(cumulative * 10000) / 10000,
      compromised: cumulative >= MIN_CHAIN_PROBABILITY,
    });
  }

  const hopsCompromised = steps.filter((s) => s.compromised).length;
  const [row] = await query<SandboxSimulation>(
    `INSERT INTO sandbox_simulations (attack_path_id, steps, overall_success_probability, hops_compromised)
     VALUES ($1, $2, $3, $4) RETURNING *`,
    [attackPathId, JSON.stringify(steps), Math.round(cumulative * 10000) / 10000, hopsCompromised],
  );
  return row;
}

export async function listSandboxSimulations(attackPathId?: string): Promise<SandboxSimulation[]> {
  if (attackPathId) return query<SandboxSimulation>('SELECT * FROM sandbox_simulations WHERE attack_path_id = $1 ORDER BY created_at DESC', [attackPathId]);
  return query<SandboxSimulation>('SELECT * FROM sandbox_simulations ORDER BY created_at DESC LIMIT 200');
}
