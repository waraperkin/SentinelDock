import { query } from '../db/pool.js';
import type { PolicyViolation, Risk, Severity, Host } from '../types/models.js';

const SEVERITY_WEIGHT: Record<Severity, number> = { low: 1, medium: 3, high: 6, critical: 10 };
const CRITICALITY_MULTIPLIER: Record<Severity, number> = { low: 1, medium: 1.2, high: 1.5, critical: 2 };

function categoryForPolicySeverity(details: Record<string, unknown>): Risk['category'] {
  if ('port' in details || 'bind_address' in details) return 'exposure';
  if ('image' in details) return 'misconfiguration';
  return 'misconfiguration';
}

/**
 * Recomputes Risk records by grouping open PolicyViolations per asset and
 * scoring them against asset criticality. Existing risks are replaced.
 */
export async function recomputeRisks(): Promise<Risk[]> {
  const violations = await query<PolicyViolation>("SELECT * FROM policy_violations WHERE status = 'open'");
  const hosts = await query<Host>('SELECT * FROM hosts');
  const hostById = new Map(hosts.map((h) => [h.id, h]));

  const grouped = new Map<string, PolicyViolation[]>();
  for (const v of violations) {
    const key = `${v.asset_type}:${v.asset_id}`;
    grouped.set(key, [...(grouped.get(key) ?? []), v]);
  }

  await query('DELETE FROM risks');

  const results: Risk[] = [];
  for (const [key, groupViolations] of grouped) {
    const [assetType, assetId] = key.split(':');
    const worstSeverity = groupViolations.reduce<Severity>((worst, v) => {
      return SEVERITY_WEIGHT[v.severity] > SEVERITY_WEIGHT[worst] ? v.severity : worst;
    }, 'low');

    const criticality: Severity = assetType === 'host' ? (hostById.get(assetId)?.criticality ?? 'medium') : 'medium';
    const baseScore = groupViolations.reduce((sum, v) => sum + SEVERITY_WEIGHT[v.severity], 0);
    const score = Math.min(100, baseScore * CRITICALITY_MULTIPLIER[criticality]);

    const category = categoryForPolicySeverity(groupViolations[0].details);
    const summary = `${groupViolations.length} open violation(s) on ${assetType} ${assetId}, worst severity ${worstSeverity}`;

    const [row] = await query<Risk>(
      `INSERT INTO risks (asset_type, asset_id, category, severity, score, summary, source_violation_ids)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [assetType, assetId, category, worstSeverity, score, summary, groupViolations.map((v) => v.id)],
    );
    results.push(row);
  }

  return results;
}

export async function globalRiskScore(): Promise<number> {
  const risks = await query<Risk>('SELECT score FROM risks');
  if (risks.length === 0) return 0;
  const total = risks.reduce((sum, r) => sum + Number(r.score), 0);
  return Math.round((total / risks.length) * 100) / 100;
}
