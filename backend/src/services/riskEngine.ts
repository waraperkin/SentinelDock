import { query } from '../db/pool.js';
import type { PolicyViolation, Risk, Severity, Host, ServiceRecord, SecretFinding } from '../types/models.js';

const SEVERITY_WEIGHT: Record<Severity, number> = { low: 1, medium: 3, high: 6, critical: 10 };
const CRITICALITY_MULTIPLIER: Record<Severity, number> = { low: 1, medium: 1.2, high: 1.5, critical: 2 };

export interface ViolationWithPolicyKey extends PolicyViolation {
  policy_key: string;
}

/**
 * Classifies a violation's risk category from the policy that triggered it.
 * Uses an explicit key->category map (rather than loose substring matching
 * on the key) to avoid false matches, e.g. "docker-socket-exposed"
 * incidentally containing the substring "os" from "exposed".
 */
const POLICY_KEY_CATEGORY: Record<string, Risk['category']> = {
  'ssh-exposed-public': 'exposure',
  'docker-socket-exposed': 'exposure',
  'database-publicly-reachable': 'exposure',
  'sensitive-ports-exposed-wan': 'exposure',
  'privileged-container': 'container',
  'outdated-os-critical-host': 'host',
  'ot-it-segmentation': 'network',
  'ics-protocol-exposed': 'ics',
  'cloud-metadata-reachable': 'cloud',
  'iam-privileged-role-exposed': 'cloud',
};

export function categoryForViolation(violation: ViolationWithPolicyKey): Risk['category'] {
  return POLICY_KEY_CATEGORY[violation.policy_key] ?? (violation.asset_type === 'container' ? 'container' : 'misconfiguration');
}

export function severityFromCvss(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/**
 * Recomputes Risk records from two independent signal sources — open
 * PolicyViolations (grouped per asset) and known-vulnerable service
 * versions (from the vulnerability scanner) — scored against asset
 * criticality. Existing risks are replaced on every run.
 */
export async function recomputeRisks(): Promise<Risk[]> {
  const violations = await query<ViolationWithPolicyKey>(
    `SELECT pv.*, p.key AS policy_key FROM policy_violations pv
     JOIN policies p ON p.id = pv.policy_id
     WHERE pv.status = 'open'`,
  );
  const hosts = await query<Host>('SELECT * FROM hosts');
  const hostById = new Map(hosts.map((h) => [h.id, h]));

  const grouped = new Map<string, ViolationWithPolicyKey[]>();
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

    const category = categoryForViolation(groupViolations[0]);
    const summary = `${groupViolations.length} open violation(s) on ${assetType} ${assetId}, worst severity ${worstSeverity}`;

    const [row] = await query<Risk>(
      `INSERT INTO risks (asset_type, asset_id, category, severity, score, summary, source_violation_ids)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [assetType, assetId, category, worstSeverity, score, summary, groupViolations.map((v) => v.id)],
    );
    results.push(row);
  }

  // Independent signal: known-vulnerable service versions, regardless of
  // whether a policy also flagged the same asset.
  const vulnerableServices = await query<ServiceRecord>('SELECT * FROM services WHERE array_length(cve_ids, 1) > 0');
  for (const service of vulnerableServices) {
    const severity = severityFromCvss(Number(service.cvss_score ?? 0));
    const criticality: Severity = 'medium';
    const score = Math.min(100, Number(service.cvss_score ?? 0) * 10 * CRITICALITY_MULTIPLIER[criticality]);
    const summary = `Service "${service.name}" (v${service.version ?? 'unknown'}) matches known vulnerabilities: ${service.cve_ids.join(', ')}`;

    const [row] = await query<Risk>(
      `INSERT INTO risks (asset_type, asset_id, category, severity, score, summary, source_violation_ids)
       VALUES ($1, $2, $3, $4, $5, $6, '{}') RETURNING *`,
      ['service', service.id, 'vulnerability', severity, score, summary],
    );
    results.push(row);
  }

  // Independent signal: detected secrets, grouped per asset. A single
  // exposed AWS access key or private key is critical on its own,
  // regardless of anything else found on that asset.
  const SECRET_SEVERITY_WEIGHT: Record<string, number> = { medium: 3, high: 6, critical: 10 };
  const secretFindings = await query<SecretFinding>('SELECT * FROM secrets_findings ORDER BY detected_at DESC');
  const secretsByAsset = new Map<string, SecretFinding[]>();
  for (const finding of secretFindings) {
    const key = `${finding.asset_type}:${finding.asset_id}`;
    secretsByAsset.set(key, [...(secretsByAsset.get(key) ?? []), finding]);
  }
  for (const [key, findings] of secretsByAsset) {
    const [assetType, assetId] = key.split(':');
    const worstSeverity = findings.reduce<Severity>((worst, f) => {
      return (SECRET_SEVERITY_WEIGHT[f.severity] ?? 0) > (SECRET_SEVERITY_WEIGHT[worst] ?? 0) ? f.severity : worst;
    }, 'medium');
    const score = Math.min(100, findings.reduce((sum, f) => sum + (SECRET_SEVERITY_WEIGHT[f.severity] ?? 3), 0) * 1.5);
    const kinds = Array.from(new Set(findings.map((f) => f.kind)));
    const summary = `${findings.length} potential secret(s) detected (${kinds.join(', ')})`;

    const [row] = await query<Risk>(
      `INSERT INTO risks (asset_type, asset_id, category, severity, score, summary, source_violation_ids)
       VALUES ($1, $2, $3, $4, $5, $6, '{}') RETURNING *`,
      [assetType, assetId, 'secrets', worstSeverity, score, summary],
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
