import { query } from '../db/pool.js';
import type { PolicyViolation, Risk, Severity, Host, ServiceRecord, SecretFinding } from '../types/models.js';
import { isKnownExploited } from './vulnerabilityScanner.js';
import { worseSeverity } from './attackPathEngine.js';

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
  'devops-cicd-exposed': 'devops',
  'git-repository-exposed': 'devops',
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
  // whether a policy also flagged the same asset. Exploit maturity (a
  // KEV-style "known exploited" flag) boosts the score beyond what raw
  // CVSS alone would give — a widely-exploited medium-CVSS bug is a more
  // urgent real-world risk than an unexploited high-CVSS one.
  const vulnerableServices = await query<ServiceRecord>('SELECT * FROM services WHERE array_length(cve_ids, 1) > 0');
  const vulnerableHostGroups = new Map<string, ServiceRecord[]>();
  for (const service of vulnerableServices) {
    const exploited = isKnownExploited(service.cve_ids);
    const baseSeverity = severityFromCvss(Number(service.cvss_score ?? 0));
    const severity = exploited ? worseSeverity(baseSeverity, 'high') : baseSeverity;
    const exploitBoost = exploited ? 1.4 : 1.0;
    const score = Math.min(100, Number(service.cvss_score ?? 0) * 10 * CRITICALITY_MULTIPLIER.medium * exploitBoost);
    const summary = `Service "${service.name}" (v${service.version ?? 'unknown'}) matches known vulnerabilities: ${service.cve_ids.join(', ')}${
      exploited ? ' — actively exploited in the wild' : ''
    }`;

    const [row] = await query<Risk>(
      `INSERT INTO risks (asset_type, asset_id, category, severity, score, summary, source_violation_ids)
       VALUES ($1, $2, $3, $4, $5, $6, '{}') RETURNING *`,
      ['service', service.id, 'vulnerability', severity, score, summary],
    );
    results.push(row);

    if (service.host_id) vulnerableHostGroups.set(service.host_id, [...(vulnerableHostGroups.get(service.host_id) ?? []), service]);
  }

  // CVE chaining / multi-hop exposure: a host running 2+ independently
  // vulnerable services is a materially different (higher) risk than the
  // sum of its parts — an attacker can chain footholds across services on
  // the same host without needing to pivot through the network at all.
  for (const [hostId, servicesOnHost] of vulnerableHostGroups) {
    if (servicesOnHost.length < 2) continue;
    const allCveIds = servicesOnHost.flatMap((s) => s.cve_ids);
    const criticality = hostById.get(hostId)?.criticality ?? 'medium';
    const score = Math.min(100, 40 + servicesOnHost.length * 15 * CRITICALITY_MULTIPLIER[criticality]);
    const summary = `${servicesOnHost.length} independently vulnerable services chainable on this host (${servicesOnHost.map((s) => s.name).join(', ')}) — combined CVEs: ${allCveIds.join(', ')}`;
    const [row] = await query<Risk>(
      `INSERT INTO risks (asset_type, asset_id, category, severity, score, summary, source_violation_ids)
       VALUES ($1, $2, $3, $4, $5, $6, '{}') RETURNING *`,
      ['host', hostId, 'vulnerability', 'critical', score, summary],
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

  // Independent signal: IAM role naming heuristic — a role/service-account
  // name containing "admin", "root", or "full-access" strongly suggests
  // overprivileged access, which is a much stronger signal than "metadata
  // was merely reachable" (the existing iam-privileged-role-exposed
  // policy). This never inspects actual IAM policy documents (no live
  // cloud API calls) — purely a naming-convention heuristic on the role
  // name the worker already enumerated read-only from the metadata service.
  const OVERPRIVILEGED_NAME_PATTERN = /admin|root|full[-_]?access|superuser|owner/i;
  const iamSnapshots = await query<{ asset_id: string; data: { role_name?: string; provider?: string } }>(
    "SELECT asset_id, data FROM config_snapshots WHERE kind = 'cloud-iam'",
  );
  for (const snapshot of iamSnapshots) {
    const roleName = snapshot.data.role_name;
    if (!roleName || !OVERPRIVILEGED_NAME_PATTERN.test(roleName)) continue;
    const summary = `IAM role/service account "${roleName}" (${snapshot.data.provider ?? 'cloud'}) is named as if it holds broad/administrative privileges — reachable via the instance metadata service`;
    const [row] = await query<Risk>(
      `INSERT INTO risks (asset_type, asset_id, category, severity, score, summary, source_violation_ids)
       VALUES ($1, $2, $3, $4, $5, $6, '{}') RETURNING *`,
      ['host', snapshot.asset_id, 'cloud', 'critical', 85, summary],
    );
    results.push(row);
  }

  // Independent signal: ICS write-risk heuristics submitted by the worker
  // (see icsScanner.ts) — a device that answered a standard read request
  // unauthenticated on an OT protocol is scored as high risk even though
  // no write was ever actually attempted against it.
  const writeRiskSnapshots = await query<{ asset_id: string; data: { protocol_family?: string } }>(
    "SELECT asset_id, data FROM config_snapshots WHERE kind = 'ics-write-risk'",
  );
  for (const snapshot of writeRiskSnapshots) {
    const summary = `Service accepts unauthenticated ${snapshot.data.protocol_family ?? 'ICS'} reads and likely also accepts writes (Modbus FC5/FC6, BACnet WriteProperty) — no write was actually sent, this is a heuristic based on the absence of read-side access control`;
    const [row] = await query<Risk>(
      `INSERT INTO risks (asset_type, asset_id, category, severity, score, summary, source_violation_ids)
       VALUES ($1, $2, $3, $4, $5, $6, '{}') RETURNING *`,
      ['service', snapshot.asset_id, 'ics', 'high', 65, summary],
    );
    results.push(row);
  }

  // Supply-chain risk: a host running CI/CD tooling (protocol_family
  // 'devops', e.g. Jenkins or an exposed .git) that ALSO has a detected
  // secret finding on the same host is a materially worse combination
  // than either alone — an attacker with pipeline access plus a leaked
  // credential can move straight to deploying malicious artifacts
  // downstream, mirroring real supply-chain compromises (e.g. SolarWinds-
  // style build-system tampering).
  const devopsServices = await query<ServiceRecord>("SELECT * FROM services WHERE protocol_family = 'devops'");
  const devopsHostIds = new Set(devopsServices.map((s) => s.host_id).filter((id): id is string => Boolean(id)));
  if (devopsHostIds.size > 0) {
    const secretsOnDevopsHosts = await query<SecretFinding>(
      `SELECT * FROM secrets_findings WHERE asset_type = 'host' AND asset_id = ANY($1::uuid[])`,
      [Array.from(devopsHostIds)],
    );
    const secretsByHost = new Map<string, SecretFinding[]>();
    for (const finding of secretsOnDevopsHosts) {
      secretsByHost.set(finding.asset_id, [...(secretsByHost.get(finding.asset_id) ?? []), finding]);
    }
    for (const [hostId, findings] of secretsByHost) {
      const criticality = hostById.get(hostId)?.criticality ?? 'medium';
      const score = Math.min(100, 55 + findings.length * 10 * CRITICALITY_MULTIPLIER[criticality]);
      const summary = `Supply-chain exposure: CI/CD tooling and ${findings.length} detected secret(s) coexist on the same host — pipeline compromise could chain directly into credential theft and malicious deployment`;
      const [row] = await query<Risk>(
        `INSERT INTO risks (asset_type, asset_id, category, severity, score, summary, source_violation_ids)
         VALUES ($1, $2, $3, $4, $5, $6, '{}') RETURNING *`,
        ['host', hostId, 'devops', 'critical', score, summary],
      );
      results.push(row);
    }
  }

  return results;
}

export async function globalRiskScore(): Promise<number> {
  const risks = await query<Risk>('SELECT score FROM risks');
  if (risks.length === 0) return 0;
  const total = risks.reduce((sum, r) => sum + Number(r.score), 0);
  return Math.round((total / risks.length) * 100) / 100;
}
