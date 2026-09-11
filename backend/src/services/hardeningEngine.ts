import { query } from '../db/pool.js';
import type { Risk, HardeningRecommendation } from '../types/models.js';

/**
 * TITAN tier: Auto-Hardening Engine. Produces RECOMMENDATIONS only — it
 * never changes any asset's configuration. Maps each open risk's category
 * (and, when available, the underlying policy key) to a concrete,
 * actionable hardening step, rather than leaving the operator to derive
 * "what do I actually do about this" from a risk score alone.
 */

const ACTION_BY_POLICY_KEY: Record<string, string> = {
  'ssh-exposed-public': 'Restrict SSH to a VPN/bastion-only network path; disable password auth and enforce key-based auth.',
  'docker-socket-exposed': 'Remove public exposure of the Docker Engine API; if remote access is required, front it with TLS client-cert auth.',
  'database-publicly-reachable': 'Move the database off any publicly-routable address; restrict access to application-tier hosts via security group/firewall rules.',
  'sensitive-ports-exposed-wan': 'Close or firewall this port from WAN access; expose only through a reverse proxy or VPN.',
  'privileged-container': 'Remove the --privileged flag; grant only the specific Linux capabilities the workload actually needs.',
  'outdated-os-critical-host': 'Patch the OS to a current supported release; schedule regular patch cadence for critical-criticality hosts.',
  'ot-it-segmentation': 'Move this OT/ICS host to a dedicated segment with a firewall or data diode enforcing filtered IT/OT traffic.',
  'ics-protocol-exposed': 'Restrict ICS protocol access (Modbus/S7/BACnet/OPC-UA) to an engineering workstation subnet only; never expose to general IT.',
  'cloud-metadata-reachable': 'Block outbound access to 169.254.169.254 / metadata.google.internal from application code paths not requiring it (e.g. via a network policy or proxy allowlist), to reduce SSRF blast radius.',
  'iam-privileged-role-exposed': 'Review the attached IAM role for least-privilege; split any broad role into narrowly-scoped ones per workload.',
  'devops-cicd-exposed': 'Restrict CI/CD tooling to an internal network or VPN-only access; rotate pipeline credentials if exposure was ever externally reachable.',
  'git-repository-exposed': 'Remove .git from the web root or block dotfile access; rotate any credentials ever committed.',
  'cloud-onprem-mixed-segment': 'Place cloud-connected assets on a dedicated segment/VPC separate from on-prem IT and ICS/OT segments.',
  'critical-host-flat-network': 'Move this critical host to a dedicated management/restricted segment with explicit firewall rules.',
};

const ACTION_BY_CATEGORY: Record<string, string> = {
  vulnerability: 'Patch the affected service to a version without the listed CVE(s), or remove/replace the service if patching is not available.',
  secrets: 'Rotate the exposed credential immediately and remove it from the source (env var, config file, or committed history).',
  ics: 'Restrict this ICS/OT service to a dedicated engineering-workstation network path; if write-risk was flagged, verify no unauthenticated write access is actually possible.',
  cloud: 'Review the associated IAM role/service account for least-privilege and restrict metadata service reachability where feasible.',
  devops: 'Isolate CI/CD tooling from general network access and rotate any credentials it holds if a secret was found alongside it.',
  'threat-intel': 'Treat this as a priority incident candidate — the match corresponds to a known-malicious pattern or an actively-campaigned CVE, not a generic weakness.',
  anomaly: 'Investigate the flagged host for unauthorized changes; confirm the new port/service was an intentional, approved change.',
  behavioral: 'Investigate the flagged asset for compromise; isolate it from the network if the detection cannot be immediately explained as legitimate.',
};

interface RiskWithPolicyKeys extends Risk {
  policy_keys: string[] | null;
}

/**
 * Regenerates hardening_recommendations from all currently open risks.
 * Clears previously auto-generated open recommendations first (same
 * idempotent-regeneration pattern as segmentationEngine), leaving any
 * human-actioned (applied/dismissed) rows untouched.
 */
export async function generateHardeningRecommendations(): Promise<HardeningRecommendation[]> {
  const risks = await query<RiskWithPolicyKeys>(
    `SELECT r.*, ARRAY(
       SELECT p.key FROM policy_violations pv
       JOIN policies p ON p.id = pv.policy_id
       WHERE pv.id = ANY(r.source_violation_ids)
     ) AS policy_keys
     FROM risks r`,
  );

  await query("DELETE FROM hardening_recommendations WHERE status = 'open'");

  const results: HardeningRecommendation[] = [];
  for (const risk of risks) {
    const policyAction = (risk.policy_keys ?? []).map((key) => ACTION_BY_POLICY_KEY[key]).find(Boolean);
    const action = policyAction ?? ACTION_BY_CATEGORY[risk.category];
    if (!action) continue; // no actionable template for this category — do not fabricate generic advice

    const [row] = await query<HardeningRecommendation>(
      `INSERT INTO hardening_recommendations (asset_type, asset_id, risk_id, action, rationale, severity)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [risk.asset_type, risk.asset_id, risk.id, action, risk.summary, risk.severity],
    );
    results.push(row);
  }

  return results;
}
