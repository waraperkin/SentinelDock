import { query } from '../db/pool.js';
import type { Risk, HardeningRecommendation, XdrDetection, RemediationPlan, Severity } from '../types/models.js';

/**
 * GODMODE tier: Auto-Remediation Engine — advanced recommendations only,
 * never an auto-apply/auto-fix system. Builds on hardeningEngine.ts's
 * single-action recommendations by turning each open risk into a
 * PRIORITIZED, ordered remediation plan (a small runbook: the concrete
 * fix, then verify, then monitor), so an operator can triage "what do I
 * work on first" instead of facing an undifferentiated list of risks.
 */

const SEVERITY_WEIGHT: Record<Severity, number> = { low: 1, medium: 3, high: 6, critical: 10 };

export async function generateRemediationPlans(): Promise<RemediationPlan[]> {
  const risks = await query<Risk>('SELECT * FROM risks');
  const hardening = await query<HardeningRecommendation>("SELECT * FROM hardening_recommendations WHERE status = 'open'");
  const xdr = await query<XdrDetection>('SELECT * FROM xdr_detections');

  const hardeningByRiskId = new Map(hardening.filter((h) => h.risk_id).map((h) => [h.risk_id as string, h]));
  const xdrByAsset = new Map(xdr.map((d) => [`${d.asset_type}:${d.asset_id}`, d]));

  await query("DELETE FROM remediation_plans WHERE status = 'open'");
  const results: RemediationPlan[] = [];

  for (const risk of risks) {
    const action = hardeningByRiskId.get(risk.id);
    if (!action) continue; // no concrete remediation template exists for this risk — do not fabricate generic advice

    const xdrHit = xdrByAsset.get(`${risk.asset_type}:${risk.asset_id}`);
    let priority = SEVERITY_WEIGHT[risk.severity] * 10;
    if (xdrHit) priority += 25; // multi-source-correlated risks jump the queue
    if (risk.category === 'threat-intel') priority += 15;

    const steps = [
      action.action,
      `Verify the fix: re-run policy evaluation and confirm the "${risk.category}" risk on this asset clears.`,
      xdrHit
        ? `This asset was cross-source correlated (${xdrHit.sources.join(', ')}) — after remediating, watch the SIEM-lite timeline for continued activity before closing the incident.`
        : `Monitor this asset for ${risk.category === 'anomaly' || risk.category === 'behavioral' ? 'recurrence of the same behavioral pattern' : 'reintroduction of this condition'} in the next few evaluation cycles.`,
    ];

    const [row] = await query<RemediationPlan>(
      `INSERT INTO remediation_plans (asset_type, asset_id, risk_id, priority, title, steps, severity)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [risk.asset_type, risk.asset_id, risk.id, priority, `Remediate: ${risk.summary.slice(0, 120)}`, JSON.stringify(steps), risk.severity],
    );
    results.push(row);
  }

  return results.sort((a, b) => b.priority - a.priority);
}
