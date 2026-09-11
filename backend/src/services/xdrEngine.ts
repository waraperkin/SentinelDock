import { query } from '../db/pool.js';
import type { TiMatch, EdrDetection, UebaAnomaly, PolicyViolation, XdrDetection, Severity } from '../types/models.js';

/**
 * GODMODE tier: XDR-lite — multi-source correlation. The value XDR adds
 * over any single detection engine is confidence: an asset flagged by
 * only one source (say, one open policy violation) is common and often
 * low-signal; an asset flagged by TWO OR MORE independent sources (TI +
 * EDR, or UEBA + an open violation) is a much stronger, correlated
 * indicator. This engine only emits a row when an asset crosses that
 * >=2-source threshold — it does not duplicate what TI/EDR/UEBA/risk
 * already report individually, it adds the cross-source view on top.
 */

const SEVERITY_WEIGHT: Record<Severity, number> = { low: 1, medium: 3, high: 6, critical: 10 };

export async function computeXdrDetections(): Promise<XdrDetection[]> {
  const [ti, edr, ueba, violations] = await Promise.all([
    query<TiMatch>('SELECT * FROM ti_matches'),
    query<EdrDetection>('SELECT * FROM edr_detections'),
    query<UebaAnomaly>("SELECT * FROM ueba_anomalies WHERE detected_at > now() - interval '24 hours'"),
    query<PolicyViolation>("SELECT * FROM policy_violations WHERE status = 'open'"),
  ]);

  type Contribution = { source: string; severity: Severity };
  const bySource = new Map<string, Contribution[]>();
  const add = (assetType: string, assetId: string, source: string, severity: Severity) => {
    const key = `${assetType}:${assetId}`;
    bySource.set(key, [...(bySource.get(key) ?? []), { source, severity }]);
  };

  for (const m of ti) add(m.asset_type, m.asset_id, 'ti', m.severity);
  for (const d of edr) add(d.asset_type, d.asset_id, 'edr', d.severity);
  for (const a of ueba) add('host', a.host_id, 'ueba', a.severity);
  for (const v of violations) add(v.asset_type, v.asset_id, 'violation', v.severity);

  await query('DELETE FROM xdr_detections');
  const results: XdrDetection[] = [];

  for (const [key, contributions] of bySource) {
    const distinctSources = Array.from(new Set(contributions.map((c) => c.source)));
    if (distinctSources.length < 2) continue; // single-source: not a correlation, leave it to the originating engine's own view

    const [assetType, assetId] = key.split(':');
    const worstSeverity = contributions.reduce<Severity>((worst, c) => (SEVERITY_WEIGHT[c.severity] > SEVERITY_WEIGHT[worst] ? c.severity : worst), 'low');
    const severity: Severity = distinctSources.length >= 3 ? 'critical' : worstSeverity === 'critical' ? 'critical' : 'high';
    const compositeScore = Math.min(100, distinctSources.length * 25 + contributions.reduce((sum, c) => sum + SEVERITY_WEIGHT[c.severity], 0) * 2);
    const summary = `${distinctSources.length} independent detection sources correlated on this asset (${distinctSources.join(', ')}) — higher-confidence than any single source alone`;

    const [row] = await query<XdrDetection>(
      `INSERT INTO xdr_detections (asset_type, asset_id, sources, composite_score, severity, summary)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [assetType, assetId, distinctSources, compositeScore, severity, summary],
    );
    results.push(row);
  }

  return results;
}
