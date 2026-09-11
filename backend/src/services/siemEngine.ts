import { query } from '../db/pool.js';
import type { Risk, PolicyViolation, SecretFinding, TiMatch, UebaAnomaly, EdrDetection, TimelineEvent, AssetType, Severity } from '../types/models.js';

/**
 * TITAN tier: SIEM-lite — a correlated timeline over signals this
 * platform already collects (risks, policy violations, secrets findings,
 * TI matches, UEBA anomalies, EDR detections). This is NOT a general-
 * purpose log SIEM (no raw log ingestion/parsing pipeline) — it is
 * event correlation over SentinelDock's own structured detection tables,
 * which is what "SIEM-lite" honestly means here.
 *
 * Correlation: events are grouped into a `cluster_id` when they share the
 * same asset and occur within CLUSTER_WINDOW_MINUTES of each other,
 * surfacing "this asset had N things happen around the same time" instead
 * of just a flat chronological list.
 */

const CLUSTER_WINDOW_MINUTES = 10;

export async function getCorrelatedTimeline(limit = 200): Promise<TimelineEvent[]> {
  const [risks, violations, secrets, ti, ueba, edr] = await Promise.all([
    query<Risk>('SELECT * FROM risks ORDER BY updated_at DESC LIMIT $1', [limit]),
    query<PolicyViolation>("SELECT * FROM policy_violations WHERE status = 'open' ORDER BY detected_at DESC LIMIT $1", [limit]),
    query<SecretFinding>('SELECT * FROM secrets_findings ORDER BY detected_at DESC LIMIT $1', [limit]),
    query<TiMatch>('SELECT * FROM ti_matches ORDER BY detected_at DESC LIMIT $1', [limit]),
    query<UebaAnomaly>('SELECT * FROM ueba_anomalies ORDER BY detected_at DESC LIMIT $1', [limit]),
    query<EdrDetection>('SELECT * FROM edr_detections ORDER BY detected_at DESC LIMIT $1', [limit]),
  ]);

  type RawEvent = { id: string; source: TimelineEvent['source']; asset_type: AssetType; asset_id: string; severity: Severity; summary: string; occurred_at: string };

  const raw: RawEvent[] = [
    ...risks.map((r) => ({ id: r.id, source: 'risk' as const, asset_type: r.asset_type, asset_id: r.asset_id, severity: r.severity, summary: r.summary, occurred_at: r.updated_at })),
    ...violations.map((v) => ({ id: v.id, source: 'violation' as const, asset_type: v.asset_type, asset_id: v.asset_id, severity: v.severity, summary: `Policy violation detected (${v.details && 'name' in v.details ? (v.details as { name?: string }).name : v.asset_type})`, occurred_at: v.detected_at })),
    ...secrets.map((s) => ({ id: s.id, source: 'secret' as const, asset_type: s.asset_type, asset_id: s.asset_id, severity: s.severity, summary: `Secret detected: ${s.kind}`, occurred_at: s.detected_at })),
    ...ti.map((t) => ({ id: t.id, source: 'ti' as const, asset_type: t.asset_type, asset_id: t.asset_id, severity: t.severity, summary: t.label, occurred_at: t.detected_at })),
    ...ueba.map((u) => ({ id: u.id, source: 'ueba' as const, asset_type: 'host' as AssetType, asset_id: u.host_id, severity: u.severity, summary: `UEBA anomaly: ${u.kind}`, occurred_at: u.detected_at })),
    ...edr.map((e) => ({ id: e.id, source: 'edr' as const, asset_type: e.asset_type, asset_id: e.asset_id, severity: e.severity, summary: `EDR detection: ${e.kind}`, occurred_at: e.detected_at })),
  ];

  raw.sort((a, b) => new Date(b.occurred_at).getTime() - new Date(a.occurred_at).getTime());

  // Cluster consecutive-in-time events that share the same asset.
  const clusterKeyByAsset = new Map<string, { clusterId: string; lastSeenMs: number }>();
  const windowMs = CLUSTER_WINDOW_MINUTES * 60_000;

  const events: TimelineEvent[] = raw.map((e) => {
    const assetKey = `${e.asset_type}:${e.asset_id}`;
    const occurredMs = new Date(e.occurred_at).getTime();
    const existing = clusterKeyByAsset.get(assetKey);
    let clusterId: string;
    if (existing && existing.lastSeenMs - occurredMs <= windowMs) {
      clusterId = existing.clusterId;
    } else {
      clusterId = `${assetKey}:${e.id}`;
    }
    clusterKeyByAsset.set(assetKey, { clusterId, lastSeenMs: occurredMs });
    return { ...e, cluster_id: clusterId };
  });

  return events.slice(0, limit);
}
