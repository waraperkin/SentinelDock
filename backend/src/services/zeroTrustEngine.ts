import { query } from '../db/pool.js';
import type { Host, NetworkSegment, Risk, XdrDetection, TiMatch, UebaAnomaly } from '../types/models.js';

export interface SegmentZeroTrustScore {
  segment_id: string;
  segment_name: string;
  zone: string;
  host_count: number;
  device_classes: string[];
  /** 0-100 score, higher is worse (more Zero Trust risk) — mirrors the Risk scoring convention used elsewhere in the platform. */
  score: number;
  critical_risk_count: number;
  /** GODMODE v2: live threat-signal count (XDR correlations + TI matches + recent UEBA anomalies) folded into this segment's score — what makes this "dynamic" rather than a static topology-only score. */
  dynamic_signal_count: number;
  reasons: string[];
}

const ZONE_TRUST_WEIGHT: Record<string, number> = { management: 5, internal: 20, dmz: 35, public: 50 };

/**
 * Scores each network segment's Zero Trust posture from signals already
 * collected elsewhere: device_class mixing within the segment (see
 * policyEngine's segment_has_mixed_device_classes), how exposed the
 * segment's declared zone is, how many critical-severity risks currently
 * attach to hosts in it, and (GODMODE v2, "dynamic segmentation") live
 * threat signals — XDR multi-source correlations, TI matches, and recent
 * UEBA anomalies on hosts in the segment — rather than only static
 * topology. This is a heuristic maturity indicator, not a certification
 * against any formal Zero Trust framework (e.g. NIST SP 800-207) — it
 * surfaces relative segmentation weaknesses across the fleet using only
 * data this platform actually has.
 */
export async function computeZeroTrustScores(): Promise<SegmentZeroTrustScore[]> {
  const segments = await query<NetworkSegment>('SELECT * FROM network_segments');
  const hosts = await query<Host>('SELECT * FROM hosts');
  const risks = await query<Risk>("SELECT * FROM risks WHERE asset_type = 'host' AND severity = 'critical'");
  const [xdrDetections, tiMatches, uebaAnomalies] = await Promise.all([
    query<XdrDetection>('SELECT * FROM xdr_detections'),
    query<TiMatch>('SELECT * FROM ti_matches'),
    query<UebaAnomaly>("SELECT * FROM ueba_anomalies WHERE detected_at > now() - interval '24 hours'"),
  ]);

  const criticalCountByHostId = new Map<string, number>();
  for (const risk of risks) {
    criticalCountByHostId.set(risk.asset_id, (criticalCountByHostId.get(risk.asset_id) ?? 0) + 1);
  }

  // Dynamic signals are keyed by host for UEBA (already host-scoped) and by
  // asset for XDR/TI (service/container/host) — resolved to a per-host
  // count below via each host's own id plus, for services/containers, we
  // conservatively only count signals directly on the host asset itself
  // (a service-level XDR hit already shows up in that service's own risk;
  // folding it into the segment score here would double-count against the
  // policy-violation-driven critical_risk_count above).
  const dynamicCountByHostId = new Map<string, number>();
  for (const d of xdrDetections) {
    if (d.asset_type !== 'host') continue;
    dynamicCountByHostId.set(d.asset_id, (dynamicCountByHostId.get(d.asset_id) ?? 0) + 1);
  }
  for (const m of tiMatches) {
    if (m.asset_type !== 'host') continue;
    dynamicCountByHostId.set(m.asset_id, (dynamicCountByHostId.get(m.asset_id) ?? 0) + 1);
  }
  for (const a of uebaAnomalies) {
    dynamicCountByHostId.set(a.host_id, (dynamicCountByHostId.get(a.host_id) ?? 0) + 1);
  }

  const hostsBySegment = new Map<string, Host[]>();
  for (const host of hosts) {
    if (!host.network_segment_id) continue;
    hostsBySegment.set(host.network_segment_id, [...(hostsBySegment.get(host.network_segment_id) ?? []), host]);
  }

  return segments.map((segment) => {
    const segmentHosts = hostsBySegment.get(segment.id) ?? [];
    const deviceClasses = Array.from(new Set(segmentHosts.map((h) => h.device_class)));
    const criticalRiskCount = segmentHosts.reduce((sum, h) => sum + (criticalCountByHostId.get(h.id) ?? 0), 0);

    const reasons: string[] = [];
    let score = ZONE_TRUST_WEIGHT[segment.zone] ?? 20;
    reasons.push(`Base exposure for zone "${segment.zone}": ${ZONE_TRUST_WEIGHT[segment.zone] ?? 20}`);

    if (deviceClasses.length > 1) {
      score += 30;
      reasons.push(`Mixed device classes in one segment (${deviceClasses.join(', ')}) — no identity-based isolation between trust domains`);
    }
    if (criticalRiskCount > 0) {
      const boost = Math.min(30, criticalRiskCount * 10);
      score += boost;
      reasons.push(`${criticalRiskCount} critical-severity risk(s) attached to host(s) in this segment`);
    }
    if (segmentHosts.some((h) => h.device_class === 'ics') && segment.zone !== 'management') {
      score += 15;
      reasons.push('ICS/OT host present outside a dedicated management/restricted zone');
    }

    const dynamicSignalCount = segmentHosts.reduce((sum, h) => sum + (dynamicCountByHostId.get(h.id) ?? 0), 0);
    if (dynamicSignalCount > 0) {
      const boost = Math.min(25, dynamicSignalCount * 8);
      score += boost;
      reasons.push(`${dynamicSignalCount} live threat signal(s) (XDR correlation/TI match/recent UEBA anomaly) on host(s) in this segment — dynamic segmentation signal, not static topology`);
    }

    return {
      segment_id: segment.id,
      segment_name: segment.name,
      dynamic_signal_count: dynamicSignalCount,
      zone: segment.zone,
      host_count: segmentHosts.length,
      device_classes: deviceClasses,
      score: Math.min(100, Math.round(score)),
      critical_risk_count: criticalRiskCount,
      reasons,
    };
  });
}
