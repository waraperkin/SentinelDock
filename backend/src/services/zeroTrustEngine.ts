import { query } from '../db/pool.js';
import type { Host, NetworkSegment, Risk } from '../types/models.js';

export interface SegmentZeroTrustScore {
  segment_id: string;
  segment_name: string;
  zone: string;
  host_count: number;
  device_classes: string[];
  /** 0-100 score, higher is worse (more Zero Trust risk) — mirrors the Risk scoring convention used elsewhere in the platform. */
  score: number;
  critical_risk_count: number;
  reasons: string[];
}

const ZONE_TRUST_WEIGHT: Record<string, number> = { management: 5, internal: 20, dmz: 35, public: 50 };

/**
 * Scores each network segment's Zero Trust posture from signals already
 * collected elsewhere: device_class mixing within the segment (see
 * policyEngine's segment_has_mixed_device_classes), how exposed the
 * segment's declared zone is, and how many critical-severity risks
 * currently attach to hosts in it. This is a heuristic maturity indicator,
 * not a certification against any formal Zero Trust framework (e.g.
 * NIST SP 800-207) — it surfaces relative segmentation weaknesses across
 * the fleet using only data this platform actually has.
 */
export async function computeZeroTrustScores(): Promise<SegmentZeroTrustScore[]> {
  const segments = await query<NetworkSegment>('SELECT * FROM network_segments');
  const hosts = await query<Host>('SELECT * FROM hosts');
  const risks = await query<Risk>("SELECT * FROM risks WHERE asset_type = 'host' AND severity = 'critical'");

  const criticalCountByHostId = new Map<string, number>();
  for (const risk of risks) {
    criticalCountByHostId.set(risk.asset_id, (criticalCountByHostId.get(risk.asset_id) ?? 0) + 1);
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

    return {
      segment_id: segment.id,
      segment_name: segment.name,
      zone: segment.zone,
      host_count: segmentHosts.length,
      device_classes: deviceClasses,
      score: Math.min(100, Math.round(score)),
      critical_risk_count: criticalRiskCount,
      reasons,
    };
  });
}
