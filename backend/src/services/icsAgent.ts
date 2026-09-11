import { query } from '../db/pool.js';
import type { Host, NetworkSegment, IcsPosture } from '../types/models.js';

/**
 * GODMODE tier: ICSMASTER — the ICS Agent. Aggregates ICS/OT signals
 * already collected (device role classification, the Modbus/BACnet
 * write-risk heuristic, network placement) into a per-segment posture
 * score. No new protocol probing of its own — it reads what the worker's
 * icsScanner.ts already discovered.
 */
export async function computeIcsPosture(): Promise<IcsPosture[]> {
  const icsHosts = await query<Host>("SELECT * FROM hosts WHERE device_class = 'ics'");
  const segments = await query<NetworkSegment>('SELECT * FROM network_segments');
  const segmentById = new Map(segments.map((s) => [s.id, s]));

  const writeRiskSnapshots = await query<{ asset_id: string; data: { host_id?: string } }>("SELECT asset_id, data FROM config_snapshots WHERE kind = 'ics-write-risk'");
  const writeRiskHostIds = new Set(writeRiskSnapshots.map((s) => s.data.host_id).filter((id): id is string => Boolean(id)));

  // A "gateway" is an ICS host whose role was classified as such by
  // classifyIcsDevice() on the worker (multiple distinct ICS protocol
  // families on one device) — read back from the stored role string.
  const gatewayHostIds = new Set(icsHosts.filter((h) => h.role === 'gateway').map((h) => h.id));

  const hostsBySegment = new Map<string, Host[]>();
  const unassigned: Host[] = [];
  for (const host of icsHosts) {
    if (!host.network_segment_id) {
      unassigned.push(host);
      continue;
    }
    hostsBySegment.set(host.network_segment_id, [...(hostsBySegment.get(host.network_segment_id) ?? []), host]);
  }

  await query('DELETE FROM ics_posture');
  const results: IcsPosture[] = [];

  const scoreFor = (segmentHosts: Host[], outsideManagement: boolean) => {
    const writeRiskCount = segmentHosts.filter((h) => writeRiskHostIds.has(h.id)).length;
    const gatewayCount = segmentHosts.filter((h) => gatewayHostIds.has(h.id)).length;
    const score = Math.min(100, segmentHosts.length * 8 + writeRiskCount * 20 + gatewayCount * 10 + (outsideManagement ? 25 : 0));
    return { writeRiskCount, gatewayCount, score };
  };

  for (const [segmentId, segmentHosts] of hostsBySegment) {
    const segment = segmentById.get(segmentId);
    const outsideManagement = segment ? segment.zone !== 'management' : true;
    const { writeRiskCount, gatewayCount, score } = scoreFor(segmentHosts, outsideManagement);
    const [row] = await query<IcsPosture>(
      `INSERT INTO ics_posture (segment_id, segment_name, device_count, write_risk_count, gateway_count, outside_management_zone, score)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [segmentId, segment?.name ?? 'unknown', segmentHosts.length, writeRiskCount, gatewayCount, outsideManagement, score],
    );
    results.push(row);
  }

  if (unassigned.length > 0) {
    const { writeRiskCount, gatewayCount, score } = scoreFor(unassigned, true);
    const [row] = await query<IcsPosture>(
      `INSERT INTO ics_posture (segment_id, segment_name, device_count, write_risk_count, gateway_count, outside_management_zone, score)
       VALUES (NULL, 'unassigned', $1, $2, $3, true, $4) RETURNING *`,
      [unassigned.length, writeRiskCount, gatewayCount, score],
    );
    results.push(row);
  }

  return results;
}
