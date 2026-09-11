import { query } from '../db/pool.js';
import type { Host, NetworkSegment, SegmentationRecommendation } from '../types/models.js';

/**
 * TITAN tier: Auto-Segmentation Engine. Produces RECOMMENDATIONS only —
 * it never moves a host or edits a network_segment itself. Reuses the
 * same "mixed device_class per segment" signal already computed for the
 * Zero Trust score and the cloud-onprem-mixed-segment policy, but turns
 * it into an actionable per-host recommendation with a suggested target
 * zone, rather than just a score or a violation flag.
 */
export async function generateSegmentationRecommendations(): Promise<SegmentationRecommendation[]> {
  const segments = await query<NetworkSegment>('SELECT * FROM network_segments');
  const hosts = await query<Host>('SELECT * FROM hosts');

  const hostsBySegment = new Map<string, Host[]>();
  for (const host of hosts) {
    if (!host.network_segment_id) continue;
    hostsBySegment.set(host.network_segment_id, [...(hostsBySegment.get(host.network_segment_id) ?? []), host]);
  }

  // Clear previously auto-generated open recommendations before
  // regenerating — this run reflects current inventory; a
  // human-actioned (applied/dismissed) recommendation is left alone since
  // this DELETE is scoped to status = 'open'.
  await query("DELETE FROM segmentation_recommendations WHERE status = 'open'");

  const results: SegmentationRecommendation[] = [];

  for (const segment of segments) {
    const segmentHosts = hostsBySegment.get(segment.id) ?? [];
    const deviceClasses = new Set(segmentHosts.map((h) => h.device_class));
    if (deviceClasses.size <= 1) continue;

    for (const host of segmentHosts) {
      const others = segmentHosts.filter((h) => h.id !== host.id && h.device_class !== host.device_class);
      if (others.length === 0) continue;
      const targetZone = host.device_class === 'ics' ? 'management' : host.device_class === 'cloud' ? 'dmz' : 'internal';
      const [row] = await query<SegmentationRecommendation>(
        `INSERT INTO segmentation_recommendations (segment_id, host_id, recommendation, rationale, target_zone)
         VALUES ($1, $2, $3, $4, $5) RETURNING *`,
        [
          segment.id,
          host.id,
          `Move "${host.hostname}" (${host.device_class}) to a dedicated segment`,
          `This segment mixes device classes (${Array.from(deviceClasses).join(', ')}) — ${host.hostname} shares a broadcast domain with ${others.length} host(s) of a different class, with no identity-based isolation between them.`,
          targetZone,
        ],
      );
      results.push(row);
    }
  }

  return results;
}
