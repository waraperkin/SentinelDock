import { query } from '../db/pool.js';
import type { Host, CloudPosture } from '../types/models.js';

/**
 * GODMODE tier: CLOUDMASTER — the Cloud Agent. Aggregates signals already
 * collected by the OMEGA/roadmap-cycle cloud work (read-only IAM role
 * enumeration, metadata reachability, mixed-segment detection) into one
 * per-provider posture score, rather than leaving an operator to piece
 * those signals together from separate risk rows. No live cloud API
 * calls of its own — it is a read-only aggregation over data this
 * platform already has.
 */
export async function computeCloudPosture(): Promise<CloudPosture[]> {
  const hosts = await query<Host>("SELECT * FROM hosts WHERE device_class = 'cloud'");
  const iamSnapshots = await query<{ asset_id: string; data: { provider?: string; role_name?: string } }>(
    "SELECT asset_id, data FROM config_snapshots WHERE kind = 'cloud-iam'",
  );
  const metadataServices = await query<{ host_id: string }>("SELECT host_id FROM services WHERE protocol_family = 'cloud-metadata' AND host_id IS NOT NULL");

  const OVERPRIVILEGED_NAME_PATTERN = /admin|root|full[-_]?access|superuser|owner/i;

  const providerByHostId = new Map<string, string>();
  const overprivilegedHostIds = new Set<string>();
  for (const snapshot of iamSnapshots) {
    const provider = snapshot.data.provider ?? 'unknown';
    providerByHostId.set(snapshot.asset_id, provider);
    if (snapshot.data.role_name && OVERPRIVILEGED_NAME_PATTERN.test(snapshot.data.role_name)) overprivilegedHostIds.add(snapshot.asset_id);
  }

  const metadataReachableHostIds = new Set(metadataServices.map((s) => s.host_id));

  // Mixed-segment cloud hosts: reuses the same "segment contains multiple
  // device_class values" signal as policyEngine/zeroTrustEngine, computed
  // independently here since this aggregation is scoped to cloud hosts only.
  const allHosts = await query<Host>('SELECT * FROM hosts');
  const deviceClassesBySegment = new Map<string, Set<string>>();
  for (const h of allHosts) {
    if (!h.network_segment_id) continue;
    const set = deviceClassesBySegment.get(h.network_segment_id) ?? new Set<string>();
    set.add(h.device_class);
    deviceClassesBySegment.set(h.network_segment_id, set);
  }

  const providers = new Map<string, Host[]>();
  for (const host of hosts) {
    const provider = providerByHostId.get(host.id) ?? 'unknown';
    providers.set(provider, [...(providers.get(provider) ?? []), host]);
  }

  await query('DELETE FROM cloud_posture');
  const results: CloudPosture[] = [];

  for (const [provider, providerHosts] of providers) {
    const overprivilegedCount = providerHosts.filter((h) => overprivilegedHostIds.has(h.id)).length;
    const metadataReachableCount = providerHosts.filter((h) => metadataReachableHostIds.has(h.id)).length;
    const mixedSegmentCount = providerHosts.filter((h) => (h.network_segment_id ? (deviceClassesBySegment.get(h.network_segment_id)?.size ?? 1) > 1 : false)).length;

    const score = Math.min(100, overprivilegedCount * 30 + metadataReachableCount * 12 + mixedSegmentCount * 15);

    const [row] = await query<CloudPosture>(
      `INSERT INTO cloud_posture (provider, host_count, overprivileged_role_count, metadata_reachable_count, mixed_segment_count, score)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [provider, providerHosts.length, overprivilegedCount, metadataReachableCount, mixedSegmentCount, score],
    );
    results.push(row);
  }

  return results;
}
