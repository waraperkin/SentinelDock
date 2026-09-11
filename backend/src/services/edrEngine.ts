import { query } from '../db/pool.js';
import type { Container, Host, ServiceRecord, EdrDetection } from '../types/models.js';

/**
 * TITAN tier: EDR-lite — behavioral detection without deploying any agent
 * on the monitored hosts. Real endpoint EDR inspects process trees,
 * syscalls, and memory; this platform only has what the worker already
 * collects remotely/read-only (open ports, container metadata), so this
 * engine is scoped honestly to what that data can actually support:
 * known malicious listener ports, suspicious container image naming
 * (cryptojacking tooling), and dangerous privilege/placement combinations.
 * It is a heuristic signal, not a replacement for a real host-based EDR
 * agent.
 */

const SUSPICIOUS_LISTENER_PORTS = new Set([4444, 1337, 31337, 6666, 6667, 3333, 5555, 7777, 9999]);

const SUSPICIOUS_IMAGE_PATTERN = /xmrig|kinsing|propagate|cryptonight|monero.?miner|minerd|cpuminer/i;

/**
 * Replaces the edr_detections table with fresh results each run
 * (idempotent snapshot of *current* exposure/state, matching the pattern
 * used by threatIntelEngine — a detection is a property of what is
 * running now, not an append-only historical log).
 */
export async function scanEdrSignals(): Promise<EdrDetection[]> {
  const [services, containers, hosts] = await Promise.all([
    query<ServiceRecord>('SELECT * FROM services'),
    query<Container>('SELECT * FROM containers'),
    query<Host>('SELECT * FROM hosts'),
  ]);
  const hostById = new Map(hosts.map((h) => [h.id, h]));

  await query('DELETE FROM edr_detections');
  const results: EdrDetection[] = [];

  for (const service of services) {
    if (!SUSPICIOUS_LISTENER_PORTS.has(service.port)) continue;
    const [row] = await query<EdrDetection>(
      `INSERT INTO edr_detections (asset_type, asset_id, kind, details, severity)
       VALUES ('service', $1, 'suspicious-port', $2, 'high') RETURNING *`,
      [service.id, JSON.stringify({ port: service.port, name: service.name })],
    );
    results.push(row);
  }

  for (const container of containers) {
    if (SUSPICIOUS_IMAGE_PATTERN.test(container.image)) {
      const [row] = await query<EdrDetection>(
        `INSERT INTO edr_detections (asset_type, asset_id, kind, details, severity)
         VALUES ('container', $1, 'suspicious-container-image', $2, 'critical') RETURNING *`,
        [container.id, JSON.stringify({ image: container.image, name: container.name })],
      );
      results.push(row);
    }

    const host = hostById.get(container.host_id);
    if (container.privileged && host?.device_class === 'ics') {
      const [row] = await query<EdrDetection>(
        `INSERT INTO edr_detections (asset_type, asset_id, kind, details, severity)
         VALUES ('container', $1, 'privileged-container-on-ics-host', $2, 'critical') RETURNING *`,
        [container.id, JSON.stringify({ image: container.image, name: container.name, host_id: container.host_id })],
      );
      results.push(row);
    }
  }

  return results;
}
