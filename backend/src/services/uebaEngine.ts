import { query, queryOne } from '../db/pool.js';
import type { Host, ServiceRecord, UebaAnomaly } from '../types/models.js';

/**
 * TITAN tier: UEBA-lite (User/Entity Behavior Analytics, scoped to assets
 * rather than user accounts — this platform has no user/session telemetry
 * to analyze, so "entity" here means host). This is a deterministic
 * baseline-deviation detector, not a statistical/ML anomaly model: each
 * host gets a rolling baseline of its observed service ports, and each run
 * compares the current state against that baseline to flag concrete,
 * explainable deviations.
 */

const SENSITIVE_NEW_PORTS = new Set([22, 3389, 5900, 502, 102, 4840, 47808]); // remote-admin + ICS ports — a new one appearing is worse than a random high port

interface UebaBaseline {
  host_id: string;
  port_set: number[];
  service_count: number;
}

/**
 * Compares current per-host service state against each host's rolling
 * baseline, records anomalies for real deviations, then updates the
 * baseline to the current state. A host observed for the first time gets
 * its baseline seeded with no anomaly emitted — there is nothing to
 * deviate from yet.
 */
export async function computeUebaAnomalies(): Promise<UebaAnomaly[]> {
  const hosts = await query<Host>('SELECT * FROM hosts');
  const services = await query<ServiceRecord>('SELECT * FROM services WHERE host_id IS NOT NULL');

  const portsByHost = new Map<string, Set<number>>();
  for (const service of services) {
    if (!service.host_id) continue;
    const set = portsByHost.get(service.host_id) ?? new Set<number>();
    set.add(service.port);
    portsByHost.set(service.host_id, set);
  }

  const anomalies: UebaAnomaly[] = [];

  for (const host of hosts) {
    const currentPorts = Array.from(portsByHost.get(host.id) ?? new Set<number>()).sort((a, b) => a - b);
    const baseline = await queryOne<UebaBaseline>('SELECT host_id, port_set, service_count FROM ueba_baselines WHERE host_id = $1', [host.id]);

    if (baseline) {
      const baselinePortSet = new Set(baseline.port_set);
      const newPorts = currentPorts.filter((p) => !baselinePortSet.has(p));

      if (newPorts.length > 0) {
        const sensitiveHit = newPorts.some((p) => SENSITIVE_NEW_PORTS.has(p));
        const [row] = await query<UebaAnomaly>(
          `INSERT INTO ueba_anomalies (host_id, kind, details, severity)
           VALUES ($1, 'new-service-port', $2, $3) RETURNING *`,
          [host.id, JSON.stringify({ new_ports: newPorts, baseline_ports: baseline.port_set }), sensitiveHit ? 'high' : 'medium'],
        );
        anomalies.push(row);
      }

      const grew = currentPorts.length - baseline.service_count;
      if (baseline.service_count >= 2 && grew >= 2 && currentPorts.length >= baseline.service_count * 1.5) {
        const [row] = await query<UebaAnomaly>(
          `INSERT INTO ueba_anomalies (host_id, kind, details, severity)
           VALUES ($1, 'service-count-spike', $2, 'medium') RETURNING *`,
          [host.id, JSON.stringify({ previous_count: baseline.service_count, current_count: currentPorts.length })],
        );
        anomalies.push(row);
      }
    }

    await query(
      `INSERT INTO ueba_baselines (host_id, port_set, service_count, updated_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (host_id) DO UPDATE SET port_set = $2, service_count = $3, updated_at = now()`,
      [host.id, currentPorts, currentPorts.length],
    );
  }

  return anomalies;
}

/** Anomalies detected within the given lookback window, most recent first — used by the risk engine and the SIEM-lite timeline so both read a bounded, recent slice rather than the full history. */
export async function recentUebaAnomalies(hoursBack = 24): Promise<UebaAnomaly[]> {
  return query<UebaAnomaly>(`SELECT * FROM ueba_anomalies WHERE detected_at > now() - ($1 || ' hours')::interval ORDER BY detected_at DESC`, [hoursBack]);
}
