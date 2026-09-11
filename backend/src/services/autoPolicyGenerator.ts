import { query } from '../db/pool.js';
import type { Host, ServiceRecord, Policy } from '../types/models.js';

/**
 * Combinations that already have dedicated, hand-authored policies (see
 * db/migrations/*_seed_*.sql and policies/*.yaml) — auto-generation must
 * not propose a duplicate draft for something already covered.
 */
const COVERED_PROTOCOL_FAMILIES = new Set(['modbus', 's7', 'bacnet', 'opcua', 'cloud-metadata', 'devops']);
const COVERED_DEVICE_CLASSES = new Set(['ics', 'cloud']);

/**
 * Scans current inventory for protocol_family (on services) and
 * device_class (on hosts) values that have no existing policy — including
 * previously auto-generated drafts, so a rerun does not create duplicates
 * — and proposes new draft policies (enabled: false) for a human to review
 * and turn on. This only ever creates disabled drafts; it never enables a
 * policy or evaluates it, since an auto-generated condition set is a
 * starting point for review, not a vetted detection rule.
 */
export async function autoGeneratePolicies(): Promise<Policy[]> {
  const existingPolicies = await query<Policy>('SELECT * FROM policies');
  const existingKeys = new Set(existingPolicies.map((p) => p.key));

  const services = await query<ServiceRecord>('SELECT * FROM services WHERE protocol_family IS NOT NULL');
  const hosts = await query<Host>('SELECT * FROM hosts');

  const proposals: Array<{ key: string; name: string; description: string; conditions: Record<string, unknown> }> = [];

  const uncoveredFamilies = new Set(
    services
      .map((s) => s.protocol_family)
      .filter((f): f is string => typeof f === 'string' && f.length > 0)
      .filter((f) => !COVERED_PROTOCOL_FAMILIES.has(f)),
  );
  for (const family of uncoveredFamilies) {
    const key = `auto-exposed-${family}`;
    if (existingKeys.has(key)) continue;
    proposals.push({
      key,
      name: `[Draft] Service with protocol family "${family}" exposed publicly`,
      description: `Auto-generated draft: at least one publicly exposed service was observed with protocol_family "${family}", which has no dedicated policy yet. Review conditions and enable if this exposure is meaningful.`,
      conditions: { target: 'service', all: [{ field: 'protocol_family', operator: 'eq', value: family }, { field: 'exposed_publicly', operator: 'eq', value: true }] },
    });
  }

  const uncoveredClasses = new Set(hosts.map((h) => h.device_class).filter((c) => !COVERED_DEVICE_CLASSES.has(c)));
  for (const deviceClass of uncoveredClasses) {
    if (deviceClass === 'it') continue; // "it" is the default/expected class — not gap-worthy on its own
    const key = `auto-device-class-${deviceClass}`;
    if (existingKeys.has(key)) continue;
    proposals.push({
      key,
      name: `[Draft] Host with device_class "${deviceClass}" present`,
      description: `Auto-generated draft: at least one host was classified as device_class "${deviceClass}", which has no dedicated policy yet. Review conditions and enable if this asset class warrants its own detection rule.`,
      conditions: { target: 'host', all: [{ field: 'device_class', operator: 'eq', value: deviceClass }] },
    });
  }

  const created: Policy[] = [];
  for (const proposal of proposals) {
    const [row] = await query<Policy>(
      `INSERT INTO policies (key, name, description, severity, recommendation, conditions, enabled)
       VALUES ($1, $2, $3, $4, $5, $6, false)
       ON CONFLICT (key) DO NOTHING RETURNING *`,
      [proposal.key, proposal.name, proposal.description, 'medium', 'Review the auto-generated conditions, adjust severity/recommendation as needed, then enable.', JSON.stringify(proposal.conditions)],
    );
    if (row) created.push(row);
  }

  return created;
}
