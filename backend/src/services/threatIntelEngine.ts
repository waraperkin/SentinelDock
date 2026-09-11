import { query } from '../db/pool.js';
import type { ServiceRecord, TiMatch } from '../types/models.js';

/**
 * TITAN tier: Threat Intelligence Local Engine (TI-local).
 *
 * This is a small, hand-curated LOCAL dataset — never a live feed against
 * an external threat-intel provider (unreliable to depend on from this
 * environment, and a live feed would need an API key/subscription this
 * project cannot assume). It illustrates the same evaluation shape a real
 * TI feed integration would populate: known-malicious port associations
 * (common C2/backdoor/cryptomining listener ports) and a curated set of
 * CVEs known to have been used in named real-world campaigns, enriching
 * (not duplicating) the plain "known exploited" flag already tracked in
 * vulnerabilityScanner.ts.
 */

interface MaliciousPortIndicator {
  port: number;
  label: string;
  severity: 'medium' | 'high' | 'critical';
}

const MALICIOUS_PORT_INDICATORS: MaliciousPortIndicator[] = [
  { port: 4444, label: 'Metasploit/Cobalt Strike default handler port', severity: 'critical' },
  { port: 1337, label: 'Common backdoor/leet-culture listener port', severity: 'high' },
  { port: 31337, label: 'Back Orifice / classic backdoor listener port ("elite")', severity: 'high' },
  { port: 6667, label: 'IRC — historically used for botnet C2 channels', severity: 'medium' },
  { port: 3333, label: 'Common cryptomining (Stratum) pool port', severity: 'high' },
  { port: 5555, label: 'Common cryptomining (Stratum) pool port / ADB exposure', severity: 'high' },
  { port: 7777, label: 'Common cryptomining (Stratum) pool port', severity: 'medium' },
  { port: 8333, label: 'Non-standard listener commonly associated with cryptocurrency mining/nodes', severity: 'medium' },
];

/** CVE ID -> named real-world campaign/threat-actor context, layered on top of the isKnownExploited flag in vulnerabilityScanner.ts. */
const TARGETED_CVE_CAMPAIGNS: Record<string, string> = {
  'CVE-2022-0543': 'Muhstik botnet — mass-exploited this Redis Lua sandbox escape for worm propagation',
  'CVE-2019-5736': 'Used in real-world container-escape attack chains against exposed Docker Engine APIs',
  'CVE-2019-0708': 'BlueKeep — mass pre-auth RDP RCE, weaponized by multiple ransomware operators',
  'CVE-2017-0144': 'EternalBlue — the SMBv1 exploit behind WannaCry and NotPetya',
  'CVE-2012-2122': 'MySQL auth-bypass — widely scripted into automated credential-stuffing/bruteforce toolkits',
};

/**
 * Matches current inventory against the local TI dataset and replaces the
 * ti_matches table with fresh results (idempotent snapshot, same pattern
 * as vulnerabilityScanner's UPDATE-per-run rather than an append-only log,
 * since a TI match is a property of *current* exposure, not a historical
 * event).
 */
export async function scanThreatIntel(): Promise<TiMatch[]> {
  const services = await query<ServiceRecord>('SELECT * FROM services');
  await query('DELETE FROM ti_matches');

  const results: TiMatch[] = [];

  for (const service of services) {
    const portIndicator = MALICIOUS_PORT_INDICATORS.find((i) => i.port === service.port);
    if (portIndicator) {
      const [row] = await query<TiMatch>(
        `INSERT INTO ti_matches (asset_type, asset_id, indicator_kind, indicator_value, label, severity)
         VALUES ('service', $1, 'malicious_port', $2, $3, $4) RETURNING *`,
        [service.id, String(service.port), portIndicator.label, portIndicator.severity],
      );
      results.push(row);
    }

    for (const cveId of service.cve_ids) {
      const campaign = TARGETED_CVE_CAMPAIGNS[cveId];
      if (!campaign) continue;
      const [row] = await query<TiMatch>(
        `INSERT INTO ti_matches (asset_type, asset_id, indicator_kind, indicator_value, label, severity)
         VALUES ('service', $1, 'targeted_cve', $2, $3, 'critical') RETURNING *`,
        [service.id, cveId, campaign],
      );
      results.push(row);
    }
  }

  return results;
}

export function maliciousPortIndicatorFor(port: number): MaliciousPortIndicator | undefined {
  return MALICIOUS_PORT_INDICATORS.find((i) => i.port === port);
}

export function targetedCampaignForCve(cveId: string): string | undefined {
  return TARGETED_CVE_CAMPAIGNS[cveId];
}
