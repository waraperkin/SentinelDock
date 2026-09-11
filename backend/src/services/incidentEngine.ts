import { query } from '../db/pool.js';
import type { AttackPath, IncidentScenario, Risk } from '../types/models.js';

function buildPlaybook(risk: Risk, attackPath: AttackPath | null): string {
  const lines: string[] = [];
  lines.push(`# Incident Playbook: ${risk.category} risk on ${risk.asset_type} ${risk.asset_id}`);
  lines.push('');
  lines.push(`**Severity:** ${risk.severity.toUpperCase()}  `);
  lines.push(`**Risk score:** ${risk.score}`);
  lines.push('');
  lines.push('## Summary');
  lines.push(risk.summary);
  lines.push('');
  if (attackPath) {
    lines.push('## Attack Path');
    lines.push(`Entry: \`${attackPath.entry_asset_type}:${attackPath.entry_asset_id}\` -> Target: \`${attackPath.target_asset_type}:${attackPath.target_asset_id}\``);
    lines.push(`Blast radius: ${attackPath.blast_radius} asset(s)`);
    lines.push('');
    lines.push('Hops:');
    for (const hop of attackPath.hops) {
      lines.push(`- via **${hop.via}** -> \`${hop.asset_type}:${hop.asset_id}\``);
    }
    lines.push('');
  }
  lines.push('## Response Steps');
  lines.push('1. **Contain** — isolate the affected asset from its network segment; disable public exposure of the offending service/port.');
  lines.push('2. **Verify** — confirm whether the exposure/misconfiguration has been exploited by reviewing access/service logs for the affected window.');
  lines.push('3. **Eradicate** — apply the policy recommendation (see violation detail) and re-run policy evaluation.');
  lines.push('4. **Recover** — restore normal exposure/segmentation once the fix is confirmed by a fresh policy evaluation pass.');
  lines.push('5. **Review** — document root cause and add/adjust a policy to prevent recurrence.');
  return lines.join('\n');
}

/**
 * Generates one IncidentScenario per high/critical Risk, linking the
 * matching AttackPath (if any) whose entry/target touches the same asset.
 */
export async function generateIncidentScenarios(): Promise<IncidentScenario[]> {
  const risks = await query<Risk>("SELECT * FROM risks WHERE severity IN ('high', 'critical') ORDER BY score DESC");
  const attackPaths = await query<AttackPath>('SELECT * FROM attack_paths');

  await query('DELETE FROM incident_scenarios');

  const results: IncidentScenario[] = [];
  for (const risk of risks) {
    const relatedPath =
      attackPaths.find(
        (p) =>
          (p.entry_asset_type === risk.asset_type && p.entry_asset_id === risk.asset_id) ||
          (p.target_asset_type === risk.asset_type && p.target_asset_id === risk.asset_id),
      ) ?? null;

    const title = `${risk.severity.toUpperCase()} ${risk.category} risk on ${risk.asset_type}:${risk.asset_id}`;
    const playbook = buildPlaybook(risk, relatedPath);

    const [row] = await query<IncidentScenario>(
      `INSERT INTO incident_scenarios (title, severity, risk_id, attack_path_id, summary, playbook)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [title, risk.severity, risk.id, relatedPath?.id ?? null, risk.summary, playbook],
    );
    results.push(row);
  }

  return results;
}
