import { query } from '../db/pool.js';
import type { AttackPath, IncidentScenario, Risk } from '../types/models.js';

interface PlaybookSteps {
  immediate: string[];
  containment: string[];
  eradication: string[];
  recovery: string[];
  lessonsLearned: string[];
}

const GENERIC_STEPS: PlaybookSteps = {
  immediate: ['Confirm the finding against live logs/service state before acting.', 'Notify the on-call security contact.'],
  containment: ['Isolate the affected asset from its network segment.', 'Disable public exposure of the offending service/port.'],
  eradication: ['Apply the policy recommendation for the triggering violation.', 'Re-run policy evaluation to confirm the finding clears.'],
  recovery: ['Restore normal exposure/segmentation once the fix is confirmed.', 'Monitor the asset for a full evaluation cycle before closing.'],
  lessonsLearned: ['Document root cause in the incident log.', 'Add or adjust a policy so this class of issue is caught earlier next time.'],
};

/** Category-specific playbook content, keyed by a substring match against the risk category/summary. */
const SCENARIO_LIBRARY: Array<{ match: RegExp; title: string; steps: PlaybookSteps }> = [
  {
    match: /ssh/i,
    title: 'SSH exposure / potential compromise',
    steps: {
      immediate: [
        'Check `last`/auth logs on the host for unrecognized logins since the exposure window began.',
        'Rotate credentials and SSH host keys if any unrecognized session is found.',
      ],
      containment: [
        'Remove the public port mapping or bind SSH to an internal-only interface immediately.',
        'Restrict access to a bastion host or VPN-only path.',
      ],
      eradication: ['Force-expire all active sessions and re-authenticate legitimate users.', 'Patch OpenSSH if the version matches a known CVE.'],
      recovery: ['Re-enable access only through the bastion/VPN path.', 'Confirm no lingering authorized_keys entries were planted.'],
      lessonsLearned: ['Add continuous monitoring for SSH exposure drift.', 'Require key-based auth and disable password login going forward.'],
    },
  },
  {
    match: /docker/i,
    title: 'Docker Engine API exposure / potential container escape',
    steps: {
      immediate: ['Assume any container on this host may be attacker-controlled until proven otherwise.', 'Snapshot running container list and images for forensics.'],
      containment: ['Block inbound access to the Docker API port at the firewall immediately.', 'Do not stop containers yet — preserve state for investigation first.'],
      eradication: [
        'Rebuild affected containers from known-good images rather than trusting the running instance.',
        'Rotate any credentials/secrets that were mounted into or reachable from affected containers.',
      ],
      recovery: ['Re-enable the API only behind mutual TLS and a socket proxy with least-privilege scopes.', 'Re-run the full evaluation pipeline to confirm the API is no longer publicly reachable.'],
      lessonsLearned: ['Never expose the raw Docker socket/API to any untrusted network.', 'Add host-level firewall rules as defense-in-depth, not just app-level config.'],
    },
  },
  {
    match: /database|postgres|redis|mysql|mongo/i,
    title: 'Database exposure / potential data compromise',
    steps: {
      immediate: ['Check database connection/audit logs for unfamiliar source IPs since exposure began.', 'Identify what data classification the exposed database holds.'],
      containment: ['Remove public exposure and restrict the listener to the internal segment immediately.', 'Rotate the database credentials.'],
      eradication: ['Review for unauthorized schema changes, new users/roles, or exfiltrated data.', 'Patch to a supported version if the exposure was paired with a known CVE.'],
      recovery: ['Restore from a known-good backup if tampering is confirmed.', 'Re-test connectivity to confirm only expected internal callers can reach it.'],
      lessonsLearned: ['Databases should never be directly reachable from a public segment — enforce this in policy.', 'Add query/audit logging if not already enabled.'],
    },
  },
  {
    match: /privileged|container/i,
    title: 'Privileged container compromise',
    steps: {
      immediate: ['Identify what host capabilities/devices the privileged container had access to.', 'Check host-level logs for signs of container-escape activity.'],
      containment: ['Stop the privileged container.', 'Isolate the host from the rest of the network pending investigation.'],
      eradication: ['Rebuild the workload without the --privileged flag, granting only required --cap-add capabilities.', 'Audit the host for persistence mechanisms left behind.'],
      recovery: ['Redeploy the hardened container definition.', 'Confirm the policy engine reports no privileged-container violations.'],
      lessonsLearned: ['Add a CI/CD gate that rejects --privileged in manifests without an explicit, reviewed exception.', 'Track this pattern for future container hardening reviews.'],
    },
  },
  {
    match: /vulnerability|cve/i,
    title: 'Known-vulnerable service version',
    steps: {
      immediate: ['Confirm the running version and cross-check the matched CVE for exploitability in this context.', 'Check for exploitation indicators (crash logs, unexpected child processes, anomalous traffic).'],
      containment: ['Restrict network access to the vulnerable service until patched.', 'Apply a WAF/network rule mitigating the specific CVE if a patch is not immediately available.'],
      eradication: ['Upgrade the service past the vulnerable version.', 'Re-scan to confirm the CVE no longer matches.'],
      recovery: ['Restore normal access once patched and re-scanned clean.', 'Monitor for a full cycle for regressions.'],
      lessonsLearned: ['Add the affected service to a routine patch-cadence review.', 'Consider automated dependency/version update alerts.'],
    },
  },
];

export function selectScenario(summary: string, category: string): { title: string; steps: PlaybookSteps } {
  const haystack = `${summary} ${category}`;
  const found = SCENARIO_LIBRARY.find((s) => s.match.test(haystack));
  return found ? { title: found.title, steps: found.steps } : { title: `${category} risk`, steps: GENERIC_STEPS };
}

function renderList(items: string[]): string {
  return items.map((item) => `- ${item}`).join('\n');
}

function buildPlaybook(risk: Risk, attackPath: AttackPath | null, scenario: { title: string; steps: PlaybookSteps }): string {
  const lines: string[] = [];
  lines.push(`# Incident Playbook: ${scenario.title}`);
  lines.push('');
  lines.push(`**Asset:** \`${risk.asset_type}:${risk.asset_id}\``);
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
  lines.push('## Immediate Actions');
  lines.push(renderList(scenario.steps.immediate));
  lines.push('');
  lines.push('## Containment');
  lines.push(renderList(scenario.steps.containment));
  lines.push('');
  lines.push('## Eradication');
  lines.push(renderList(scenario.steps.eradication));
  lines.push('');
  lines.push('## Recovery');
  lines.push(renderList(scenario.steps.recovery));
  lines.push('');
  lines.push('## Lessons Learned');
  lines.push(renderList(scenario.steps.lessonsLearned));
  return lines.join('\n');
}

/**
 * Generates one IncidentScenario per high/critical Risk, linking the
 * matching AttackPath (if any) whose entry/target touches the same asset,
 * and selecting a category-specific playbook from the scenario library.
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

    const policyKeys =
      risk.source_violation_ids.length > 0
        ? (await query<{ key: string }>(
            `SELECT DISTINCT p.key FROM policy_violations pv JOIN policies p ON p.id = pv.policy_id WHERE pv.id = ANY($1)`,
            [risk.source_violation_ids],
          )).map((r) => r.key)
        : [];
    const scenario = selectScenario(`${risk.summary} ${policyKeys.join(' ')}`, risk.category);
    const title = `${risk.severity.toUpperCase()}: ${scenario.title} (${risk.asset_type}:${risk.asset_id})`;
    const playbook = buildPlaybook(risk, relatedPath, scenario);

    const [row] = await query<IncidentScenario>(
      `INSERT INTO incident_scenarios (title, severity, risk_id, attack_path_id, summary, playbook)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [title, risk.severity, risk.id, relatedPath?.id ?? null, risk.summary, playbook],
    );
    results.push(row);
  }

  return results;
}
