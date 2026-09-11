/**
 * Maps a dependency relation + hop asset type to a MITRE ATT&CK-flavored
 * tactic/technique label. This is a heuristic label, not a full ATT&CK
 * Navigator integration — it gives each attack path hop a recognizable
 * "what stage of the kill chain is this" tag using the small set of
 * relations SentinelDock's dependency graph actually produces
 * (runs_on / member_of / connects_to, reversed variants included).
 */
const RELATION_TECHNIQUE: Record<string, string> = {
  runs_on: 'Lateral Movement (TA0008): Exploitation of Remote Services (T1210)',
  'runs_on (reverse)': 'Discovery (TA0007): Remote System Discovery (T1018)',
  member_of: 'Discovery (TA0007): Network Service Discovery (T1046)',
  'member_of (reverse)': 'Lateral Movement (TA0008): Remote Services (T1021)',
  connects_to: 'Command and Control (TA0011): Application Layer Protocol (T1071)',
  'connects_to (reverse)': 'Command and Control (TA0011): Application Layer Protocol (T1071)',
  depends_on: 'Lateral Movement (TA0008): Remote Services (T1021)',
};

const ENTRY_TECHNIQUE = 'Initial Access (TA0001): Exploit Public-Facing Application (T1190)';

export function techniqueForRelation(relation: string): string {
  return RELATION_TECHNIQUE[relation] ?? 'Lateral Movement (TA0008): Remote Services (T1021)';
}

export function entryTechnique(): string {
  return ENTRY_TECHNIQUE;
}
