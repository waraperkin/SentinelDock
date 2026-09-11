export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Criticality = Severity;
export type AssetType = 'host' | 'container' | 'service' | 'network';

export interface NetworkSegment {
  id: string;
  name: string;
  cidr: string;
  zone: 'internal' | 'dmz' | 'public' | 'management';
  description?: string | null;
  created_at: string;
}

export interface Host {
  id: string;
  hostname: string;
  os?: string | null;
  os_version?: string | null;
  ip_address?: string | null;
  role: string;
  network_segment_id?: string | null;
  criticality: Criticality;
  device_class: 'it' | 'ics' | 'cloud';
  last_seen?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ContainerPortMapping {
  container: number;
  host: number;
  protocol: 'tcp' | 'udp';
}

export interface Container {
  id: string;
  host_id: string;
  name: string;
  image: string;
  image_tag?: string | null;
  status: 'running' | 'stopped' | 'paused';
  ports: ContainerPortMapping[];
  privileged: boolean;
  created_at: string;
  updated_at: string;
}

export interface ServiceRecord {
  id: string;
  host_id?: string | null;
  container_id?: string | null;
  name: string;
  port: number;
  protocol: string;
  bind_address: string;
  banner?: string | null;
  version?: string | null;
  exposed_publicly: boolean;
  cve_ids: string[];
  cvss_score?: number | null;
  protocol_family?: string | null;
  created_at: string;
  updated_at: string;
}

export interface Dependency {
  id: string;
  source_asset_type: AssetType;
  source_asset_id: string;
  target_asset_type: AssetType;
  target_asset_id: string;
  relation: string;
  created_at: string;
}

export interface ConfigSnapshot {
  id: string;
  asset_type: AssetType;
  asset_id: string;
  kind: string;
  data: Record<string, unknown>;
  collected_at: string;
  created_at: string;
}

export interface PolicyCondition {
  field: string;
  operator: 'eq' | 'neq' | 'in' | 'not_in' | 'lt' | 'lte' | 'gt' | 'gte' | 'contains';
  value: unknown;
}

export interface PolicyDefinition {
  target: 'host' | 'container' | 'service';
  all?: PolicyCondition[];
  any?: PolicyCondition[];
}

export interface Policy {
  id: string;
  key: string;
  name: string;
  description?: string | null;
  severity: Severity;
  recommendation?: string | null;
  conditions: PolicyDefinition;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface PolicyViolation {
  id: string;
  policy_id: string;
  asset_type: AssetType;
  asset_id: string;
  severity: Severity;
  details: Record<string, unknown>;
  status: 'open' | 'acknowledged' | 'resolved';
  detected_at: string;
  resolved_at?: string | null;
}

export interface Risk {
  id: string;
  asset_type: AssetType;
  asset_id: string;
  category:
    | 'exposure'
    | 'misconfiguration'
    | 'segmentation'
    | 'patching'
    | 'vulnerability'
    | 'network'
    | 'container'
    | 'host'
    | 'ics'
    | 'cloud'
    | 'secrets';
  severity: Severity;
  score: number;
  summary: string;
  source_violation_ids: string[];
  created_at: string;
  updated_at: string;
}

export interface AttackPathHop {
  asset_type: AssetType;
  asset_id: string;
  via: string;
  /** MITRE ATT&CK-flavored tactic:technique label for this hop, e.g. "Lateral Movement (TA0008): Remote Services (T1021)". */
  technique?: string;
}

export interface SecretFinding {
  id: string;
  asset_type: AssetType;
  asset_id: string;
  kind: 'aws_access_key' | 'private_key' | 'generic_api_key' | 'generic_password';
  match_preview: string;
  source: string;
  severity: Severity;
  detected_at: string;
}

export interface AttackPath {
  id: string;
  name: string;
  entry_asset_type: AssetType;
  entry_asset_id: string;
  target_asset_type: AssetType;
  target_asset_id: string;
  hops: AttackPathHop[];
  blast_radius: number;
  severity: Severity;
  created_at: string;
}

export interface IncidentScenario {
  id: string;
  title: string;
  severity: Severity;
  risk_id?: string | null;
  attack_path_id?: string | null;
  summary: string;
  playbook: string;
  created_at: string;
}
