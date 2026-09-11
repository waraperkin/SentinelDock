export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface Host {
  id: string;
  hostname: string;
  os?: string | null;
  os_version?: string | null;
  ip_address?: string | null;
  role: string;
  network_segment_id?: string | null;
  criticality: Severity;
  device_class: 'it' | 'ics' | 'cloud';
  last_seen?: string | null;
}

export interface Container {
  id: string;
  host_id: string;
  name: string;
  image: string;
  status: string;
  ports: Array<{ container: number; host: number; protocol: string }>;
  privileged: boolean;
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
}

export interface NetworkSegment {
  id: string;
  name: string;
  cidr: string;
  zone: string;
  description?: string | null;
}

export interface Policy {
  id: string;
  key: string;
  name: string;
  description?: string | null;
  severity: Severity;
  recommendation?: string | null;
  enabled: boolean;
}

export interface PolicyViolation {
  id: string;
  policy_id: string;
  asset_type: string;
  asset_id: string;
  severity: Severity;
  details: Record<string, unknown>;
  status: 'open' | 'acknowledged' | 'resolved';
  detected_at: string;
}

export interface Risk {
  id: string;
  asset_type: string;
  asset_id: string;
  category: string;
  severity: Severity;
  score: number;
  summary: string;
}

export interface AttackPath {
  id: string;
  name: string;
  entry_asset_type: string;
  entry_asset_id: string;
  target_asset_type: string;
  target_asset_id: string;
  hops: Array<{ asset_type: string; asset_id: string; via: string; technique?: string }>;
  blast_radius: number;
  severity: Severity;
}

export interface SecretFinding {
  id: string;
  asset_type: string;
  asset_id: string;
  kind: string;
  match_preview: string;
  source: string;
  severity: Severity;
  detected_at: string;
}

export interface WorkerNode {
  id: string;
  worker_id: string;
  hostname: string;
  is_leader: boolean;
  last_cycle_summary: Record<string, number> | null;
  first_seen_at: string;
  last_heartbeat_at: string;
  online: boolean;
}

export interface AttackPathGraph {
  nodes: Array<{ id: string; type: string; layer: string }>;
  edges: Array<{ source: string; target: string; via: string; severity: string; path_id: string }>;
}

export interface IncidentScenario {
  id: string;
  title: string;
  severity: Severity;
  summary: string;
  playbook: string;
  created_at: string;
}

export interface SegmentZeroTrustScore {
  segment_id: string;
  segment_name: string;
  zone: string;
  host_count: number;
  device_classes: string[];
  score: number;
  critical_risk_count: number;
  /** GODMODE v2: live threat-signal count (XDR correlations + TI matches + recent UEBA anomalies) folded into the score. */
  dynamic_signal_count: number;
  reasons: string[];
}

export interface TiMatch {
  id: string;
  asset_type: string;
  asset_id: string;
  indicator_kind: 'malicious_port' | 'targeted_cve';
  indicator_value: string;
  label: string;
  severity: Severity;
  detected_at: string;
}

export interface UebaAnomaly {
  id: string;
  host_id: string;
  kind: 'new-service-port' | 'service-count-spike';
  details: Record<string, unknown>;
  severity: Severity;
  detected_at: string;
}

export interface EdrDetection {
  id: string;
  asset_type: string;
  asset_id: string;
  kind: string;
  details: Record<string, unknown>;
  severity: Severity;
  detected_at: string;
}

export interface SegmentationRecommendation {
  id: string;
  segment_id: string;
  host_id?: string | null;
  recommendation: string;
  rationale: string;
  target_zone?: string | null;
  status: 'open' | 'applied' | 'dismissed';
  created_at: string;
}

export interface HardeningRecommendation {
  id: string;
  asset_type: string;
  asset_id: string;
  risk_id?: string | null;
  action: string;
  rationale: string;
  severity: Severity;
  status: 'open' | 'applied' | 'dismissed';
  created_at: string;
}

export interface TimelineEvent {
  id: string;
  source: 'risk' | 'violation' | 'secret' | 'ti' | 'ueba' | 'edr';
  asset_type: string;
  asset_id: string;
  severity: Severity;
  summary: string;
  occurred_at: string;
  cluster_id: string;
}

export interface SandboxSimulationStep {
  hop_index: number;
  asset_type: string;
  asset_id: string;
  via: string;
  success_probability: number;
  cumulative_probability: number;
  compromised: boolean;
}

export interface SandboxSimulation {
  id: string;
  attack_path_id: string;
  steps: SandboxSimulationStep[];
  overall_success_probability: number;
  hops_compromised: number;
  created_at: string;
}

export interface CloudPosture {
  id: string;
  provider: string;
  host_count: number;
  overprivileged_role_count: number;
  metadata_reachable_count: number;
  mixed_segment_count: number;
  score: number;
  computed_at: string;
}

export interface IcsPosture {
  id: string;
  segment_id?: string | null;
  segment_name: string;
  device_count: number;
  write_risk_count: number;
  gateway_count: number;
  outside_management_zone: boolean;
  score: number;
  computed_at: string;
}

export interface XdrDetection {
  id: string;
  asset_type: string;
  asset_id: string;
  sources: string[];
  composite_score: number;
  severity: Severity;
  summary: string;
  detected_at: string;
}

export interface RemediationPlan {
  id: string;
  asset_type: string;
  asset_id: string;
  risk_id?: string | null;
  priority: number;
  title: string;
  steps: string[];
  severity: Severity;
  status: 'open' | 'in_progress' | 'done' | 'dismissed';
  created_at: string;
}

export interface DashboardSummary {
  asset_count: number;
  hosts: number;
  containers: number;
  services: number;
  global_risk_score: number;
  open_violations: number;
  incident_scenarios: number;
}

export interface SimulationCampaign {
  id: string;
  path_count: number;
  avg_success_probability: number;
  max_success_probability: number;
  worst_attack_path_id?: string | null;
  simulation_ids: string[];
  created_at: string;
}

export interface QuantumTrend {
  samples: number;
  slope: number;
  current_score: number;
  forecast_next: number;
  direction: 'increasing' | 'decreasing' | 'stable';
  message?: string;
}

export interface QuantumOutlier {
  id: string;
  asset_type: string;
  asset_id: string;
  score: number;
  mean: number;
  stddev: number;
  z_score: number;
  computed_at: string;
}

export type Role = 'admin' | 'analyst' | 'readonly';

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  created_at: string;
}

export interface AuthToken {
  id: string;
  name: string;
  role: Role;
  tenant_id?: string | null;
  created_at: string;
  revoked_at?: string | null;
}
