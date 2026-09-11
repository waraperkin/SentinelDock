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
  exposed_publicly: boolean;
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
  hops: Array<{ asset_type: string; asset_id: string; via: string }>;
  blast_radius: number;
  severity: Severity;
}

export interface AttackPathGraph {
  nodes: Array<{ id: string; type: string }>;
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

export interface DashboardSummary {
  asset_count: number;
  hosts: number;
  containers: number;
  services: number;
  global_risk_score: number;
  open_violations: number;
  incident_scenarios: number;
}
