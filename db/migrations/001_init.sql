-- AegisGrid initial schema
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE network_segments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  cidr TEXT NOT NULL,
  zone TEXT NOT NULL DEFAULT 'internal', -- internal | dmz | public | management
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hosts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  hostname TEXT NOT NULL,
  os TEXT,
  os_version TEXT,
  ip_address TEXT,
  role TEXT NOT NULL DEFAULT 'generic', -- generic | database | web | bastion | worker | lb
  network_segment_id UUID REFERENCES network_segments(id) ON DELETE SET NULL,
  criticality TEXT NOT NULL DEFAULT 'medium', -- low | medium | high | critical
  last_seen TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_hosts_segment ON hosts(network_segment_id);
CREATE INDEX idx_hosts_role ON hosts(role);

CREATE TABLE containers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  host_id UUID REFERENCES hosts(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  image TEXT NOT NULL,
  image_tag TEXT,
  status TEXT NOT NULL DEFAULT 'running', -- running | stopped | paused
  ports JSONB NOT NULL DEFAULT '[]', -- [{container:80, host:8080, protocol:"tcp"}]
  privileged BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_containers_host ON containers(host_id);

CREATE TABLE services (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  host_id UUID REFERENCES hosts(id) ON DELETE CASCADE,
  container_id UUID REFERENCES containers(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  port INTEGER NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'tcp',
  bind_address TEXT NOT NULL DEFAULT '0.0.0.0',
  banner TEXT,
  version TEXT,
  exposed_publicly BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_services_host ON services(host_id);
CREATE INDEX idx_services_container ON services(container_id);
CREATE INDEX idx_services_port ON services(port);

CREATE TABLE dependencies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_asset_type TEXT NOT NULL, -- host | container | service
  source_asset_id UUID NOT NULL,
  target_asset_type TEXT NOT NULL,
  target_asset_id UUID NOT NULL,
  relation TEXT NOT NULL DEFAULT 'connects_to', -- connects_to | depends_on | routes_to
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_dependencies_source ON dependencies(source_asset_type, source_asset_id);
CREATE INDEX idx_dependencies_target ON dependencies(target_asset_type, target_asset_id);

CREATE TABLE config_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_type TEXT NOT NULL, -- host | container | service | network
  asset_id UUID NOT NULL,
  kind TEXT NOT NULL, -- os | docker | network | service
  data JSONB NOT NULL,
  collected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_config_snapshots_asset ON config_snapshots(asset_type, asset_id);
CREATE INDEX idx_config_snapshots_collected_at ON config_snapshots(collected_at);

CREATE TABLE policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL DEFAULT 'medium', -- low | medium | high | critical
  recommendation TEXT,
  conditions JSONB NOT NULL, -- policy DSL, see policies/*.yaml
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_policies_severity ON policies(severity);

CREATE TABLE policy_violations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
  asset_type TEXT NOT NULL,
  asset_id UUID NOT NULL,
  severity TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'open', -- open | acknowledged | resolved
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ
);
CREATE INDEX idx_violations_policy ON policy_violations(policy_id);
CREATE INDEX idx_violations_asset ON policy_violations(asset_type, asset_id);
CREATE INDEX idx_violations_severity ON policy_violations(severity);
CREATE INDEX idx_violations_status ON policy_violations(status);

CREATE TABLE risks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_type TEXT NOT NULL,
  asset_id UUID NOT NULL,
  category TEXT NOT NULL, -- exposure | misconfiguration | segmentation | patching
  severity TEXT NOT NULL, -- low | medium | high | critical
  score NUMERIC(5,2) NOT NULL DEFAULT 0,
  summary TEXT NOT NULL,
  source_violation_ids UUID[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_risks_asset ON risks(asset_type, asset_id);
CREATE INDEX idx_risks_severity ON risks(severity);
CREATE INDEX idx_risks_category ON risks(category);

CREATE TABLE attack_paths (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  entry_asset_type TEXT NOT NULL,
  entry_asset_id UUID NOT NULL,
  target_asset_type TEXT NOT NULL,
  target_asset_id UUID NOT NULL,
  hops JSONB NOT NULL DEFAULT '[]', -- [{asset_type, asset_id, via}]
  blast_radius INTEGER NOT NULL DEFAULT 0,
  severity TEXT NOT NULL DEFAULT 'medium',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_attack_paths_entry ON attack_paths(entry_asset_type, entry_asset_id);
CREATE INDEX idx_attack_paths_severity ON attack_paths(severity);

CREATE TABLE incident_scenarios (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'medium',
  risk_id UUID REFERENCES risks(id) ON DELETE SET NULL,
  attack_path_id UUID REFERENCES attack_paths(id) ON DELETE SET NULL,
  summary TEXT NOT NULL,
  playbook TEXT NOT NULL, -- markdown
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_incident_scenarios_severity ON incident_scenarios(severity);
