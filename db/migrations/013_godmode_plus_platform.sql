-- GODMODE+ tier: Attack Simulation Engine (batch campaigns over the
-- existing Network Sandbox Engine), QUANTUM Engine (local statistical
-- risk-trend + outlier analysis — NOT quantum computing, see README),
-- SOVEREIGN Engine (DB-backed RBAC tokens + optional tenant scoping,
-- additive on top of the existing opt-in API_TOKENS env-var auth).
-- OMNIPOTENT Agent findings reuse the existing config_snapshots table
-- (kind = 'omnipotent-agent') — no new table needed for it.

-- Attack Simulation Engine: one row per batch run over ALL current
-- attack paths (each individual path's hop-by-hop result is still a
-- sandbox_simulations row — this table aggregates a full-fleet run).
CREATE TABLE IF NOT EXISTS simulation_campaigns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  path_count INTEGER NOT NULL DEFAULT 0,
  avg_success_probability NUMERIC(6,5) NOT NULL DEFAULT 0,
  max_success_probability NUMERIC(6,5) NOT NULL DEFAULT 0,
  worst_attack_path_id UUID REFERENCES attack_paths(id) ON DELETE SET NULL,
  simulation_ids UUID[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_simulation_campaigns_created_at ON simulation_campaigns(created_at);

-- QUANTUM Engine: append-only global-risk-score time series, sampled once
-- per evaluation cycle, powering the trend/forecast analysis.
CREATE TABLE IF NOT EXISTS risk_score_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  global_score NUMERIC(6,2) NOT NULL DEFAULT 0,
  risk_count INTEGER NOT NULL DEFAULT 0,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_risk_score_snapshots_recorded_at ON risk_score_snapshots(recorded_at);

-- QUANTUM Engine: idempotent per-asset statistical outlier snapshot
-- (z-score of that asset's risk score against the current distribution).
CREATE TABLE IF NOT EXISTS quantum_outliers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_type TEXT NOT NULL,
  asset_id UUID NOT NULL,
  score NUMERIC(6,2) NOT NULL,
  mean NUMERIC(6,2) NOT NULL,
  stddev NUMERIC(6,2) NOT NULL,
  z_score NUMERIC(6,3) NOT NULL,
  computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_quantum_outliers_asset ON quantum_outliers(asset_type, asset_id);

-- SOVEREIGN Engine: multi-tenant scoping (nullable — NULL means the
-- default/global tenant, so existing single-tenant deployments and rows
-- need no migration action) and DB-backed, revocable, role-aware API
-- tokens layered on top of the existing API_TOKENS env-var mechanism
-- (that mechanism is untouched and still works standalone).
CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash TEXT NOT NULL UNIQUE, -- sha256 hex digest; the raw token is never stored
  name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'readonly', -- admin | analyst | readonly
  tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_tenant ON auth_tokens(tenant_id);

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;
ALTER TABLE network_segments ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_tenant ON hosts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_network_segments_tenant ON network_segments(tenant_id);
