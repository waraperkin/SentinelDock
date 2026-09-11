-- GODMODE tier: Network Sandbox Engine, CLOUDMASTER (cloud posture),
-- ICSMASTER (ICS posture), XDR-lite (multi-source correlation),
-- Auto-Remediation Engine (prioritized plans). Zero Trust v2 and
-- Distributed Evaluation v2 extend existing engines/tables and need no
-- new schema.

-- Network Sandbox Engine: each row is one non-destructive simulation run
-- over an existing attack path — pure computation against already-
-- collected data, never a real network action. Append-only (a history of
-- simulation runs is useful), unlike the idempotent-snapshot tables below.
CREATE TABLE IF NOT EXISTS sandbox_simulations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  attack_path_id UUID NOT NULL REFERENCES attack_paths(id) ON DELETE CASCADE,
  steps JSONB NOT NULL DEFAULT '[]', -- [{hop_index, asset_type, asset_id, via, success_probability, cumulative_probability, compromised}]
  overall_success_probability NUMERIC(5,4) NOT NULL DEFAULT 0,
  hops_compromised INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sandbox_simulations_attack_path ON sandbox_simulations(attack_path_id);
CREATE INDEX IF NOT EXISTS idx_sandbox_simulations_created_at ON sandbox_simulations(created_at);

-- CLOUDMASTER: idempotent per-provider cloud security posture snapshot,
-- regenerated every evaluation cycle (same DELETE+reinsert pattern as
-- ti_matches/edr_detections — a property of *current* posture).
CREATE TABLE IF NOT EXISTS cloud_posture (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider TEXT NOT NULL,
  host_count INTEGER NOT NULL DEFAULT 0,
  overprivileged_role_count INTEGER NOT NULL DEFAULT 0,
  metadata_reachable_count INTEGER NOT NULL DEFAULT 0,
  mixed_segment_count INTEGER NOT NULL DEFAULT 0,
  score NUMERIC(5,2) NOT NULL DEFAULT 0,
  computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ICSMASTER: idempotent per-segment ICS/OT security posture snapshot.
CREATE TABLE IF NOT EXISTS ics_posture (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  segment_id UUID REFERENCES network_segments(id) ON DELETE CASCADE,
  segment_name TEXT NOT NULL,
  device_count INTEGER NOT NULL DEFAULT 0,
  write_risk_count INTEGER NOT NULL DEFAULT 0,
  gateway_count INTEGER NOT NULL DEFAULT 0,
  outside_management_zone BOOLEAN NOT NULL DEFAULT false,
  score NUMERIC(5,2) NOT NULL DEFAULT 0,
  computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- XDR-lite: idempotent multi-source correlation results — only assets hit
-- by 2+ distinct detection sources get a row, since that cross-source
-- correlation is the actual signal XDR adds over any single source alone.
CREATE TABLE IF NOT EXISTS xdr_detections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_type TEXT NOT NULL,
  asset_id UUID NOT NULL,
  sources TEXT[] NOT NULL DEFAULT '{}', -- e.g. {ti, edr, ueba, violation}
  composite_score NUMERIC(5,2) NOT NULL DEFAULT 0,
  severity TEXT NOT NULL DEFAULT 'medium',
  summary TEXT NOT NULL,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_xdr_detections_asset ON xdr_detections(asset_type, asset_id);

-- Auto-Remediation Engine: prioritized, ordered remediation plans —
-- recommendations only, same idempotent-regeneration pattern as
-- hardening_recommendations/segmentation_recommendations.
CREATE TABLE IF NOT EXISTS remediation_plans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_type TEXT NOT NULL,
  asset_id UUID NOT NULL,
  risk_id UUID REFERENCES risks(id) ON DELETE SET NULL,
  priority INTEGER NOT NULL DEFAULT 0, -- higher = more urgent
  title TEXT NOT NULL,
  steps JSONB NOT NULL DEFAULT '[]', -- ordered array of plain-text steps
  severity TEXT NOT NULL DEFAULT 'medium',
  status TEXT NOT NULL DEFAULT 'open', -- open | in_progress | done | dismissed
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_remediation_plans_priority ON remediation_plans(priority DESC);
CREATE INDEX IF NOT EXISTS idx_remediation_plans_status ON remediation_plans(status);
