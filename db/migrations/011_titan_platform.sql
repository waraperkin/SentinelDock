-- TITAN tier: Threat Intelligence (local), UEBA-lite, EDR-lite, SIEM-lite
-- (correlated read over existing tables, no new storage needed for it),
-- Auto-Segmentation recommendations, Auto-Hardening recommendations.

CREATE TABLE IF NOT EXISTS ti_matches (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_type TEXT NOT NULL,
  asset_id UUID NOT NULL,
  indicator_kind TEXT NOT NULL, -- malicious_port | targeted_cve
  indicator_value TEXT NOT NULL, -- the port number or CVE id that matched
  label TEXT NOT NULL, -- human-readable campaign/tooling name from the local curated dataset
  severity TEXT NOT NULL DEFAULT 'high',
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ti_matches_asset ON ti_matches(asset_type, asset_id);
CREATE INDEX IF NOT EXISTS idx_ti_matches_detected_at ON ti_matches(detected_at);

-- Rolling per-host baseline of observed service ports, used by UEBA-lite to
-- detect deviations (new ports, sudden service-count spikes) on later runs.
CREATE TABLE IF NOT EXISTS ueba_baselines (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  host_id UUID NOT NULL UNIQUE REFERENCES hosts(id) ON DELETE CASCADE,
  port_set INTEGER[] NOT NULL DEFAULT '{}',
  service_count INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ueba_anomalies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, -- new-service-port | service-count-spike
  details JSONB NOT NULL DEFAULT '{}',
  severity TEXT NOT NULL DEFAULT 'medium',
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_host ON ueba_anomalies(host_id);
CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_detected_at ON ueba_anomalies(detected_at);

CREATE TABLE IF NOT EXISTS edr_detections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_type TEXT NOT NULL,
  asset_id UUID NOT NULL,
  kind TEXT NOT NULL, -- suspicious-port | suspicious-container-image | privileged-container-on-ics-host
  details JSONB NOT NULL DEFAULT '{}',
  severity TEXT NOT NULL DEFAULT 'high',
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_edr_detections_asset ON edr_detections(asset_type, asset_id);
CREATE INDEX IF NOT EXISTS idx_edr_detections_detected_at ON edr_detections(detected_at);

CREATE TABLE IF NOT EXISTS segmentation_recommendations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  segment_id UUID NOT NULL REFERENCES network_segments(id) ON DELETE CASCADE,
  host_id UUID REFERENCES hosts(id) ON DELETE CASCADE,
  recommendation TEXT NOT NULL,
  rationale TEXT NOT NULL,
  target_zone TEXT,
  status TEXT NOT NULL DEFAULT 'open', -- open | applied | dismissed
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_segmentation_recommendations_segment ON segmentation_recommendations(segment_id);
CREATE INDEX IF NOT EXISTS idx_segmentation_recommendations_status ON segmentation_recommendations(status);

CREATE TABLE IF NOT EXISTS hardening_recommendations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_type TEXT NOT NULL,
  asset_id UUID NOT NULL,
  risk_id UUID REFERENCES risks(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  rationale TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'medium',
  status TEXT NOT NULL DEFAULT 'open', -- open | applied | dismissed
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_hardening_recommendations_asset ON hardening_recommendations(asset_type, asset_id);
CREATE INDEX IF NOT EXISTS idx_hardening_recommendations_status ON hardening_recommendations(status);
