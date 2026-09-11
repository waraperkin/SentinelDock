-- Adds lightweight vulnerability tracking to services, populated by the
-- backend's static vulnerability scanner (see backend/src/services/vulnerabilityScanner.ts).
ALTER TABLE services ADD COLUMN IF NOT EXISTS cve_ids TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE services ADD COLUMN IF NOT EXISTS cvss_score NUMERIC(3,1);

CREATE INDEX IF NOT EXISTS idx_services_cve ON services USING GIN (cve_ids);
