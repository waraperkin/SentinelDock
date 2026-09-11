-- Adds columns/tables for the "advanced platform" capability set: ICS/OT and
-- cloud device classification, secret findings, and MITRE ATT&CK technique
-- tagging on attack path hops (stored inline in the existing JSONB `hops`
-- column — no schema change needed there).

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS device_class TEXT NOT NULL DEFAULT 'it';
-- device_class: it | ics | cloud

ALTER TABLE services ADD COLUMN IF NOT EXISTS protocol_family TEXT;
-- protocol_family: modbus | s7 | bacnet | opcua | cloud-metadata | null (generic)

CREATE TABLE IF NOT EXISTS secrets_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_type TEXT NOT NULL,
  asset_id UUID NOT NULL,
  kind TEXT NOT NULL, -- aws_access_key | private_key | generic_api_key | generic_password
  match_preview TEXT NOT NULL, -- redacted preview, never the full secret
  source TEXT NOT NULL, -- e.g. "container_env:MY_VAR", "banner"
  severity TEXT NOT NULL DEFAULT 'high',
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_secrets_findings_asset ON secrets_findings(asset_type, asset_id);
