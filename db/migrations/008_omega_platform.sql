-- Adds tables for OMEGA-tier capabilities: distributed worker node
-- visibility (heartbeat registry) and a minimal audit log for write
-- operations, the foundation for real "Enterprise" traceability without
-- pretending to be a full multi-tenant RBAC system.

CREATE TABLE IF NOT EXISTS worker_nodes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  worker_id TEXT NOT NULL UNIQUE, -- stable per-process UUID from distributedLock.workerId()
  hostname TEXT NOT NULL,
  is_leader BOOLEAN NOT NULL DEFAULT false, -- held the distributed cycle lock on its last heartbeat
  last_cycle_summary JSONB,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_worker_nodes_last_heartbeat ON worker_nodes(last_heartbeat_at);

CREATE TABLE IF NOT EXISTS audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action TEXT NOT NULL, -- e.g. "policies.evaluate", "secrets.ingest", "policy.delete"
  actor TEXT NOT NULL DEFAULT 'api-token', -- caller identity — "api-token" (default) or a named token if API_TOKENS maps one
  detail JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
