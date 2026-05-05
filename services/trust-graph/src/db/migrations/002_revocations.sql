-- Authority revocation records propagated from agentd.

CREATE TABLE IF NOT EXISTS revocation_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  did TEXT NOT NULL,
  reason TEXT NOT NULL,
  revoked_by TEXT NOT NULL,
  record JSONB NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_revocation_records_did ON revocation_records(did);

CREATE TABLE IF NOT EXISTS incident_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_did TEXT NOT NULL REFERENCES identities(did),
  type TEXT NOT NULL,
  severity TEXT NOT NULL,
  description TEXT NOT NULL,
  evidence_refs JSONB NOT NULL DEFAULT '[]',
  reported_at TIMESTAMP NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMP,
  trust_penalty DOUBLE PRECISION NOT NULL DEFAULT 0,
  reputation_penalty DOUBLE PRECISION NOT NULL DEFAULT 0,
  capabilities_revoked JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_incident_records_actor ON incident_records(actor_did);
