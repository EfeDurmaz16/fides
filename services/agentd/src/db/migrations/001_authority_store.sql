CREATE TABLE IF NOT EXISTS agentd_schema_migrations (
  id TEXT PRIMARY KEY,
  checksum TEXT,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE agentd_schema_migrations
  ADD COLUMN IF NOT EXISTS checksum TEXT;

CREATE TABLE IF NOT EXISTS agentd_delegation_nonces (
  nonce TEXT PRIMARY KEY,
  record JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agentd_sessions (
  id TEXT PRIMARY KEY,
  delegatee_did TEXT NOT NULL,
  session JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agentd_evidence_chains (
  did TEXT PRIMARY KEY,
  chain JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agentd_revocations (
  did TEXT PRIMARY KEY,
  record JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agentd_incidents (
  id TEXT PRIMARY KEY,
  actor_did TEXT NOT NULL,
  record JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agentd_authority_propagations (
  id TEXT PRIMARY KEY,
  actor_did TEXT NOT NULL,
  record_type TEXT NOT NULL,
  record_id TEXT NOT NULL,
  target TEXT NOT NULL,
  path TEXT NOT NULL,
  body JSONB NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  next_attempt_at TIMESTAMPTZ NOT NULL,
  record JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agentd_sessions_delegatee
  ON agentd_sessions(delegatee_did);

CREATE INDEX IF NOT EXISTS idx_agentd_incidents_actor
  ON agentd_incidents(actor_did);

CREATE INDEX IF NOT EXISTS idx_agentd_propagations_pending
  ON agentd_authority_propagations(status, next_attempt_at);

INSERT INTO agentd_schema_migrations (id, checksum)
VALUES ('001_authority_store', '644aa2331e775ad73b7c971282d7d9850a0cb4a5dd531cc7901764dbe77d214d')
ON CONFLICT (id) DO UPDATE SET checksum = EXCLUDED.checksum
WHERE agentd_schema_migrations.checksum IS NULL;
