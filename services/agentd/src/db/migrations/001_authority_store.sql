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

CREATE INDEX IF NOT EXISTS idx_agentd_sessions_delegatee
  ON agentd_sessions(delegatee_did);

CREATE INDEX IF NOT EXISTS idx_agentd_incidents_actor
  ON agentd_incidents(actor_did);
