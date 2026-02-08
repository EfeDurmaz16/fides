-- Initial schema for FIDES Trust Graph Service

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Identities table
CREATE TABLE identities (
  did TEXT PRIMARY KEY,
  public_key BYTEA NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}',
  first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
  last_seen TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Trust edges table
CREATE TABLE trust_edges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_did TEXT NOT NULL REFERENCES identities(did),
  target_did TEXT NOT NULL REFERENCES identities(did),
  trust_level SMALLINT NOT NULL CHECK (trust_level >= 0 AND trust_level <= 100),
  attestation JSONB NOT NULL,
  signature BYTEA NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP,
  revoked_at TIMESTAMP,
  UNIQUE(source_did, target_did)
);

-- Indexes for trust edges
CREATE INDEX idx_trust_edges_source ON trust_edges(source_did) WHERE revoked_at IS NULL;
CREATE INDEX idx_trust_edges_target ON trust_edges(target_did) WHERE revoked_at IS NULL;
CREATE INDEX idx_trust_edges_expires ON trust_edges(expires_at) WHERE expires_at IS NOT NULL AND revoked_at IS NULL;

-- Key history table
CREATE TABLE key_history (
  did TEXT NOT NULL REFERENCES identities(did),
  public_key BYTEA NOT NULL,
  successor_key BYTEA,
  succession_signature BYTEA,
  active_from TIMESTAMP NOT NULL DEFAULT NOW(),
  active_until TIMESTAMP,
  PRIMARY KEY (did, public_key)
);

-- Reputation scores table
CREATE TABLE reputation_scores (
  did TEXT PRIMARY KEY REFERENCES identities(did),
  score DOUBLE PRECISION NOT NULL,
  direct_trusters INTEGER NOT NULL DEFAULT 0,
  transitive_trusters INTEGER NOT NULL DEFAULT 0,
  last_computed TIMESTAMP NOT NULL DEFAULT NOW()
);
