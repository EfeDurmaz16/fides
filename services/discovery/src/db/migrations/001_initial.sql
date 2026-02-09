-- Discovery Service: Initial Schema
-- Creates the identities table for DID registration and resolution

CREATE TABLE IF NOT EXISTS identities (
  did TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}',
  domain TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identities_domain ON identities (domain) WHERE domain IS NOT NULL;
