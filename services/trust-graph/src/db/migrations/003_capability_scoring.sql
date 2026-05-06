-- Capability-scoped trust edges and per-capability reputation state.

ALTER TABLE trust_edges ADD COLUMN IF NOT EXISTS capability_id TEXT;
ALTER TABLE trust_edges ADD COLUMN IF NOT EXISTS context TEXT;

ALTER TABLE trust_edges DROP CONSTRAINT IF EXISTS trust_edges_source_did_target_did_key;

CREATE UNIQUE INDEX IF NOT EXISTS unique_source_target
  ON trust_edges(source_did, target_did, capability_id);

CREATE INDEX IF NOT EXISTS idx_trust_edges_capability ON trust_edges(capability_id);

CREATE TABLE IF NOT EXISTS capability_scores (
  did TEXT NOT NULL REFERENCES identities(did),
  capability_id TEXT NOT NULL,
  score DOUBLE PRECISION NOT NULL,
  invocation_count INTEGER NOT NULL DEFAULT 0,
  incident_count INTEGER NOT NULL DEFAULT 0,
  last_computed TIMESTAMP NOT NULL DEFAULT NOW(),
  PRIMARY KEY (did, capability_id)
);
