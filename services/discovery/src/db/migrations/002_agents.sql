CREATE TABLE IF NOT EXISTS agents (
  did TEXT PRIMARY KEY REFERENCES identities(did) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  url TEXT NOT NULL,
  version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
  provider JSONB,
  capabilities JSONB NOT NULL DEFAULT '{}',
  skills JSONB NOT NULL DEFAULT '[]',
  default_input_modes JSONB DEFAULT '[]',
  default_output_modes JSONB DEFAULT '[]',
  status VARCHAR(16) NOT NULL DEFAULT 'online',
  heartbeat_at TIMESTAMP NOT NULL DEFAULT NOW(),
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_skills ON agents USING GIN (skills);
CREATE INDEX idx_agents_capabilities ON agents USING GIN (capabilities);
CREATE INDEX idx_agents_heartbeat ON agents(heartbeat_at);
