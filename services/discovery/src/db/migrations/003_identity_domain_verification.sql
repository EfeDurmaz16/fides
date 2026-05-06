ALTER TABLE identities
  ADD COLUMN IF NOT EXISTS domain_verified BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS domain_verified_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS verification_method VARCHAR(32);

CREATE INDEX IF NOT EXISTS idx_identities_domain_verified
  ON identities(domain_verified)
  WHERE domain_verified = TRUE;
