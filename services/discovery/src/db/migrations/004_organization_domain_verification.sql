ALTER TABLE identities
  ADD COLUMN IF NOT EXISTS organization_domain TEXT,
  ADD COLUMN IF NOT EXISTS organization_domain_verified BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS organization_domain_verified_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS organization_verification_method VARCHAR(32);

CREATE INDEX IF NOT EXISTS idx_identities_organization_domain_verified
  ON identities(organization_domain_verified)
  WHERE organization_domain_verified = TRUE;

CREATE INDEX IF NOT EXISTS idx_identities_organization_domain
  ON identities(organization_domain);
