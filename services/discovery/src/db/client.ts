import { drizzle } from 'drizzle-orm/postgres-js'
import { createHash } from 'node:crypto'
import postgres from 'postgres'
import * as schema from './schema.js'

const DEV_FALLBACK = 'postgresql://fides:fides@localhost:5432/fides'

function getConnectionString(): string {
  const url = process.env.DATABASE_URL
  if (url) return url

  if (process.env.NODE_ENV === 'production') {
    throw new Error('DATABASE_URL must be set in production')
  }

  console.warn('DATABASE_URL not set — using development fallback')
  return DEV_FALLBACK
}

const poolConfig = {
  max: parseInt(process.env.DB_POOL_MAX || '10', 10),
  idle_timeout: 20,
  connect_timeout: 10,
}

const connectionString = getConnectionString()

export const sql = postgres(connectionString, poolConfig)
export const db = drizzle(sql, { schema })

export const DISCOVERY_MIGRATIONS = [
  {
    id: '001_initial',
    statements: [
      `CREATE TABLE IF NOT EXISTS identities (
  did TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}',
  domain TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
)`,
      'CREATE INDEX IF NOT EXISTS idx_identities_domain ON identities (domain) WHERE domain IS NOT NULL',
    ],
  },
  {
    id: '002_agents',
    statements: [
      `CREATE TABLE IF NOT EXISTS agents (
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
)`,
      'CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)',
      'CREATE INDEX IF NOT EXISTS idx_agents_skills ON agents USING GIN (skills)',
      'CREATE INDEX IF NOT EXISTS idx_agents_capabilities ON agents USING GIN (capabilities)',
      'CREATE INDEX IF NOT EXISTS idx_agents_heartbeat ON agents(heartbeat_at)',
    ],
  },
  {
    id: '003_identity_domain_verification',
    statements: [
      `ALTER TABLE identities
  ADD COLUMN IF NOT EXISTS domain_verified BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS domain_verified_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS verification_method VARCHAR(32)`,
      `CREATE INDEX IF NOT EXISTS idx_identities_domain_verified
  ON identities(domain_verified)
  WHERE domain_verified = TRUE`,
    ],
  },
  {
    id: '004_organization_domain_verification',
    statements: [
      `ALTER TABLE identities
  ADD COLUMN IF NOT EXISTS organization_domain TEXT,
  ADD COLUMN IF NOT EXISTS organization_domain_verified BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS organization_domain_verified_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS organization_verification_method VARCHAR(32)`,
      `CREATE INDEX IF NOT EXISTS idx_identities_organization_domain_verified
  ON identities(organization_domain_verified)
  WHERE organization_domain_verified = TRUE`,
      'CREATE INDEX IF NOT EXISTS idx_identities_organization_domain ON identities(organization_domain)',
    ],
  },
] as const

export async function ensureDiscoveryDatabaseReady(client: postgres.Sql = sql): Promise<void> {
  if (process.env.DISCOVERY_DB_AUTO_MIGRATE === 'false') {
    await assertDiscoverySchema(client)
    return
  }
  await runDiscoveryMigrations(client)
}

export async function runDiscoveryMigrations(client: postgres.Sql): Promise<void> {
  await client`SELECT pg_advisory_lock(hashtext('discovery_migrations'))`

  try {
    await ensureDiscoveryMigrationLedger(client)
    for (const migration of DISCOVERY_MIGRATIONS) {
      const checksum = discoveryMigrationChecksum(migration)
      const existing = await client`
        SELECT id, checksum
        FROM discovery_schema_migrations
        WHERE id = ${migration.id}
        LIMIT 1
      `
      if (existing.length > 0) {
        const appliedChecksum = existing[0]?.checksum as string | null | undefined
        if (appliedChecksum && appliedChecksum !== checksum) {
          throw new Error(`discovery migration ${migration.id} checksum mismatch`)
        }
        if (!appliedChecksum) {
          await client`
            UPDATE discovery_schema_migrations
            SET checksum = ${checksum}
            WHERE id = ${migration.id}
          `
        }
        continue
      }

      for (const statement of migration.statements) {
        await client.unsafe(statement)
      }

      await client`INSERT INTO discovery_schema_migrations (id, checksum) VALUES (${migration.id}, ${checksum})`
    }
  } finally {
    await client`SELECT pg_advisory_unlock(hashtext('discovery_migrations'))`
  }
}

async function ensureDiscoveryMigrationLedger(client: postgres.Sql): Promise<void> {
  await client`
    CREATE TABLE IF NOT EXISTS discovery_schema_migrations (
      id TEXT PRIMARY KEY,
      checksum TEXT,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `
  await client`ALTER TABLE discovery_schema_migrations ADD COLUMN IF NOT EXISTS checksum TEXT`
}

async function assertDiscoverySchema(client: postgres.Sql): Promise<void> {
  const rows = await client`
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = current_schema()
      AND table_name IN ('identities', 'agents', 'discovery_schema_migrations')
  `
  if (rows.length !== 3) {
    throw new Error('discovery schema is not migrated')
  }

  const columns = await client`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'identities'
      AND column_name IN (
        'domain_verified',
        'domain_verified_at',
        'verification_method',
        'organization_domain',
        'organization_domain_verified',
        'organization_domain_verified_at',
        'organization_verification_method'
      )
  `
  if (columns.length !== 7) {
    throw new Error('discovery schema is not migrated')
  }

  const applied = await client`
    SELECT id, checksum
    FROM discovery_schema_migrations
    WHERE id IN ${client(DISCOVERY_MIGRATIONS.map(migration => migration.id))}
  `
  if (applied.length !== DISCOVERY_MIGRATIONS.length) {
    throw new Error('discovery schema is not migrated')
  }
  const checksums = new Map(applied.map(row => [row.id as string, row.checksum as string | null]))
  for (const migration of DISCOVERY_MIGRATIONS) {
    if (checksums.get(migration.id) !== discoveryMigrationChecksum(migration)) {
      throw new Error(`discovery migration ${migration.id} checksum mismatch`)
    }
  }
}

function discoveryMigrationChecksum(migration: typeof DISCOVERY_MIGRATIONS[number]): string {
  return createHash('sha256')
    .update(migration.statements.join('\n'))
    .digest('hex')
}
