import postgres from 'postgres'
import { drizzle } from 'drizzle-orm/postgres-js'
import { createHash } from 'node:crypto'
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

export function createDbClient() {
  const connectionString = getConnectionString()
  const connection = postgres(connectionString, poolConfig)
  return drizzle(connection, { schema })
}

/** Raw postgres connection for shutdown/health checks */
export function createRawClient() {
  const connectionString = getConnectionString()
  return postgres(connectionString, poolConfig)
}

export type DbClient = ReturnType<typeof createDbClient>

export const TRUST_GRAPH_MIGRATIONS = [
  {
    id: '001_initial',
    statements: [
      'CREATE EXTENSION IF NOT EXISTS "pgcrypto"',
      `CREATE TABLE IF NOT EXISTS identities (
  did TEXT PRIMARY KEY,
  public_key BYTEA NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}',
  first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
  last_seen TIMESTAMP NOT NULL DEFAULT NOW()
)`,
      `CREATE TABLE IF NOT EXISTS trust_edges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_did TEXT NOT NULL REFERENCES identities(did),
  target_did TEXT NOT NULL REFERENCES identities(did),
  trust_level SMALLINT NOT NULL CHECK (trust_level >= 0 AND trust_level <= 100),
  attestation JSONB NOT NULL,
  signature BYTEA NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP,
  revoked_at TIMESTAMP
)`,
      `CREATE TABLE IF NOT EXISTS key_history (
  did TEXT NOT NULL REFERENCES identities(did),
  public_key BYTEA NOT NULL,
  successor_key BYTEA,
  succession_signature BYTEA,
  active_from TIMESTAMP NOT NULL DEFAULT NOW(),
  active_until TIMESTAMP,
  PRIMARY KEY (did, public_key)
)`,
      `CREATE TABLE IF NOT EXISTS reputation_scores (
  did TEXT PRIMARY KEY REFERENCES identities(did),
  score DOUBLE PRECISION NOT NULL,
  direct_trusters INTEGER NOT NULL DEFAULT 0,
  transitive_trusters INTEGER NOT NULL DEFAULT 0,
  last_computed TIMESTAMP NOT NULL DEFAULT NOW()
)`,
      'CREATE INDEX IF NOT EXISTS idx_trust_edges_source ON trust_edges(source_did)',
      'CREATE INDEX IF NOT EXISTS idx_trust_edges_target ON trust_edges(target_did)',
      'CREATE INDEX IF NOT EXISTS idx_trust_edges_expires ON trust_edges(expires_at) WHERE expires_at IS NOT NULL AND revoked_at IS NULL',
    ],
  },
  {
    id: '002_revocations',
    statements: [
      `CREATE TABLE IF NOT EXISTS revocation_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  did TEXT NOT NULL,
  reason TEXT NOT NULL,
  revoked_by TEXT NOT NULL,
  record JSONB NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
)`,
      'CREATE INDEX IF NOT EXISTS idx_revocation_records_did ON revocation_records(did)',
      `CREATE TABLE IF NOT EXISTS incident_records (
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
)`,
      'CREATE INDEX IF NOT EXISTS idx_incident_records_actor ON incident_records(actor_did)',
    ],
  },
  {
    id: '003_capability_scoring',
    statements: [
      'ALTER TABLE trust_edges ADD COLUMN IF NOT EXISTS capability_id TEXT',
      'ALTER TABLE trust_edges ADD COLUMN IF NOT EXISTS context TEXT',
      'ALTER TABLE trust_edges DROP CONSTRAINT IF EXISTS trust_edges_source_did_target_did_key',
      `CREATE UNIQUE INDEX IF NOT EXISTS unique_source_target
  ON trust_edges(source_did, target_did, capability_id)`,
      'CREATE INDEX IF NOT EXISTS idx_trust_edges_capability ON trust_edges(capability_id)',
      `CREATE TABLE IF NOT EXISTS capability_scores (
  did TEXT NOT NULL REFERENCES identities(did),
  capability_id TEXT NOT NULL,
  score DOUBLE PRECISION NOT NULL,
  invocation_count INTEGER NOT NULL DEFAULT 0,
  incident_count INTEGER NOT NULL DEFAULT 0,
  last_computed TIMESTAMP NOT NULL DEFAULT NOW(),
  PRIMARY KEY (did, capability_id)
)`,
    ],
  },
] as const

export async function ensureTrustGraphDatabaseReady(client: postgres.Sql): Promise<void> {
  if (process.env.TRUST_GRAPH_DB_AUTO_MIGRATE === 'false') {
    await assertTrustGraphSchema(client)
    return
  }
  await runTrustGraphMigrations(client)
}

export async function runTrustGraphMigrations(client: postgres.Sql): Promise<void> {
  await client`SELECT pg_advisory_lock(hashtext('trust_graph_migrations'))`

  try {
    await ensureTrustGraphMigrationLedger(client)
    for (const migration of TRUST_GRAPH_MIGRATIONS) {
      const checksum = trustGraphMigrationChecksum(migration)
      const existing = await client`
        SELECT id, checksum
        FROM trust_graph_schema_migrations
        WHERE id = ${migration.id}
        LIMIT 1
      `
      if (existing.length > 0) {
        const appliedChecksum = existing[0]?.checksum as string | null | undefined
        if (appliedChecksum && appliedChecksum !== checksum) {
          throw new Error(`trust graph migration ${migration.id} checksum mismatch`)
        }
        if (!appliedChecksum) {
          await client`
            UPDATE trust_graph_schema_migrations
            SET checksum = ${checksum}
            WHERE id = ${migration.id}
          `
        }
        continue
      }

      for (const statement of migration.statements) {
        await client.unsafe(statement)
      }

      await client`INSERT INTO trust_graph_schema_migrations (id, checksum) VALUES (${migration.id}, ${checksum})`
    }
  } finally {
    await client`SELECT pg_advisory_unlock(hashtext('trust_graph_migrations'))`
  }
}

async function ensureTrustGraphMigrationLedger(client: postgres.Sql): Promise<void> {
  await client`
    CREATE TABLE IF NOT EXISTS trust_graph_schema_migrations (
      id TEXT PRIMARY KEY,
      checksum TEXT,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `
  await client`ALTER TABLE trust_graph_schema_migrations ADD COLUMN IF NOT EXISTS checksum TEXT`
}

async function assertTrustGraphSchema(client: postgres.Sql): Promise<void> {
  const tables = await client`
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = current_schema()
      AND table_name IN (
        'identities',
        'trust_edges',
        'key_history',
        'reputation_scores',
        'revocation_records',
        'incident_records',
        'capability_scores',
        'trust_graph_schema_migrations'
      )
  `
  if (tables.length !== 8) {
    throw new Error('trust graph schema is not migrated')
  }

  const columns = await client`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'trust_edges'
      AND column_name IN ('capability_id', 'context')
  `
  if (columns.length !== 2) {
    throw new Error('trust graph schema is not migrated')
  }

  const applied = await client`
    SELECT id, checksum
    FROM trust_graph_schema_migrations
    WHERE id IN ${client(TRUST_GRAPH_MIGRATIONS.map(migration => migration.id))}
  `
  if (applied.length !== TRUST_GRAPH_MIGRATIONS.length) {
    throw new Error('trust graph schema is not migrated')
  }

  const checksums = new Map(applied.map(row => [row.id as string, row.checksum as string | null]))
  for (const migration of TRUST_GRAPH_MIGRATIONS) {
    if (checksums.get(migration.id) !== trustGraphMigrationChecksum(migration)) {
      throw new Error(`trust graph migration ${migration.id} checksum mismatch`)
    }
  }
}

function trustGraphMigrationChecksum(migration: typeof TRUST_GRAPH_MIGRATIONS[number]): string {
  return createHash('sha256')
    .update(migration.statements.join('\n'))
    .digest('hex')
}
