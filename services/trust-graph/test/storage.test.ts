import postgres from 'postgres'
import { describe, expect, it } from 'vitest'
import {
  TRUST_GRAPH_MIGRATIONS,
  ensureTrustGraphDatabaseReady,
  runTrustGraphMigrations,
} from '../src/db/client.js'

const postgresUrl = process.env.TRUST_GRAPH_DATABASE_URL || process.env.DATABASE_URL

function postgresUrlWithSearchPath(connectionString: string, schema: string): string {
  const url = new URL(connectionString)
  url.searchParams.set('options', `-c search_path=${schema}`)
  return url.toString()
}

function quoteIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`
}

describe.skipIf(!postgresUrl)('trust graph migrations', () => {
  it('records applied trust graph migrations once with checksums', async () => {
    const schema = `trust_graph_migrations_${crypto.randomUUID().replaceAll('-', '')}`
    const schemaIdentifier = quoteIdentifier(schema)
    const adminSql = postgres(postgresUrl, { max: 1 })
    const scopedSql = postgres(postgresUrlWithSearchPath(postgresUrl, schema), { max: 1 })

    try {
      await adminSql.unsafe(`CREATE SCHEMA ${schemaIdentifier}`)
      await runTrustGraphMigrations(scopedSql)
      await runTrustGraphMigrations(scopedSql)

      const rows = await scopedSql`
        SELECT id, checksum, count(*)::int AS count
        FROM trust_graph_schema_migrations
        WHERE id IN ${scopedSql(TRUST_GRAPH_MIGRATIONS.map(migration => migration.id))}
        GROUP BY id, checksum
      `

      expect(rows).toHaveLength(TRUST_GRAPH_MIGRATIONS.length)
      expect(rows.every(row => row.count === 1)).toBe(true)
      expect(rows.every(row => typeof row.checksum === 'string' && row.checksum.length === 64)).toBe(true)
      await expect(scopedSql`SELECT capability_id, context FROM trust_edges LIMIT 1`).resolves.toBeDefined()
      await expect(scopedSql`SELECT did, capability_id FROM capability_scores LIMIT 1`).resolves.toBeDefined()
    } finally {
      await scopedSql.end()
      await adminSql.unsafe(`DROP SCHEMA IF EXISTS ${schemaIdentifier} CASCADE`)
      await adminSql.end()
    }
  }, 30_000)

  it('fails closed when an applied trust graph migration checksum drifts', async () => {
    const schema = `trust_graph_checksum_${crypto.randomUUID().replaceAll('-', '')}`
    const schemaIdentifier = quoteIdentifier(schema)
    const adminSql = postgres(postgresUrl, { max: 1 })
    const scopedSql = postgres(postgresUrlWithSearchPath(postgresUrl, schema), { max: 1 })

    try {
      await adminSql.unsafe(`CREATE SCHEMA ${schemaIdentifier}`)
      await runTrustGraphMigrations(scopedSql)
      await scopedSql`
        UPDATE trust_graph_schema_migrations
        SET checksum = ${'0'.repeat(64)}
        WHERE id = ${TRUST_GRAPH_MIGRATIONS[0].id}
      `

      await expect(runTrustGraphMigrations(scopedSql)).rejects.toThrow('checksum mismatch')
    } finally {
      await scopedSql.end()
      await adminSql.unsafe(`DROP SCHEMA IF EXISTS ${schemaIdentifier} CASCADE`)
      await adminSql.end()
    }
  }, 30_000)

  it('fails closed without manual migrations when auto-migrate is disabled', async () => {
    const schema = `trust_graph_manual_${crypto.randomUUID().replaceAll('-', '')}`
    const schemaIdentifier = quoteIdentifier(schema)
    const adminSql = postgres(postgresUrl, { max: 1 })
    const scopedSql = postgres(postgresUrlWithSearchPath(postgresUrl, schema), { max: 1 })
    const previousAutoMigrate = process.env.TRUST_GRAPH_DB_AUTO_MIGRATE

    try {
      await adminSql.unsafe(`CREATE SCHEMA ${schemaIdentifier}`)
      process.env.TRUST_GRAPH_DB_AUTO_MIGRATE = 'false'

      await expect(ensureTrustGraphDatabaseReady(scopedSql)).rejects.toThrow('trust graph schema is not migrated')

      await runTrustGraphMigrations(scopedSql)
      await expect(ensureTrustGraphDatabaseReady(scopedSql)).resolves.toBeUndefined()
      await expect(scopedSql`SELECT did FROM identities LIMIT 1`).resolves.toBeDefined()
    } finally {
      if (previousAutoMigrate === undefined) {
        delete process.env.TRUST_GRAPH_DB_AUTO_MIGRATE
      } else {
        process.env.TRUST_GRAPH_DB_AUTO_MIGRATE = previousAutoMigrate
      }
      await scopedSql.end()
      await adminSql.unsafe(`DROP SCHEMA IF EXISTS ${schemaIdentifier} CASCADE`)
      await adminSql.end()
    }
  }, 30_000)
})
