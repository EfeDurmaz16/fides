import postgres from 'postgres'
import { afterAll, describe, expect, it } from 'vitest'
import {
  DISCOVERY_MIGRATIONS,
  ensureDiscoveryDatabaseReady,
  runDiscoveryMigrations,
  sql,
} from '../src/db/client.js'

const postgresUrl = process.env.DISCOVERY_DATABASE_URL || process.env.DATABASE_URL

afterAll(async () => {
  await sql.end()
})

function postgresUrlWithSearchPath(connectionString: string, schema: string): string {
  const url = new URL(connectionString)
  url.searchParams.set('options', `-c search_path=${schema}`)
  return url.toString()
}

function quoteIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`
}

describe.skipIf(!postgresUrl)('discovery migrations', () => {
  it('records applied discovery migrations once with checksums', async () => {
    const schema = `discovery_migrations_${crypto.randomUUID().replaceAll('-', '')}`
    const schemaIdentifier = quoteIdentifier(schema)
    const adminSql = postgres(postgresUrl, { max: 1 })
    const scopedSql = postgres(postgresUrlWithSearchPath(postgresUrl, schema), { max: 1 })

    try {
      await adminSql.unsafe(`CREATE SCHEMA ${schemaIdentifier}`)
      await runDiscoveryMigrations(scopedSql)
      await runDiscoveryMigrations(scopedSql)

      const rows = await scopedSql`
        SELECT id, checksum, count(*)::int AS count
        FROM discovery_schema_migrations
        WHERE id IN ${scopedSql(DISCOVERY_MIGRATIONS.map(migration => migration.id))}
        GROUP BY id, checksum
      `

      expect(rows).toHaveLength(DISCOVERY_MIGRATIONS.length)
      expect(rows.every(row => row.count === 1)).toBe(true)
      expect(rows.every(row => typeof row.checksum === 'string' && row.checksum.length === 64)).toBe(true)
    } finally {
      await scopedSql.end()
      await adminSql.unsafe(`DROP SCHEMA IF EXISTS ${schemaIdentifier} CASCADE`)
      await adminSql.end()
    }
  }, 30_000)

  it('fails closed when an applied discovery migration checksum drifts', async () => {
    const schema = `discovery_checksum_${crypto.randomUUID().replaceAll('-', '')}`
    const schemaIdentifier = quoteIdentifier(schema)
    const adminSql = postgres(postgresUrl, { max: 1 })
    const scopedSql = postgres(postgresUrlWithSearchPath(postgresUrl, schema), { max: 1 })

    try {
      await adminSql.unsafe(`CREATE SCHEMA ${schemaIdentifier}`)
      await runDiscoveryMigrations(scopedSql)
      await scopedSql`
        UPDATE discovery_schema_migrations
        SET checksum = ${'0'.repeat(64)}
        WHERE id = ${DISCOVERY_MIGRATIONS[0].id}
      `

      await expect(runDiscoveryMigrations(scopedSql)).rejects.toThrow('checksum mismatch')
    } finally {
      await scopedSql.end()
      await adminSql.unsafe(`DROP SCHEMA IF EXISTS ${schemaIdentifier} CASCADE`)
      await adminSql.end()
    }
  }, 30_000)

  it('fails closed without manual migrations when auto-migrate is disabled', async () => {
    const schema = `discovery_manual_${crypto.randomUUID().replaceAll('-', '')}`
    const schemaIdentifier = quoteIdentifier(schema)
    const adminSql = postgres(postgresUrl, { max: 1 })
    const scopedSql = postgres(postgresUrlWithSearchPath(postgresUrl, schema), { max: 1 })
    const previousAutoMigrate = process.env.DISCOVERY_DB_AUTO_MIGRATE

    try {
      await adminSql.unsafe(`CREATE SCHEMA ${schemaIdentifier}`)
      process.env.DISCOVERY_DB_AUTO_MIGRATE = 'false'

      await expect(ensureDiscoveryDatabaseReady(scopedSql)).rejects.toThrow('discovery schema is not migrated')

      await runDiscoveryMigrations(scopedSql)
      await expect(ensureDiscoveryDatabaseReady(scopedSql)).resolves.toBeUndefined()
      await expect(scopedSql`SELECT did FROM identities LIMIT 1`).resolves.toBeDefined()
    } finally {
      if (previousAutoMigrate === undefined) {
        delete process.env.DISCOVERY_DB_AUTO_MIGRATE
      } else {
        process.env.DISCOVERY_DB_AUTO_MIGRATE = previousAutoMigrate
      }
      await scopedSql.end()
      await adminSql.unsafe(`DROP SCHEMA IF EXISTS ${schemaIdentifier} CASCADE`)
      await adminSql.end()
    }
  }, 30_000)
})
