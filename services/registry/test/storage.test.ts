import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import postgres from 'postgres'
import { afterEach, describe, expect, it } from 'vitest'
import {
  FileRegistryStore,
  InMemoryRegistryStore,
  PostgresRegistryStore,
  REGISTRY_MIGRATIONS,
  runRegistryMigrations,
  type RegistryEntry,
} from '../src/storage.js'

const tempDirs: string[] = []
const postgresUrl = process.env.REGISTRY_DATABASE_URL || process.env.DATABASE_URL

afterEach(async () => {
  await Promise.all(tempDirs.map(path => rm(path, { recursive: true, force: true })))
  tempDirs.length = 0
})

function entry(overrides: Partial<RegistryEntry> = {}): RegistryEntry {
  return {
    card: { id: 'did:fides:test', name: 'Test Agent' },
    mode: 'public',
    registeredAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    metadata: {},
    ...overrides,
  }
}

function postgresUrlWithSearchPath(connectionString: string, schema: string): string {
  const url = new URL(connectionString)
  url.searchParams.set('options', `-c search_path=${schema}`)
  return url.toString()
}

function quoteIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`
}

describe('Registry stores', () => {
  it('tracks entries and stats in memory', async () => {
    const store = new InMemoryRegistryStore()

    await store.put('did:fides:public', entry())
    await store.put('did:fides:private', entry({ mode: 'private' }))

    expect(await store.get('did:fides:public')).toMatchObject({ mode: 'public' })
    expect(await store.stats()).toEqual({ total: 2, public: 1, private: 1 })
    expect(await store.delete('did:fides:private')).toBe(true)
    expect(await store.delete('did:fides:missing')).toBe(false)
  })

  it('persists entries through the file store', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fides-registry-'))
    tempDirs.push(dir)
    const path = join(dir, 'registry.json')

    const writer = new FileRegistryStore(path)
    await writer.put('did:fides:persisted', entry({ metadata: { owner: 'test' } }))

    const reader = new FileRegistryStore(path)
    expect(await reader.get('did:fides:persisted')).toMatchObject({
      mode: 'public',
      metadata: { owner: 'test' },
    })
    expect(await reader.healthCheck()).toMatchObject({ ok: true, kind: 'file' })
  })

  describe.skipIf(!postgresUrl)('postgres registry store', () => {
    it('records applied registry migrations once with checksums', async () => {
      const sql = postgres(postgresUrl, { max: 1 })

      try {
        await runRegistryMigrations(sql)
        await runRegistryMigrations(sql)

        const rows = await sql`
          SELECT id, checksum, count(*)::int AS count
          FROM registry_schema_migrations
          WHERE id IN ${sql(REGISTRY_MIGRATIONS.map(migration => migration.id))}
          GROUP BY id, checksum
        `

        expect(rows).toHaveLength(REGISTRY_MIGRATIONS.length)
        expect(rows.every(row => row.count === 1)).toBe(true)
        expect(rows.every(row => typeof row.checksum === 'string' && row.checksum.length === 64)).toBe(true)
      } finally {
        await sql.end()
      }
    }, 30_000)

    it('round-trips registry state through Postgres', async () => {
      const store = new PostgresRegistryStore(postgresUrl)
      const did = `did:fides:registry-${crypto.randomUUID()}`

      try {
        await store.put(did, entry({
          card: { id: did, name: 'Postgres Registry Agent' },
          mode: 'private',
          metadata: { owner: 'postgres-test' },
        }))

        expect(await store.get(did)).toMatchObject({
          mode: 'private',
          metadata: { owner: 'postgres-test' },
        })
        expect((await store.stats()).total).toBeGreaterThan(0)
        expect(await store.delete(did)).toBe(true)
        expect(await store.get(did)).toBeNull()
        expect((await store.healthCheck()).ok).toBe(true)
      } finally {
        await store.close()
      }
    }, 30_000)

    it('fails closed when an applied migration checksum drifts', async () => {
      const schema = `registry_migration_checksum_${crypto.randomUUID().replaceAll('-', '')}`
      const schemaIdentifier = quoteIdentifier(schema)
      const adminSql = postgres(postgresUrl, { max: 1 })
      const scopedUrl = postgresUrlWithSearchPath(postgresUrl, schema)
      const scopedSql = postgres(scopedUrl, { max: 1 })

      try {
        await adminSql.unsafe(`CREATE SCHEMA ${schemaIdentifier}`)
        await runRegistryMigrations(scopedSql)
        await scopedSql`
          UPDATE registry_schema_migrations
          SET checksum = ${'0'.repeat(64)}
          WHERE id = ${REGISTRY_MIGRATIONS[0].id}
        `

        await expect(runRegistryMigrations(scopedSql)).rejects.toThrow('checksum mismatch')
        const store = new PostgresRegistryStore(scopedUrl)
        try {
          const health = await store.healthCheck()
          expect(health.ok).toBe(false)
          expect(health.detail).toContain('checksum mismatch')
        } finally {
          await store.close()
        }
      } finally {
        await scopedSql.end()
        await adminSql.unsafe(`DROP SCHEMA IF EXISTS ${schemaIdentifier} CASCADE`)
        await adminSql.end()
      }
    }, 30_000)

    it('fails closed without manual migrations when auto-migrate is disabled', async () => {
      const schema = `registry_manual_migration_${crypto.randomUUID().replaceAll('-', '')}`
      const schemaIdentifier = quoteIdentifier(schema)
      const adminSql = postgres(postgresUrl, { max: 1 })
      const scopedUrl = postgresUrlWithSearchPath(postgresUrl, schema)
      const scopedSql = postgres(scopedUrl, { max: 1 })
      const previousAutoMigrate = process.env.REGISTRY_DB_AUTO_MIGRATE

      try {
        await adminSql.unsafe(`CREATE SCHEMA ${schemaIdentifier}`)
        process.env.REGISTRY_DB_AUTO_MIGRATE = 'false'

        const unmigratedStore = new PostgresRegistryStore(scopedUrl)
        try {
          const health = await unmigratedStore.healthCheck()
          expect(health.ok).toBe(false)
          expect(health.detail).toContain('registry store schema is not migrated')
        } finally {
          await unmigratedStore.close()
        }

        await runRegistryMigrations(scopedSql)

        const migratedStore = new PostgresRegistryStore(scopedUrl)
        try {
          const did = `did:fides:registry-manual-${crypto.randomUUID()}`
          await migratedStore.put(did, entry({ card: { id: did }, mode: 'public' }))
          expect((await migratedStore.healthCheck()).ok).toBe(true)
        } finally {
          await migratedStore.close()
        }
      } finally {
        if (previousAutoMigrate === undefined) {
          delete process.env.REGISTRY_DB_AUTO_MIGRATE
        } else {
          process.env.REGISTRY_DB_AUTO_MIGRATE = previousAutoMigrate
        }
        await scopedSql.end()
        await adminSql.unsafe(`DROP SCHEMA IF EXISTS ${schemaIdentifier} CASCADE`)
        await adminSql.end()
      }
    }, 30_000)
  })
})
