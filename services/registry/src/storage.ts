import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'
import { createHash } from 'node:crypto'
import postgres from 'postgres'

export interface RegistryEntry {
  card: Record<string, unknown>
  mode: 'public' | 'private'
  registeredAt: string
  updatedAt: string
  metadata: Record<string, unknown>
}

export interface RegistryStats {
  total: number
  public: number
  private: number
}

export interface RegistryStoreHealth {
  ok: boolean
  kind: RegistryStore['kind']
  detail?: string
}

export interface RegistryStore {
  readonly kind: 'memory' | 'file' | 'postgres'
  get(did: string): Promise<RegistryEntry | null>
  put(did: string, entry: RegistryEntry): Promise<void>
  delete(did: string): Promise<boolean>
  list(): Promise<Array<[string, RegistryEntry]>>
  stats(): Promise<RegistryStats>
  healthCheck(): Promise<RegistryStoreHealth>
  close?(): Promise<void>
}

export const REGISTRY_MIGRATIONS = [
  {
    id: '001_registry_cards',
    statements: [
      'CREATE TABLE IF NOT EXISTS registry_cards (did TEXT PRIMARY KEY, card JSONB NOT NULL, mode TEXT NOT NULL CHECK (mode IN (\'public\', \'private\')), metadata JSONB NOT NULL DEFAULT \'{}\'::jsonb, registered_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL)',
      'CREATE INDEX IF NOT EXISTS idx_registry_cards_mode ON registry_cards(mode)',
      'CREATE INDEX IF NOT EXISTS idx_registry_cards_updated_at ON registry_cards(updated_at DESC)',
    ],
  },
] as const

export class InMemoryRegistryStore implements RegistryStore {
  readonly kind = 'memory' as const
  private entries = new Map<string, RegistryEntry>()

  async get(did: string): Promise<RegistryEntry | null> {
    return this.entries.get(did) ?? null
  }

  async put(did: string, entry: RegistryEntry): Promise<void> {
    this.entries.set(did, entry)
  }

  async delete(did: string): Promise<boolean> {
    return this.entries.delete(did)
  }

  async list(): Promise<Array<[string, RegistryEntry]>> {
    return Array.from(this.entries.entries())
  }

  async stats(): Promise<RegistryStats> {
    return statsFromEntries(this.entries.values())
  }

  async healthCheck(): Promise<RegistryStoreHealth> {
    return { ok: true, kind: this.kind }
  }
}

export class FileRegistryStore implements RegistryStore {
  readonly kind = 'file' as const

  constructor(private readonly path = join(homedir(), '.fides', 'registry', 'registry.json')) {}

  async get(did: string): Promise<RegistryEntry | null> {
    return (await this.read()).get(did) ?? null
  }

  async put(did: string, entry: RegistryEntry): Promise<void> {
    const entries = await this.read()
    entries.set(did, entry)
    await this.write(entries)
  }

  async delete(did: string): Promise<boolean> {
    const entries = await this.read()
    const deleted = entries.delete(did)
    if (deleted) await this.write(entries)
    return deleted
  }

  async list(): Promise<Array<[string, RegistryEntry]>> {
    return Array.from((await this.read()).entries())
  }

  async stats(): Promise<RegistryStats> {
    return statsFromEntries((await this.read()).values())
  }

  async healthCheck(): Promise<RegistryStoreHealth> {
    try {
      await mkdir(dirname(this.path), { recursive: true })
      await this.read()
      return { ok: true, kind: this.kind, detail: this.path }
    } catch (error) {
      return { ok: false, kind: this.kind, detail: error instanceof Error ? error.message : String(error) }
    }
  }

  private async read(): Promise<Map<string, RegistryEntry>> {
    try {
      const raw = await readFile(this.path, 'utf8')
      const data = JSON.parse(raw) as Record<string, RegistryEntry>
      return new Map(Object.entries(data))
    } catch (error) {
      if (error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'ENOENT') {
        return new Map()
      }
      throw error
    }
  }

  private async write(entries: Map<string, RegistryEntry>): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true })
    const obj: Record<string, RegistryEntry> = {}
    for (const [did, entry] of entries) {
      obj[did] = entry
    }
    const tempPath = `${this.path}.${process.pid}.${Date.now()}.tmp`
    await writeFile(tempPath, `${JSON.stringify(obj, null, 2)}\n`, 'utf8')
    await rename(tempPath, this.path)
  }
}

export class PostgresRegistryStore implements RegistryStore {
  readonly kind = 'postgres' as const
  private sql: postgres.Sql
  private initialized: Promise<void>

  constructor(connectionString = requiredDatabaseUrl()) {
    this.sql = postgres(connectionString, {
      max: parseInt(process.env.REGISTRY_DB_POOL_MAX || process.env.DB_POOL_MAX || '10', 10),
      idle_timeout: 20,
      connect_timeout: 10,
    })
    this.initialized = this.init()
  }

  async get(did: string): Promise<RegistryEntry | null> {
    await this.initialized
    const rows = await this.sql`
      SELECT card, mode, metadata, registered_at, updated_at
      FROM registry_cards
      WHERE did = ${did}
      LIMIT 1
    `
    return rowToEntry(rows[0])
  }

  async put(did: string, entry: RegistryEntry): Promise<void> {
    await this.initialized
    await this.sql`
      INSERT INTO registry_cards (did, card, mode, metadata, registered_at, updated_at)
      VALUES (
        ${did},
        ${this.sql.json(entry.card as any)},
        ${entry.mode},
        ${this.sql.json(entry.metadata as any)},
        ${entry.registeredAt},
        ${entry.updatedAt}
      )
      ON CONFLICT (did) DO UPDATE SET
        card = EXCLUDED.card,
        mode = EXCLUDED.mode,
        metadata = EXCLUDED.metadata,
        registered_at = EXCLUDED.registered_at,
        updated_at = EXCLUDED.updated_at
    `
  }

  async delete(did: string): Promise<boolean> {
    await this.initialized
    const rows = await this.sql`DELETE FROM registry_cards WHERE did = ${did} RETURNING did`
    return rows.length > 0
  }

  async list(): Promise<Array<[string, RegistryEntry]>> {
    await this.initialized
    const rows = await this.sql`
      SELECT did, card, mode, metadata, registered_at, updated_at
      FROM registry_cards
      ORDER BY updated_at DESC
    `
    return rows.map(row => [row.did as string, rowToEntry(row) as RegistryEntry])
  }

  async stats(): Promise<RegistryStats> {
    await this.initialized
    const rows = await this.sql`
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE mode = 'public')::int AS public,
        COUNT(*) FILTER (WHERE mode = 'private')::int AS private
      FROM registry_cards
    `
    return {
      total: rows[0]?.total ?? 0,
      public: rows[0]?.public ?? 0,
      private: rows[0]?.private ?? 0,
    }
  }

  async close(): Promise<void> {
    await this.sql.end()
  }

  async healthCheck(): Promise<RegistryStoreHealth> {
    try {
      await this.initialized
      await this.sql`SELECT 1`
      return { ok: true, kind: this.kind }
    } catch (error) {
      return { ok: false, kind: this.kind, detail: error instanceof Error ? error.message : String(error) }
    }
  }

  private async init(): Promise<void> {
    if (process.env.REGISTRY_DB_AUTO_MIGRATE === 'false') {
      await assertRegistrySchema(this.sql)
      return
    }
    await runRegistryMigrations(this.sql)
  }
}

export async function runRegistryMigrations(sql: postgres.Sql): Promise<void> {
  await sql`SELECT pg_advisory_lock(hashtext('registry_migrations'))`

  try {
    await ensureRegistryMigrationLedger(sql)
    for (const migration of REGISTRY_MIGRATIONS) {
      const checksum = registryMigrationChecksum(migration)
      const existing = await sql`
        SELECT id, checksum
        FROM registry_schema_migrations
        WHERE id = ${migration.id}
        LIMIT 1
      `
      if (existing.length > 0) {
        const appliedChecksum = existing[0]?.checksum as string | null | undefined
        if (appliedChecksum && appliedChecksum !== checksum) {
          throw new Error(`registry migration ${migration.id} checksum mismatch`)
        }
        if (!appliedChecksum) {
          await sql`
            UPDATE registry_schema_migrations
            SET checksum = ${checksum}
            WHERE id = ${migration.id}
          `
        }
        continue
      }

      for (const statement of migration.statements) {
        await sql.unsafe(statement)
      }

      await sql`INSERT INTO registry_schema_migrations (id, checksum) VALUES (${migration.id}, ${checksum})`
    }
  } finally {
    await sql`SELECT pg_advisory_unlock(hashtext('registry_migrations'))`
  }
}

async function ensureRegistryMigrationLedger(sql: postgres.Sql): Promise<void> {
  await sql`
    CREATE TABLE IF NOT EXISTS registry_schema_migrations (
      id TEXT PRIMARY KEY,
      checksum TEXT,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `
  await sql`ALTER TABLE registry_schema_migrations ADD COLUMN IF NOT EXISTS checksum TEXT`
}

function registryMigrationChecksum(migration: typeof REGISTRY_MIGRATIONS[number]): string {
  return createHash('sha256')
    .update(migration.statements.join('\n'))
    .digest('hex')
}

export function createRegistryStore(): RegistryStore {
  if (process.env.NODE_ENV === 'test') return new InMemoryRegistryStore()
  if (process.env.REGISTRY_STORE === 'postgres') {
    return new PostgresRegistryStore(process.env.REGISTRY_DATABASE_URL || process.env.DATABASE_URL)
  }
  return new FileRegistryStore(process.env.REGISTRY_STORE_PATH)
}

function statsFromEntries(entries: Iterable<RegistryEntry>): RegistryStats {
  let publicCount = 0
  let privateCount = 0
  let total = 0
  for (const entry of entries) {
    total++
    if (entry.mode === 'public') publicCount++
    else privateCount++
  }
  return { total, public: publicCount, private: privateCount }
}

function rowToEntry(row: any): RegistryEntry | null {
  if (!row) return null
  return {
    card: row.card as Record<string, unknown>,
    mode: row.mode as 'public' | 'private',
    metadata: row.metadata as Record<string, unknown>,
    registeredAt: new Date(row.registered_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  }
}

async function assertRegistrySchema(sql: postgres.Sql): Promise<void> {
  const rows = await sql`
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = current_schema()
      AND table_name IN ('registry_cards', 'registry_schema_migrations')
  `
  if (rows.length !== 2) {
    throw new Error('registry store schema is not migrated')
  }

  const applied = await sql`
    SELECT id, checksum
    FROM registry_schema_migrations
    WHERE id IN ${sql(REGISTRY_MIGRATIONS.map(migration => migration.id))}
  `
  if (applied.length !== REGISTRY_MIGRATIONS.length) {
    throw new Error('registry store schema is not migrated')
  }
  const checksums = new Map(applied.map(row => [row.id as string, row.checksum as string | null]))
  for (const migration of REGISTRY_MIGRATIONS) {
    if (checksums.get(migration.id) !== registryMigrationChecksum(migration)) {
      throw new Error(`registry migration ${migration.id} checksum mismatch`)
    }
  }
}

function requiredDatabaseUrl(): string {
  const url = process.env.REGISTRY_DATABASE_URL || process.env.DATABASE_URL
  if (!url) {
    throw new Error('REGISTRY_DATABASE_URL or DATABASE_URL is required for REGISTRY_STORE=postgres')
  }
  return url
}
