import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'
import postgres from 'postgres'
import type { EvidenceChain } from '@fides/evidence'
import type {
  IncidentRecord,
  NonceUseRecord,
  RevocationRecord,
  SessionStore,
  StoredSession,
} from '@fides/core'

export interface AuthorityStore extends SessionStore {
  readonly kind: 'memory' | 'file' | 'postgres'
  getEvidenceChain(did: string): Promise<EvidenceChain | null>
  setEvidenceChain(did: string, chain: EvidenceChain): Promise<void>
  putRevocation(record: RevocationRecord): Promise<void>
  getRevocation(did: string): Promise<RevocationRecord | null>
  putIncident(record: IncidentRecord): Promise<void>
  listIncidents(did: string): Promise<IncidentRecord[]>
  enqueuePropagation(record: AuthorityPropagationRecord): Promise<void>
  listPendingPropagations(now?: string, limit?: number): Promise<AuthorityPropagationRecord[]>
  updatePropagationAttempt(id: string, result: AuthorityPropagationAttemptResult): Promise<AuthorityPropagationRecord | null>
  healthCheck(): Promise<AuthorityStoreHealth>
  close?(): Promise<void>
}

export interface AuthorityStoreHealth {
  ok: boolean
  kind: AuthorityStore['kind']
  detail?: string
}

export type AuthorityPropagationRecordType = 'revocation' | 'incident'
export type AuthorityPropagationStatus = 'pending' | 'confirmed' | 'failed'

export interface AuthorityPropagationRecord {
  id: string
  actor: string
  recordType: AuthorityPropagationRecordType
  recordId: string
  target: string
  path: string
  body: Record<string, unknown>
  status: AuthorityPropagationStatus
  attempts: number
  maxAttempts: number
  nextAttemptAt: string
  createdAt: string
  updatedAt: string
  lastAttemptAt?: string
  lastStatus?: number
  lastError?: string
}

export interface AuthorityPropagationAttemptResult {
  ok: boolean
  status: number
  error?: string
  attemptedAt: string
  nextAttemptAt?: string
}

export const AUTHORITY_MIGRATIONS = [
  {
    id: '001_authority_store',
    statements: [
      'CREATE TABLE IF NOT EXISTS agentd_delegation_nonces (nonce TEXT PRIMARY KEY, record JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())',
      'CREATE TABLE IF NOT EXISTS agentd_sessions (id TEXT PRIMARY KEY, delegatee_did TEXT NOT NULL, session JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())',
      'CREATE TABLE IF NOT EXISTS agentd_evidence_chains (did TEXT PRIMARY KEY, chain JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())',
      'CREATE TABLE IF NOT EXISTS agentd_revocations (did TEXT PRIMARY KEY, record JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())',
      'CREATE TABLE IF NOT EXISTS agentd_incidents (id TEXT PRIMARY KEY, actor_did TEXT NOT NULL, record JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())',
      'CREATE TABLE IF NOT EXISTS agentd_authority_propagations (id TEXT PRIMARY KEY, actor_did TEXT NOT NULL, record_type TEXT NOT NULL, record_id TEXT NOT NULL, target TEXT NOT NULL, path TEXT NOT NULL, body JSONB NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 5, next_attempt_at TIMESTAMPTZ NOT NULL, record JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())',
      'CREATE INDEX IF NOT EXISTS idx_agentd_sessions_delegatee ON agentd_sessions(delegatee_did)',
      'CREATE INDEX IF NOT EXISTS idx_agentd_incidents_actor ON agentd_incidents(actor_did)',
      'CREATE INDEX IF NOT EXISTS idx_agentd_propagations_pending ON agentd_authority_propagations(status, next_attempt_at)',
    ],
  },
] as const

interface AuthoritySnapshot {
  nonces: NonceUseRecord[]
  sessions: StoredSession[]
  evidenceChains: Record<string, EvidenceChain>
  revocations: Record<string, RevocationRecord>
  incidents: Record<string, IncidentRecord[]>
  propagations: AuthorityPropagationRecord[]
}

function emptySnapshot(): AuthoritySnapshot {
  return {
    nonces: [],
    sessions: [],
    evidenceChains: {},
    revocations: {},
    incidents: {},
    propagations: [],
  }
}

export class InMemoryAuthorityStore implements AuthorityStore {
  readonly kind = 'memory' as const
  private nonces = new Map<string, NonceUseRecord>()
  private sessions = new Map<string, StoredSession>()
  private evidenceChains = new Map<string, EvidenceChain>()
  private revocations = new Map<string, RevocationRecord>()
  private incidents = new Map<string, IncidentRecord[]>()
  private propagations = new Map<string, AuthorityPropagationRecord>()

  async hasNonce(nonce: string): Promise<boolean> {
    return this.nonces.has(nonce)
  }

  async markNonceUsed(record: NonceUseRecord): Promise<void> {
    this.nonces.set(record.nonce, record)
  }

  async createSession(session: StoredSession): Promise<void> {
    this.sessions.set(session.id, session)
  }

  async getSession(id: string): Promise<StoredSession | null> {
    return this.sessions.get(id) ?? null
  }

  async listSessions(): Promise<StoredSession[]> {
    return Array.from(this.sessions.values())
  }

  async revokeSession(id: string, reason?: string): Promise<StoredSession | null> {
    const session = this.sessions.get(id)
    if (!session) return null
    const revoked = { ...session, revoked: true, revokedAt: new Date().toISOString(), revocationReason: reason }
    this.sessions.set(id, revoked)
    return revoked
  }

  async getEvidenceChain(did: string): Promise<EvidenceChain | null> {
    return this.evidenceChains.get(did) ?? null
  }

  async setEvidenceChain(did: string, chain: EvidenceChain): Promise<void> {
    this.evidenceChains.set(did, chain)
  }

  async putRevocation(record: RevocationRecord): Promise<void> {
    this.revocations.set(record.did, record)
  }

  async getRevocation(did: string): Promise<RevocationRecord | null> {
    return this.revocations.get(did) ?? null
  }

  async putIncident(record: IncidentRecord): Promise<void> {
    const existing = this.incidents.get(record.actor) ?? []
    this.incidents.set(record.actor, [...existing, record])
  }

  async listIncidents(did: string): Promise<IncidentRecord[]> {
    return this.incidents.get(did) ?? []
  }

  async enqueuePropagation(record: AuthorityPropagationRecord): Promise<void> {
    this.propagations.set(record.id, record)
  }

  async listPendingPropagations(now = new Date().toISOString(), limit = 25): Promise<AuthorityPropagationRecord[]> {
    return Array.from(this.propagations.values())
      .filter(record => record.status === 'pending' && record.nextAttemptAt <= now)
      .sort((a, b) => a.nextAttemptAt.localeCompare(b.nextAttemptAt))
      .slice(0, limit)
  }

  async updatePropagationAttempt(id: string, result: AuthorityPropagationAttemptResult): Promise<AuthorityPropagationRecord | null> {
    const record = this.propagations.get(id)
    if (!record) return null
    const updated = applyPropagationAttempt(record, result)
    this.propagations.set(id, updated)
    return updated
  }

  async healthCheck(): Promise<AuthorityStoreHealth> {
    return { ok: true, kind: this.kind }
  }
}

export class FileAuthorityStore implements AuthorityStore {
  readonly kind = 'file' as const

  constructor(private readonly path = join(homedir(), '.fides', 'agentd', 'authority-store.json')) {}

  async hasNonce(nonce: string): Promise<boolean> {
    return (await this.read()).nonces.some(record => record.nonce === nonce)
  }

  async markNonceUsed(record: NonceUseRecord): Promise<void> {
    const snapshot = await this.read()
    await this.write({
      ...snapshot,
      nonces: [...snapshot.nonces.filter(existing => existing.nonce !== record.nonce), record],
    })
  }

  async createSession(session: StoredSession): Promise<void> {
    const snapshot = await this.read()
    await this.write({
      ...snapshot,
      sessions: [...snapshot.sessions.filter(existing => existing.id !== session.id), session],
    })
  }

  async getSession(id: string): Promise<StoredSession | null> {
    return (await this.read()).sessions.find(session => session.id === id) ?? null
  }

  async listSessions(): Promise<StoredSession[]> {
    return (await this.read()).sessions
  }

  async revokeSession(id: string, reason?: string): Promise<StoredSession | null> {
    const snapshot = await this.read()
    const session = snapshot.sessions.find(existing => existing.id === id)
    if (!session) return null
    const revoked = { ...session, revoked: true, revokedAt: new Date().toISOString(), revocationReason: reason }
    await this.write({
      ...snapshot,
      sessions: snapshot.sessions.map(existing => existing.id === id ? revoked : existing),
    })
    return revoked
  }

  async getEvidenceChain(did: string): Promise<EvidenceChain | null> {
    return (await this.read()).evidenceChains[did] ?? null
  }

  async setEvidenceChain(did: string, chain: EvidenceChain): Promise<void> {
    const snapshot = await this.read()
    await this.write({ ...snapshot, evidenceChains: { ...snapshot.evidenceChains, [did]: chain } })
  }

  async putRevocation(record: RevocationRecord): Promise<void> {
    const snapshot = await this.read()
    await this.write({ ...snapshot, revocations: { ...snapshot.revocations, [record.did]: record } })
  }

  async getRevocation(did: string): Promise<RevocationRecord | null> {
    return (await this.read()).revocations[did] ?? null
  }

  async putIncident(record: IncidentRecord): Promise<void> {
    const snapshot = await this.read()
    const existing = snapshot.incidents[record.actor] ?? []
    await this.write({ ...snapshot, incidents: { ...snapshot.incidents, [record.actor]: [...existing, record] } })
  }

  async listIncidents(did: string): Promise<IncidentRecord[]> {
    return (await this.read()).incidents[did] ?? []
  }

  async enqueuePropagation(record: AuthorityPropagationRecord): Promise<void> {
    const snapshot = await this.read()
    await this.write({
      ...snapshot,
      propagations: [...snapshot.propagations.filter(existing => existing.id !== record.id), record],
    })
  }

  async listPendingPropagations(now = new Date().toISOString(), limit = 25): Promise<AuthorityPropagationRecord[]> {
    return (await this.read()).propagations
      .filter(record => record.status === 'pending' && record.nextAttemptAt <= now)
      .sort((a, b) => a.nextAttemptAt.localeCompare(b.nextAttemptAt))
      .slice(0, limit)
  }

  async updatePropagationAttempt(id: string, result: AuthorityPropagationAttemptResult): Promise<AuthorityPropagationRecord | null> {
    const snapshot = await this.read()
    const record = snapshot.propagations.find(existing => existing.id === id)
    if (!record) return null
    const updated = applyPropagationAttempt(record, result)
    await this.write({
      ...snapshot,
      propagations: snapshot.propagations.map(existing => existing.id === id ? updated : existing),
    })
    return updated
  }

  async healthCheck(): Promise<AuthorityStoreHealth> {
    try {
      await mkdir(dirname(this.path), { recursive: true })
      await this.read()
      return { ok: true, kind: this.kind, detail: this.path }
    } catch (error) {
      return { ok: false, kind: this.kind, detail: error instanceof Error ? error.message : String(error) }
    }
  }

  private async read(): Promise<AuthoritySnapshot> {
    try {
      const raw = await readFile(this.path, 'utf8')
      return { ...emptySnapshot(), ...JSON.parse(raw) }
    } catch (error) {
      if (error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'ENOENT') {
        return emptySnapshot()
      }
      throw error
    }
  }

  private async write(snapshot: AuthoritySnapshot): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true })
    const tempPath = `${this.path}.${process.pid}.${Date.now()}.tmp`
    await writeFile(tempPath, `${JSON.stringify(snapshot, null, 2)}\n`, 'utf8')
    await rename(tempPath, this.path)
  }
}

export class PostgresAuthorityStore implements AuthorityStore {
  readonly kind = 'postgres' as const
  private sql: postgres.Sql
  private initialized: Promise<void>

  constructor(connectionString = requiredDatabaseUrl()) {
    this.sql = postgres(connectionString, {
      max: parseInt(process.env.AGENTD_DB_POOL_MAX || process.env.DB_POOL_MAX || '10', 10),
      idle_timeout: 20,
      connect_timeout: 10,
    })
    this.initialized = this.init()
  }

  async hasNonce(nonce: string): Promise<boolean> {
    await this.initialized
    const rows = await this.sql`SELECT nonce FROM agentd_delegation_nonces WHERE nonce = ${nonce} LIMIT 1`
    return rows.length > 0
  }

  async markNonceUsed(record: NonceUseRecord): Promise<void> {
    await this.initialized
    await this.sql`
      INSERT INTO agentd_delegation_nonces (nonce, record)
      VALUES (${record.nonce}, ${this.sql.json(record as any)})
      ON CONFLICT (nonce) DO UPDATE SET record = EXCLUDED.record
    `
  }

  async createSession(session: StoredSession): Promise<void> {
    await this.initialized
    await this.sql`
      INSERT INTO agentd_sessions (id, delegatee_did, session)
      VALUES (${session.id}, ${session.token.delegatee}, ${this.sql.json(session as any)})
      ON CONFLICT (id) DO UPDATE SET delegatee_did = EXCLUDED.delegatee_did, session = EXCLUDED.session
    `
  }

  async getSession(id: string): Promise<StoredSession | null> {
    await this.initialized
    const rows = await this.sql`SELECT session FROM agentd_sessions WHERE id = ${id} LIMIT 1`
    return (rows[0]?.session as StoredSession | undefined) ?? null
  }

  async listSessions(): Promise<StoredSession[]> {
    await this.initialized
    const rows = await this.sql`SELECT session FROM agentd_sessions ORDER BY created_at DESC`
    return rows.map(row => row.session as StoredSession)
  }

  async revokeSession(id: string, reason?: string): Promise<StoredSession | null> {
    const session = await this.getSession(id)
    if (!session) return null
    const revoked = { ...session, revoked: true, revokedAt: new Date().toISOString(), revocationReason: reason }
    await this.createSession(revoked)
    return revoked
  }

  async getEvidenceChain(did: string): Promise<EvidenceChain | null> {
    await this.initialized
    const rows = await this.sql`SELECT chain FROM agentd_evidence_chains WHERE did = ${did} LIMIT 1`
    return (rows[0]?.chain as EvidenceChain | undefined) ?? null
  }

  async setEvidenceChain(did: string, chain: EvidenceChain): Promise<void> {
    await this.initialized
    await this.sql`
      INSERT INTO agentd_evidence_chains (did, chain)
      VALUES (${did}, ${this.sql.json(chain as any)})
      ON CONFLICT (did) DO UPDATE SET chain = EXCLUDED.chain, updated_at = now()
    `
  }

  async putRevocation(record: RevocationRecord): Promise<void> {
    await this.initialized
    await this.sql`
      INSERT INTO agentd_revocations (did, record)
      VALUES (${record.did}, ${this.sql.json(record as any)})
      ON CONFLICT (did) DO UPDATE SET record = EXCLUDED.record, updated_at = now()
    `
  }

  async getRevocation(did: string): Promise<RevocationRecord | null> {
    await this.initialized
    const rows = await this.sql`SELECT record FROM agentd_revocations WHERE did = ${did} LIMIT 1`
    return (rows[0]?.record as RevocationRecord | undefined) ?? null
  }

  async putIncident(record: IncidentRecord): Promise<void> {
    await this.initialized
    await this.sql`
      INSERT INTO agentd_incidents (id, actor_did, record)
      VALUES (${record.id}, ${record.actor}, ${this.sql.json(record as any)})
      ON CONFLICT (id) DO UPDATE SET actor_did = EXCLUDED.actor_did, record = EXCLUDED.record
    `
  }

  async listIncidents(did: string): Promise<IncidentRecord[]> {
    await this.initialized
    const rows = await this.sql`SELECT record FROM agentd_incidents WHERE actor_did = ${did} ORDER BY created_at DESC`
    return rows.map(row => row.record as IncidentRecord)
  }

  async enqueuePropagation(record: AuthorityPropagationRecord): Promise<void> {
    await this.initialized
    await this.sql`
      INSERT INTO agentd_authority_propagations (
        id, actor_did, record_type, record_id, target, path, body, status,
        attempts, max_attempts, next_attempt_at, record, created_at, updated_at
      )
      VALUES (
        ${record.id}, ${record.actor}, ${record.recordType}, ${record.recordId},
        ${record.target}, ${record.path}, ${this.sql.json(record.body as any)}, ${record.status},
        ${record.attempts}, ${record.maxAttempts}, ${record.nextAttemptAt}, ${this.sql.json(record as any)},
        ${record.createdAt}, ${record.updatedAt}
      )
      ON CONFLICT (id) DO UPDATE SET
        actor_did = EXCLUDED.actor_did,
        record_type = EXCLUDED.record_type,
        record_id = EXCLUDED.record_id,
        target = EXCLUDED.target,
        path = EXCLUDED.path,
        body = EXCLUDED.body,
        status = EXCLUDED.status,
        attempts = EXCLUDED.attempts,
        max_attempts = EXCLUDED.max_attempts,
        next_attempt_at = EXCLUDED.next_attempt_at,
        record = EXCLUDED.record,
        updated_at = EXCLUDED.updated_at
    `
  }

  async listPendingPropagations(now = new Date().toISOString(), limit = 25): Promise<AuthorityPropagationRecord[]> {
    await this.initialized
    const rows = await this.sql`
      SELECT record
      FROM agentd_authority_propagations
      WHERE status = 'pending' AND next_attempt_at <= ${now}
      ORDER BY next_attempt_at ASC
      LIMIT ${limit}
    `
    return rows.map(row => row.record as AuthorityPropagationRecord)
  }

  async updatePropagationAttempt(id: string, result: AuthorityPropagationAttemptResult): Promise<AuthorityPropagationRecord | null> {
    await this.initialized
    const rows = await this.sql`SELECT record FROM agentd_authority_propagations WHERE id = ${id} LIMIT 1`
    const record = rows[0]?.record as AuthorityPropagationRecord | undefined
    if (!record) return null
    const updated = applyPropagationAttempt(record, result)
    await this.enqueuePropagation(updated)
    return updated
  }

  async close(): Promise<void> {
    await this.sql.end()
  }

  async healthCheck(): Promise<AuthorityStoreHealth> {
    try {
      await this.initialized
      await this.sql`SELECT 1`
      return { ok: true, kind: this.kind }
    } catch (error) {
      return { ok: false, kind: this.kind, detail: error instanceof Error ? error.message : String(error) }
    }
  }

  private async init(): Promise<void> {
    if (process.env.AGENTD_DB_AUTO_MIGRATE === 'false') {
      await assertAuthoritySchema(this.sql)
      return
    }
    await runAuthorityMigrations(this.sql)
  }
}

export async function runAuthorityMigrations(sql: postgres.Sql): Promise<void> {
  await sql`SELECT pg_advisory_lock(hashtext('agentd_authority_migrations'))`

  try {
    await sql`CREATE TABLE IF NOT EXISTS agentd_schema_migrations (id TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`
    for (const migration of AUTHORITY_MIGRATIONS) {
      const existing = await sql`SELECT id FROM agentd_schema_migrations WHERE id = ${migration.id} LIMIT 1`
      if (existing.length > 0) continue

      for (const statement of migration.statements) {
        await sql.unsafe(statement)
      }

      await sql`INSERT INTO agentd_schema_migrations (id) VALUES (${migration.id})`
    }
  } finally {
    await sql`SELECT pg_advisory_unlock(hashtext('agentd_authority_migrations'))`
  }
}

async function assertAuthoritySchema(sql: postgres.Sql): Promise<void> {
  const rows = await sql`
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = current_schema()
      AND table_name IN (
        'agentd_delegation_nonces',
        'agentd_sessions',
        'agentd_evidence_chains',
        'agentd_revocations',
        'agentd_incidents',
        'agentd_authority_propagations',
        'agentd_schema_migrations'
      )
  `
  if (rows.length !== 7) {
    throw new Error('agentd authority store schema is not migrated')
  }

  const applied = await sql`
    SELECT id
    FROM agentd_schema_migrations
    WHERE id IN ${sql(AUTHORITY_MIGRATIONS.map(migration => migration.id))}
  `
  if (applied.length !== AUTHORITY_MIGRATIONS.length) {
    throw new Error('agentd authority store schema is not migrated')
  }
}

function applyPropagationAttempt(
  record: AuthorityPropagationRecord,
  result: AuthorityPropagationAttemptResult
): AuthorityPropagationRecord {
  const attempts = record.attempts + 1
  const status = propagationAttemptStatus(result.status, result.ok, attempts, record.maxAttempts)
  return {
    ...record,
    status,
    attempts,
    lastAttemptAt: result.attemptedAt,
    lastStatus: result.status,
    lastError: result.error,
    nextAttemptAt: result.ok ? record.nextAttemptAt : result.nextAttemptAt ?? record.nextAttemptAt,
    updatedAt: result.attemptedAt,
  }
}

function propagationAttemptStatus(
  status: number,
  ok: boolean,
  attempts: number,
  maxAttempts: number
): AuthorityPropagationStatus {
  if (ok) return 'confirmed'
  if (attempts >= maxAttempts) return 'failed'
  if (status >= 400 && status < 500 && status !== 408 && status !== 409 && status !== 429) return 'failed'
  return 'pending'
}

export function createAuthorityStore(): AuthorityStore {
  if (process.env.NODE_ENV === 'test') return new InMemoryAuthorityStore()
  if (process.env.AGENTD_AUTHORITY_STORE === 'postgres') {
    return new PostgresAuthorityStore(process.env.AGENTD_DATABASE_URL || process.env.DATABASE_URL)
  }
  return new FileAuthorityStore(process.env.AGENTD_STATE_STORE_PATH)
}

function requiredDatabaseUrl(): string {
  const url = process.env.AGENTD_DATABASE_URL || process.env.DATABASE_URL
  if (!url) {
    throw new Error('AGENTD_DATABASE_URL or DATABASE_URL is required for AGENTD_AUTHORITY_STORE=postgres')
  }
  return url
}
