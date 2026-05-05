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
  getEvidenceChain(did: string): Promise<EvidenceChain | null>
  setEvidenceChain(did: string, chain: EvidenceChain): Promise<void>
  putRevocation(record: RevocationRecord): Promise<void>
  getRevocation(did: string): Promise<RevocationRecord | null>
  putIncident(record: IncidentRecord): Promise<void>
  listIncidents(did: string): Promise<IncidentRecord[]>
  close?(): Promise<void>
}

interface AuthoritySnapshot {
  nonces: NonceUseRecord[]
  sessions: StoredSession[]
  evidenceChains: Record<string, EvidenceChain>
  revocations: Record<string, RevocationRecord>
  incidents: Record<string, IncidentRecord[]>
}

function emptySnapshot(): AuthoritySnapshot {
  return {
    nonces: [],
    sessions: [],
    evidenceChains: {},
    revocations: {},
    incidents: {},
  }
}

export class InMemoryAuthorityStore implements AuthorityStore {
  private nonces = new Map<string, NonceUseRecord>()
  private sessions = new Map<string, StoredSession>()
  private evidenceChains = new Map<string, EvidenceChain>()
  private revocations = new Map<string, RevocationRecord>()
  private incidents = new Map<string, IncidentRecord[]>()

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
}

export class FileAuthorityStore implements AuthorityStore {
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

  async close(): Promise<void> {
    await this.sql.end()
  }

  private async init(): Promise<void> {
    await this.sql`CREATE TABLE IF NOT EXISTS agentd_delegation_nonces (nonce TEXT PRIMARY KEY, record JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`
    await this.sql`CREATE TABLE IF NOT EXISTS agentd_sessions (id TEXT PRIMARY KEY, delegatee_did TEXT NOT NULL, session JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`
    await this.sql`CREATE TABLE IF NOT EXISTS agentd_evidence_chains (did TEXT PRIMARY KEY, chain JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`
    await this.sql`CREATE TABLE IF NOT EXISTS agentd_revocations (did TEXT PRIMARY KEY, record JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`
    await this.sql`CREATE TABLE IF NOT EXISTS agentd_incidents (id TEXT PRIMARY KEY, actor_did TEXT NOT NULL, record JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`
    await this.sql`CREATE INDEX IF NOT EXISTS idx_agentd_sessions_delegatee ON agentd_sessions(delegatee_did)`
    await this.sql`CREATE INDEX IF NOT EXISTS idx_agentd_incidents_actor ON agentd_incidents(actor_did)`
  }
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
