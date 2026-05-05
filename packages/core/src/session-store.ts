import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'
import {
  createSessionGrant,
  isSessionExpired,
  type DelegationToken,
  type SessionGrant,
  validateDelegationToken,
} from './delegation.js'

export interface NonceUseRecord {
  nonce: string
  tokenId?: string
  delegator?: string
  delegatee?: string
  usedAt: string
}

export interface StoredSession extends SessionGrant {
  createdAt: string
  revoked: boolean
  revokedAt?: string
  revocationReason?: string
}

export interface SessionStore {
  hasNonce(nonce: string): Promise<boolean>
  markNonceUsed(record: NonceUseRecord): Promise<void>
  createSession(session: StoredSession): Promise<void>
  getSession(id: string): Promise<StoredSession | null>
  listSessions(): Promise<StoredSession[]>
  revokeSession(id: string, reason?: string): Promise<StoredSession | null>
}

export interface DelegationAuthorizationInput {
  token: DelegationToken
  store: SessionStore
  capabilityId?: string
  audience?: string
  boundTo?: string
  ttlMs?: number
}

export interface SessionInvocationInput {
  sessionId: string
  store: SessionStore
  capabilityId?: string
  audience?: string
}

export interface AuthorizationResult {
  ok: boolean
  session?: StoredSession
  errors: string[]
}

export class InMemorySessionStore implements SessionStore {
  private nonces = new Map<string, NonceUseRecord>()
  private sessions = new Map<string, StoredSession>()

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

    const revoked: StoredSession = {
      ...session,
      revoked: true,
      revokedAt: new Date().toISOString(),
      revocationReason: reason,
    }
    this.sessions.set(id, revoked)
    return revoked
  }
}

interface SessionStoreSnapshot {
  nonces: NonceUseRecord[]
  sessions: StoredSession[]
}

export class FileSessionStore implements SessionStore {
  private readonly path: string

  constructor(path = join(homedir(), '.fides', 'sessions', 'session-store.json')) {
    this.path = path
  }

  async hasNonce(nonce: string): Promise<boolean> {
    const snapshot = await this.readSnapshot()
    return snapshot.nonces.some(record => record.nonce === nonce)
  }

  async markNonceUsed(record: NonceUseRecord): Promise<void> {
    const snapshot = await this.readSnapshot()
    const next = snapshot.nonces.filter(existing => existing.nonce !== record.nonce)
    next.push(record)
    await this.writeSnapshot({ ...snapshot, nonces: next })
  }

  async createSession(session: StoredSession): Promise<void> {
    const snapshot = await this.readSnapshot()
    const next = snapshot.sessions.filter(existing => existing.id !== session.id)
    next.push(session)
    await this.writeSnapshot({ ...snapshot, sessions: next })
  }

  async getSession(id: string): Promise<StoredSession | null> {
    const snapshot = await this.readSnapshot()
    return snapshot.sessions.find(session => session.id === id) ?? null
  }

  async listSessions(): Promise<StoredSession[]> {
    const snapshot = await this.readSnapshot()
    return snapshot.sessions
  }

  async revokeSession(id: string, reason?: string): Promise<StoredSession | null> {
    const snapshot = await this.readSnapshot()
    const session = snapshot.sessions.find(existing => existing.id === id)
    if (!session) return null

    const revoked: StoredSession = {
      ...session,
      revoked: true,
      revokedAt: new Date().toISOString(),
      revocationReason: reason,
    }
    await this.writeSnapshot({
      ...snapshot,
      sessions: snapshot.sessions.map(existing => (existing.id === id ? revoked : existing)),
    })
    return revoked
  }

  private async readSnapshot(): Promise<SessionStoreSnapshot> {
    try {
      const raw = await readFile(this.path, 'utf8')
      const parsed = JSON.parse(raw) as Partial<SessionStoreSnapshot>
      return {
        nonces: Array.isArray(parsed.nonces) ? parsed.nonces : [],
        sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
      }
    } catch (error) {
      if (isNodeError(error) && error.code === 'ENOENT') {
        return { nonces: [], sessions: [] }
      }
      throw error
    }
  }

  private async writeSnapshot(snapshot: SessionStoreSnapshot): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true })
    const tempPath = `${this.path}.${process.pid}.${Date.now()}.tmp`
    await writeFile(tempPath, `${JSON.stringify(snapshot, null, 2)}\n`, 'utf8')
    await rename(tempPath, this.path)
  }
}

export async function authorizeDelegation(input: DelegationAuthorizationInput): Promise<AuthorizationResult> {
  const validation = validateDelegationToken(input.token)
  const errors = [...validation.errors]

  if (input.capabilityId && !input.token.capabilities.includes(input.capabilityId)) {
    errors.push(`DelegationToken does not grant capability ${input.capabilityId}`)
  }

  if (input.audience && input.token.audience?.length && !input.token.audience.includes(input.audience)) {
    errors.push(`DelegationToken audience does not include ${input.audience}`)
  }

  if (await input.store.hasNonce(input.token.nonce)) {
    errors.push('DelegationToken nonce has already been used')
  }

  if (errors.length > 0) {
    return { ok: false, errors }
  }

  const session = toStoredSession(
    createSessionGrant({
      token: input.token,
      boundTo: input.boundTo,
      ttlMs: input.ttlMs,
    })
  )
  await input.store.markNonceUsed({
    nonce: input.token.nonce,
    tokenId: input.token.id,
    delegator: input.token.delegator,
    delegatee: input.token.delegatee,
    usedAt: new Date().toISOString(),
  })
  await input.store.createSession(session)
  return { ok: true, session, errors: [] }
}

export async function authorizeSessionInvocation(input: SessionInvocationInput): Promise<AuthorizationResult> {
  const session = await input.store.getSession(input.sessionId)
  if (!session) {
    return { ok: false, errors: ['SessionGrant not found'] }
  }

  const errors: string[] = []
  if (session.revoked) {
    errors.push('SessionGrant is revoked')
  }
  if (isSessionExpired(session)) {
    errors.push('SessionGrant is expired')
  }
  if (input.capabilityId && !session.token.capabilities.includes(input.capabilityId)) {
    errors.push(`SessionGrant does not grant capability ${input.capabilityId}`)
  }
  if (input.audience && session.token.audience?.length && !session.token.audience.includes(input.audience)) {
    errors.push(`SessionGrant audience does not include ${input.audience}`)
  }

  return { ok: errors.length === 0, session, errors }
}

export function toStoredSession(session: SessionGrant): StoredSession {
  return {
    ...session,
    createdAt: new Date().toISOString(),
    revoked: false,
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error
}
