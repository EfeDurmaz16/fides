import {
  createDelegationToken,
  createIncidentRecord,
  createRevocationRecord,
  deriveEd25519PublicKeyHex,
  signDelegationToken,
  signIncidentRecord,
  signRevocationRecord,
  type DelegationToken as CoreDelegationToken,
  type IncidentRecord as CoreIncidentRecord,
  type RevocationRecord as CoreRevocationRecord,
} from '@fides/core'
import type { AgentCard } from '../registry/client.js'

export interface AgentdClientOptions {
  baseUrl: string
  apiKey?: string
}

export interface AuthorizationRequest {
  agentDid: string
  capabilityId: string
  sessionId?: string
  audience?: string
  context?: Record<string, unknown>
  policy?: Record<string, unknown>
  attestationValid?: boolean
  reputationScore?: number
  capabilityScore?: number
  capabilityHighRisk?: boolean
  requiresRuntimeAttestation?: boolean
  requiresApproval?: boolean
  approvalGranted?: boolean
}

export type DelegationToken = CoreDelegationToken

export interface SessionGrant {
  id: string
  token: DelegationToken
  sessionKey: string
  expiresAt: string
  boundTo?: string
  createdAt?: string
  revoked?: boolean
  revokedAt?: string
  revocationReason?: string
}

export interface SessionCreateRequest {
  token: DelegationToken
  capabilityId?: string
  audience?: string
  boundTo?: string
  ttlMs?: number
  delegatorPublicKey?: string
}

export interface SessionCreateResponse {
  authorized: boolean
  session?: SessionGrant
  errors?: string[]
}

export interface SessionLookupResponse {
  session: SessionGrant
}

export interface SessionRevokeResponse {
  revoked: boolean
  session: SessionGrant
}

export interface AgentdCardResponse {
  did: string
  card: AgentCard | null
  error?: string
}

export type RevocationRecord = CoreRevocationRecord

export interface RevocationSubmitRequest {
  record: RevocationRecord
  revokerPublicKey?: string
}

export interface RevocationSubmitResponse {
  revoked: boolean
  record: RevocationRecord
  propagation?: AuthorityPropagationResponse
}

export interface RevocationStatusResponse {
  did: string
  revoked: boolean
  record?: RevocationRecord
}

export type IncidentRecord = CoreIncidentRecord

export interface CreateSignedSessionOptions {
  delegator: string
  delegatee: string
  capabilities: string[]
  privateKey: Uint8Array | string
  constraints?: DelegationToken['constraints']
  audience?: string[]
  capabilityId?: string
  boundTo?: string
  tokenExpiresAt?: string
  tokenTtlMs?: number
  sessionTtlMs?: number
  sessionAudience?: string
}

export interface RecordSignedRevocationOptions {
  did: string
  reason: string
  revokedBy: string
  privateKey: Uint8Array | string
}

export interface RecordSignedIncidentOptions {
  actor: string
  reportedBy: string
  type: IncidentRecord['type']
  severity: IncidentRecord['severity']
  description: string
  privateKey: Uint8Array | string
  evidenceRefs?: string[]
  trustPenalty?: number
  reputationPenalty?: number
  capabilitiesRevoked?: string[]
}

export interface IncidentSubmitRequest {
  record: IncidentRecord
  reporterPublicKey?: string
}

export interface IncidentSubmitResponse {
  recorded: boolean
  record: IncidentRecord
  impact?: Record<string, unknown>
  propagation?: AuthorityPropagationResponse
}

export interface IncidentListResponse {
  did: string
  incidents: IncidentRecord[]
  impact: Record<string, unknown>
}

export interface AuthorizationDecision {
  decision: 'allow' | 'deny'
  explanation: string
  factors?: Array<Record<string, unknown>>
  session?: Record<string, unknown>
  incidentImpact?: Record<string, unknown>
  revoked?: boolean
  errors?: string[]
}

export interface AuthorityPropagationResponse {
  attempted: boolean
  ok: boolean
  target: string
  status: number
  queued: boolean
  outboxId?: string
  error?: string
}

export interface AuthorityPropagationRecord {
  id: string
  actor: string
  recordType: 'revocation' | 'incident'
  recordId: string
  target: string
  path: string
  body: Record<string, unknown>
  status: 'pending' | 'confirmed' | 'failed'
  attempts: number
  maxAttempts: number
  nextAttemptAt: string
  createdAt: string
  updatedAt: string
  lastAttemptAt?: string
  lastStatus?: number
  lastError?: string
}

export interface AuthorityPropagationListResponse {
  count: number
  propagations: AuthorityPropagationRecord[]
}

export interface AuthorityPropagationRetryResult {
  id: string
  ok: boolean
  status: number
  attempts?: number
  outboxStatus?: 'pending' | 'confirmed' | 'failed'
  nextAttemptAt?: string
  error?: string
}

export interface AuthorityPropagationRetryResponse {
  attempted: number
  results: AuthorityPropagationRetryResult[]
}

export class AgentdError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly payload?: unknown
  ) {
    super(message)
    this.name = 'AgentdError'
  }
}

export class AgentdClient {
  constructor(private options: AgentdClientOptions) {}

  async createSession(request: SessionCreateRequest): Promise<SessionCreateResponse> {
    return this.post<SessionCreateResponse>('/v1/sessions', request)
  }

  async createSignedSession(options: CreateSignedSessionOptions): Promise<SessionCreateResponse> {
    const privateKey = this.privateKeyBytes(options.privateKey)
    const audience = options.audience ?? ['agentd']
    const token = createDelegationToken({
      delegator: options.delegator,
      delegatee: options.delegatee,
      capabilities: options.capabilities,
      constraints: options.constraints ?? {},
      expiresAt: options.tokenExpiresAt ?? this.expiresAt(options.tokenTtlMs ?? 3600_000),
      audience,
    })
    const signedToken = await signDelegationToken(token, privateKey)

    return this.createSession({
      token: signedToken,
      capabilityId: options.capabilityId,
      audience: options.sessionAudience ?? audience[0] ?? 'agentd',
      boundTo: options.boundTo,
      ttlMs: options.sessionTtlMs,
      delegatorPublicKey: await this.publicKeyHex(options.privateKey),
    })
  }

  async getSession(id: string): Promise<SessionLookupResponse> {
    return this.get<SessionLookupResponse>(`/v1/sessions/${encodeURIComponent(id)}`)
  }

  async getCard(did: string): Promise<AgentdCardResponse> {
    return this.get<AgentdCardResponse>(`/v1/cards/${encodeURIComponent(did)}`)
  }

  async revokeSession(id: string, reason?: string): Promise<SessionRevokeResponse> {
    return this.post<SessionRevokeResponse>(`/v1/sessions/${encodeURIComponent(id)}/revoke`, { reason })
  }

  async recordRevocation(request: RevocationSubmitRequest): Promise<RevocationSubmitResponse> {
    return this.post<RevocationSubmitResponse>('/v1/revocations', request)
  }

  async recordSignedRevocation(options: RecordSignedRevocationOptions): Promise<RevocationSubmitResponse> {
    const privateKey = this.privateKeyBytes(options.privateKey)
    const record = createRevocationRecord({
      did: options.did,
      reason: options.reason,
      revokedBy: options.revokedBy,
    })
    const signedRecord = await signRevocationRecord(record, privateKey)

    return this.recordRevocation({
      record: signedRecord,
      revokerPublicKey: await this.publicKeyHex(options.privateKey),
    })
  }

  async getRevocation(did: string): Promise<RevocationStatusResponse> {
    return this.get<RevocationStatusResponse>(`/v1/revocations/${encodeURIComponent(did)}`)
  }

  async recordIncident(request: IncidentSubmitRequest): Promise<IncidentSubmitResponse> {
    return this.post<IncidentSubmitResponse>('/v1/incidents', request)
  }

  async recordSignedIncident(options: RecordSignedIncidentOptions): Promise<IncidentSubmitResponse> {
    const privateKey = this.privateKeyBytes(options.privateKey)
    const record = createIncidentRecord({
      actor: options.actor,
      reportedBy: options.reportedBy,
      type: options.type,
      severity: options.severity,
      description: options.description,
      evidenceRefs: options.evidenceRefs,
      trustPenalty: options.trustPenalty,
      reputationPenalty: options.reputationPenalty,
      capabilitiesRevoked: options.capabilitiesRevoked,
    })
    const signedRecord = await signIncidentRecord(record, privateKey)

    return this.recordIncident({
      record: signedRecord,
      reporterPublicKey: await this.publicKeyHex(options.privateKey),
    })
  }

  async listIncidents(did: string): Promise<IncidentListResponse> {
    return this.get<IncidentListResponse>(`/v1/incidents/${encodeURIComponent(did)}`)
  }

  async authorize(request: AuthorizationRequest): Promise<AuthorizationDecision> {
    return this.post<AuthorizationDecision>('/v1/authorize', request)
  }

  async listPendingPropagations(limit = 25): Promise<AuthorityPropagationListResponse> {
    const url = new URL(`${this.baseUrl()}/v1/authority/propagations/pending`)
    url.searchParams.set('limit', String(limit))
    return this.request<AuthorityPropagationListResponse>(url.toString(), { method: 'GET' })
  }

  async retryPropagations(limit = 25): Promise<AuthorityPropagationRetryResponse> {
    return this.post<AuthorityPropagationRetryResponse>('/v1/authority/propagations/retry', { limit })
  }

  private async get<T>(path: string): Promise<T> {
    return this.request<T>(`${this.baseUrl()}${path}`, { method: 'GET' })
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>(`${this.baseUrl()}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  }

  private privateKeyBytes(key: Uint8Array | string): Uint8Array {
    const bytes = typeof key === 'string' ? Uint8Array.from(Buffer.from(key, 'hex')) : key
    if (bytes.length !== 32) {
      throw new AgentdError('Ed25519 private key must be 32 bytes')
    }
    return bytes
  }

  private async publicKeyHex(key: Uint8Array | string): Promise<string> {
    const hex = typeof key === 'string' ? key : Buffer.from(key).toString('hex')
    return deriveEd25519PublicKeyHex(hex)
  }

  private expiresAt(ttlMs: number): string {
    return new Date(Date.now() + ttlMs).toISOString()
  }

  private async request<T>(url: string, init: RequestInit): Promise<T> {
    const headers = new Headers(init.headers)
    if (this.options.apiKey) {
      headers.set('X-API-Key', this.options.apiKey)
    }

    const response = await fetch(url, { ...init, headers })
    const text = await response.text()
    const payload = text ? JSON.parse(text) : {}
    if (!response.ok) {
      throw new AgentdError(`agentd request failed: ${response.status}`, response.status, payload)
    }
    return payload as T
  }

  private baseUrl(): string {
    return this.options.baseUrl.replace(/\/$/, '')
  }
}
