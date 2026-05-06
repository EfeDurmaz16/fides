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

export interface DelegationToken {
  id: string
  delegator: string
  delegatee: string
  capabilities: string[]
  constraints: Record<string, unknown>
  issuedAt: string
  expiresAt: string
  nonce: string
  signature: string
  audience?: string[]
}

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

export interface RevocationRecord {
  id: string
  did: string
  reason: string
  revokedAt: string
  revokedBy: string
  signature: string
  propagatedTo: string[]
}

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

export interface IncidentRecord {
  id: string
  type: 'compromise' | 'misbehavior' | 'policy_violation' | 'runtime_failure' | 'sybil'
  severity: 'low' | 'medium' | 'high' | 'critical'
  actor: string
  reportedBy: string
  description: string
  evidenceRefs: string[]
  reportedAt: string
  impact: {
    trustPenalty: number
    reputationPenalty: number
    capabilitiesRevoked: string[]
  }
  signature: string
  resolvedAt?: string
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

  async getSession(id: string): Promise<SessionLookupResponse> {
    return this.get<SessionLookupResponse>(`/v1/sessions/${encodeURIComponent(id)}`)
  }

  async revokeSession(id: string, reason?: string): Promise<SessionRevokeResponse> {
    return this.post<SessionRevokeResponse>(`/v1/sessions/${encodeURIComponent(id)}/revoke`, { reason })
  }

  async recordRevocation(request: RevocationSubmitRequest): Promise<RevocationSubmitResponse> {
    return this.post<RevocationSubmitResponse>('/v1/revocations', request)
  }

  async getRevocation(did: string): Promise<RevocationStatusResponse> {
    return this.get<RevocationStatusResponse>(`/v1/revocations/${encodeURIComponent(did)}`)
  }

  async recordIncident(request: IncidentSubmitRequest): Promise<IncidentSubmitResponse> {
    return this.post<IncidentSubmitResponse>('/v1/incidents', request)
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
