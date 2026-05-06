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

export interface AuthorizationDecision {
  decision: 'allow' | 'deny'
  explanation: string
  factors?: Array<Record<string, unknown>>
  session?: Record<string, unknown>
  incidentImpact?: Record<string, unknown>
  revoked?: boolean
  errors?: string[]
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
