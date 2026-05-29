import { isErrorEnvelope, type ErrorEnvelope } from '@fides/core'

export interface FidesClientOptions {
  daemonUrl: string
  apiKey?: string
}

export interface FidesRequestOptions {
  headers?: Record<string, string>
}

export interface FidesDiscoveryQuery {
  intent?: string
  capability: string
  constraints?: Record<string, unknown>
  supported_versions?: string[]
  required_versions?: string[]
}

export interface FidesProviderRecord {
  agentId?: string
  agent_id?: string
  cardId?: string
  capability?: string
  capabilities?: string[]
  authorityGranted?: false
  agentCardUrl?: string
  agent_card_url?: string
  agentCardHash?: string
  agent_card_hash?: string
  registryIndexVerified?: boolean
  registryIndexRecord?: Record<string, unknown>
  registryIndexProof?: Record<string, unknown> | null
  signedAgentCard?: boolean
  agentCardProof?: Record<string, unknown> | null
  verification?: Record<string, unknown>
  versionNegotiation?: Record<string, unknown>
  reasons?: string[]
  [key: string]: unknown
}

export interface FidesDiscoveryResponse {
  provider?: string
  capability?: string | null
  candidates?: FidesProviderRecord[]
  rejectedCandidates?: FidesProviderRecord[]
  records?: FidesProviderRecord[]
  rejectedRecords?: FidesProviderRecord[]
  pointers?: FidesProviderRecord[]
  rejectedPointers?: FidesProviderRecord[]
  authorityGranted: false
  explanation?: string
  [key: string]: unknown
}

export interface FidesRegistryPublishRequest {
  agentCardId: string
  mode?: 'public' | 'private'
}

export interface FidesRelayRegisterRequest {
  agentId: string
  endpointHints?: string[]
}

export interface FidesDhtPublishRequest {
  capability: string
  agentId?: string
  agentCardId?: string
  agentCard?: string
  agentCardUrl?: string
  expiresAt?: string
}

export class FidesClientError extends Error {
  readonly name = 'FidesClientError'

  constructor(
    message: string,
    readonly status: number,
    readonly payload: unknown,
    readonly error?: ErrorEnvelope
  ) {
    super(message)
  }
}

export class FidesClient {
  readonly identity = {
    createAgent: (body: Record<string, unknown> = {}) => this.post('/identities', { ...body, type: 'agent' }),
    createPublisher: (body: Record<string, unknown> = {}) => this.post('/identities', { ...body, type: 'publisher' }),
    createPrincipal: (body: Record<string, unknown> = {}) => this.post('/identities', { ...body, type: 'principal' }),
    list: () => this.get('/identities'),
    show: (id: string) => this.get(`/identities/${encodeURIComponent(id)}`),
  }

  readonly cards = {
    create: (body: Record<string, unknown>) => this.post('/agent-cards', body),
    sign: (card: { id?: string } & Record<string, unknown>) => this.post(`/agent-cards/${encodeURIComponent(String(card.id))}/sign`, card),
    verify: (id: string) => this.post(`/agent-cards/${encodeURIComponent(id)}/verify`, {}),
    get: (id: string) => this.get(`/agent-cards/${encodeURIComponent(id)}`),
  }

  readonly agents = {
    register: (card: Record<string, unknown>) => this.post('/agents/register', card),
    list: () => this.get('/agents'),
    inspect: (agentId: string) => this.get(`/agents/${encodeURIComponent(agentId)}`),
  }

  readonly discovery = {
    find: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover', query) as Promise<FidesDiscoveryResponse>,
    local: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover/local', query) as Promise<FidesDiscoveryResponse>,
    wellKnown: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover/well-known', query) as Promise<FidesDiscoveryResponse>,
    registry: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover/registry', query) as Promise<FidesDiscoveryResponse>,
    relay: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover/relay', query) as Promise<FidesDiscoveryResponse>,
    dht: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover/dht', query) as Promise<FidesDiscoveryResponse>,
  }

  readonly trust = {
    evaluate: (body: Record<string, unknown>) => this.post('/trust/evaluate', body),
    get: (agentId: string) => this.get(`/trust/${encodeURIComponent(agentId)}`),
  }

  readonly reputation = {
    update: (body: Record<string, unknown>) => this.post('/reputation/update', body),
    get: (agentId: string) => this.get(`/reputation/${encodeURIComponent(agentId)}`),
  }

  readonly policy = {
    evaluate: (body: Record<string, unknown>) => this.post('/policy/evaluate', body),
  }

  readonly delegations = {
    create: (body: Record<string, unknown>) => this.post('/delegations', body),
  }

  readonly approvals = {
    create: (body: Record<string, unknown>) => this.post('/approvals', body),
    list: () => this.get('/approvals'),
    approve: (approvalId: string, body: Record<string, unknown> = {}) => this.post(`/approvals/${encodeURIComponent(approvalId)}/approve`, body),
    deny: (approvalId: string, body: Record<string, unknown> = {}) => this.post(`/approvals/${encodeURIComponent(approvalId)}/deny`, body),
  }

  readonly killSwitch = {
    enable: (body: Record<string, unknown>) => this.post('/killswitch', body),
    list: () => this.get('/killswitch'),
    disable: (ruleId: string) => this.delete(`/killswitch/${encodeURIComponent(ruleId)}`),
  }

  readonly revocations = {
    create: (body: Record<string, unknown>) => this.post('/revocations', body),
    list: () => this.get('/revocations'),
    get: (recordId: string) => this.get(`/revocations/${encodeURIComponent(recordId)}`),
  }

  readonly incidents = {
    report: (body: Record<string, unknown>) => this.post('/incidents', body),
    list: () => this.get('/incidents'),
    get: (recordId: string) => this.get(`/incidents/${encodeURIComponent(recordId)}`),
    resolve: (recordId: string, body: Record<string, unknown> = {}) => this.post(`/incidents/${encodeURIComponent(recordId)}/resolve`, body),
  }

  readonly attestations = {
    create: (body: Record<string, unknown>) => this.post('/attestations', body),
    get: (attestationId: string) => this.get(`/attestations/${encodeURIComponent(attestationId)}`),
    verify: (attestationId: string) => this.post(`/attestations/${encodeURIComponent(attestationId)}/verify`, {}),
  }

  readonly sessions = {
    request: (body: Record<string, unknown>) => this.post('/sessions', body),
    verify: (sessionId: string) => this.post(`/sessions/${encodeURIComponent(sessionId)}/verify`, {}),
    get: (sessionId: string) => this.get(`/sessions/${encodeURIComponent(sessionId)}`),
  }

  readonly registry = {
    start: () => this.post('/registry/start', {}),
    publish: (body: FidesRegistryPublishRequest) => this.post('/registry/publish', body),
    search: (body: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/registry/search', body) as Promise<FidesDiscoveryResponse>,
    index: () => this.get('/registry/index'),
  }

  readonly relay = {
    start: () => this.post('/relay/start', {}),
    register: (body: FidesRelayRegisterRequest) => this.post('/relay/register', body),
    discover: (body: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/relay/discover', body) as Promise<FidesDiscoveryResponse>,
  }

  readonly dht = {
    start: () => this.post('/dht/start', {}),
    publish: (body: FidesDhtPublishRequest) => this.post('/dht/publish', body),
    find: (body: Pick<FidesDiscoveryQuery, 'capability'>) => this.post('/dht/find', body),
  }

  readonly wellKnown = {
    fides: () => this.get('/.well-known/fides.json'),
    agents: () => this.get('/.well-known/agents.json'),
    agent: (agentId: string) => this.get(`/.well-known/agents/${encodeURIComponent(agentId)}.json`),
  }

  readonly evidence = {
    append: (body: Record<string, unknown>) => this.post('/evidence', body),
    list: () => this.get('/evidence'),
    inspect: (eventId: string) => this.get(`/evidence/${encodeURIComponent(eventId)}`),
    verify: () => this.post('/evidence/verify', {}),
    export: () => this.post('/evidence/export', {}),
  }

  readonly demo = {
    run: () => this.post('/demo/run', {}),
  }

  readonly simulate = {
    adversarial: () => this.post('/simulate/adversarial', {}),
  }

  constructor(private readonly options: FidesClientOptions) {}

  invoke(body: Record<string, unknown>): Promise<unknown> {
    return this.post('/invoke', body)
  }

  private async get(path: string): Promise<unknown> {
    return this.request(path, { method: 'GET' })
  }

  private async post(path: string, body: unknown): Promise<unknown> {
    return this.request(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  }

  private async delete(path: string): Promise<unknown> {
    return this.request(path, { method: 'DELETE' })
  }

  private async request(path: string, init: RequestInit): Promise<unknown> {
    const headers = new Headers(init.headers)
    if (this.options.apiKey) {
      headers.set('X-API-Key', this.options.apiKey)
    }

    const response = await fetch(`${this.options.daemonUrl.replace(/\/+$/, '')}${path}`, {
      ...init,
      headers,
    })
    const text = await response.text()
    const payload = text ? JSON.parse(text) : {}
    if (!response.ok) {
      const envelope = extractErrorEnvelope(payload)
      const message = envelope?.message ?? `FIDES request failed with HTTP ${response.status}`
      throw new FidesClientError(message, response.status, payload, envelope)
    }
    return payload
  }
}

function extractErrorEnvelope(payload: unknown): ErrorEnvelope | undefined {
  if (isErrorEnvelope(payload)) return payload
  if (!payload || typeof payload !== 'object') return undefined
  const error = (payload as { error?: unknown }).error
  return isErrorEnvelope(error) ? error : undefined
}
