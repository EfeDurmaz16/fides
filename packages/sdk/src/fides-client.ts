import {
  type CapabilityControl,
  type TrustResult,
  createInvocationRequest,
  isErrorEnvelope,
  signInvocationRequest,
  type ErrorEnvelope,
  type InvocationRequest,
  type InvocationResult,
  type SessionGrantV2,
  type SignedInvocationRequest,
  type SignedInvocationResult,
} from '@fides/core'

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
  authority?: 'candidate_only'
  cardId?: string
  capability?: string
  capabilities?: string[]
  authorityGranted?: false
  evidence_refs?: string[]
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

export interface FidesLocalAgentRegistration {
  registered?: true
  agentId: string
  cardId: string
  registeredAt: string
  signed: boolean
  verified: boolean
  authority: 'candidate_only'
  capabilities: string[]
  authorityGranted: false
  reasons: string[]
  reason?: string
  [key: string]: unknown
}

export interface FidesLocalAgentListResponse {
  agents: FidesLocalAgentRegistration[]
  authorityGranted: false
}

export interface FidesLocalAgentDetailResponse extends FidesLocalAgentRegistration {
  card: Record<string, unknown> | null
  signedCard: Record<string, unknown> | null
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

export interface FidesInvocationRequest {
  sessionId?: string
  session_id?: string
  input?: unknown
  dryRun?: boolean
  signedRequest?: SignedInvocationRequest
}

export interface FidesSignedInvocationRequest {
  sessionGrant: SessionGrantV2
  input?: unknown
  dryRun?: boolean
  privateKey: Uint8Array | string
  verificationMethod?: string
  inputSchema?: unknown
  outputSchema?: unknown
  issuedAt?: string
}

export interface FidesEvidenceExportRequest {
  privacy_mode?: 'public' | 'private' | 'redacted' | 'hash_only'
  include_metadata?: boolean
}

export interface FidesIdentityAttestationRequest {
  identity: string
}

export interface FidesGithubAttestationRequest extends FidesIdentityAttestationRequest {
  handle: string
}

export interface FidesEmailAttestationRequest extends FidesIdentityAttestationRequest {
  email: string
}

export interface FidesDomainAttestationRequest extends FidesIdentityAttestationRequest {
  domain: string
}

export interface FidesPackageAttestationRequest extends FidesIdentityAttestationRequest {
  registry: 'npm' | 'pypi'
  package: string
}

export interface FidesWalletAttestationRequest extends FidesIdentityAttestationRequest {
  address: string
}

export interface FidesInvocationResponse {
  authorityGranted: boolean
  session: SessionGrantV2
  request: InvocationRequest
  signedRequest?: SignedInvocationRequest
  signedRequestVerified?: boolean
  preflight: Record<string, unknown>
  result: InvocationResult
  signedResult?: SignedInvocationResult
  signedResultVerified?: boolean
}

export type FidesPolicyDecisionAction =
  | 'allow'
  | 'deny'
  | 'require_approval'
  | 'dry_run_only'
  | 'scope_limit'
  | 'risk_limit'

export interface FidesPolicyDecision {
  schema_version: 'fides.policy.decision.v1'
  id: string
  issuer: string
  subject: string
  decision: FidesPolicyDecisionAction
  principal_id: string
  requester_agent_id: string
  target_agent_id: string
  capability: string
  reason_codes: string[]
  machine_reasons: Array<Record<string, unknown>>
  human_reasons: string[]
  required_controls: CapabilityControl[]
  evidence_refs: string[]
  issued_at: string
  evaluated_at: string
  payload_hash: string
  [key: string]: unknown
}

export interface FidesPolicyEvaluationResponse {
  policy: FidesPolicyDecision
  trust: TrustResult
  authorityGranted: false
  requiresSessionGrant: boolean
  explanation: string
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
    register: (card: Record<string, unknown>): Promise<FidesLocalAgentRegistration> => (
      this.post('/agents/register', card) as Promise<FidesLocalAgentRegistration>
    ),
    list: (): Promise<FidesLocalAgentListResponse> => this.get('/agents') as Promise<FidesLocalAgentListResponse>,
    inspect: (agentId: string): Promise<FidesLocalAgentDetailResponse> => (
      this.get(`/agents/${encodeURIComponent(agentId)}`) as Promise<FidesLocalAgentDetailResponse>
    ),
  }

  readonly discovery = {
    find: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover', query) as Promise<FidesDiscoveryResponse>,
    local: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover/local', query) as Promise<FidesDiscoveryResponse>,
    wellKnown: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover/well-known', query) as Promise<FidesDiscoveryResponse>,
    registry: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover/registry', query) as Promise<FidesDiscoveryResponse>,
    relay: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover/relay', query) as Promise<FidesDiscoveryResponse>,
    dht: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover/dht', query) as Promise<FidesDiscoveryResponse>,
    federation: (query: FidesDiscoveryQuery): Promise<FidesDiscoveryResponse> => this.post('/discover/federation', query) as Promise<FidesDiscoveryResponse>,
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
    evaluate: (body: Record<string, unknown>): Promise<FidesPolicyEvaluationResponse> => (
      this.post('/policy/evaluate', body) as Promise<FidesPolicyEvaluationResponse>
    ),
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
    github: (body: FidesGithubAttestationRequest) => this.post('/attestations', { type: 'github', ...body }),
    email: (body: FidesEmailAttestationRequest) => this.post('/attestations', { type: 'email', ...body }),
    domain: (body: FidesDomainAttestationRequest) => this.post('/attestations', { type: 'domain', ...body }),
    package: (body: FidesPackageAttestationRequest) => this.post('/attestations', { type: 'package', ...body }),
    wallet: (body: FidesWalletAttestationRequest) => this.post('/attestations', { type: 'wallet', ...body }),
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
    export: (body: FidesEvidenceExportRequest = {}) => this.post('/evidence/export', body),
  }

  readonly demo = {
    run: () => this.post('/demo/run', {}),
  }

  readonly simulate = {
    adversarial: () => this.post('/simulate/adversarial', {}),
  }

  constructor(private readonly options: FidesClientOptions) {}

  invoke(body: FidesInvocationRequest): Promise<FidesInvocationResponse> {
    return this.post('/invoke', body) as Promise<FidesInvocationResponse>
  }

  async invokeSigned(body: FidesSignedInvocationRequest): Promise<FidesInvocationResponse> {
    const request = createInvocationRequest({
      issuer: body.sessionGrant.requester_agent_id,
      sessionGrant: body.sessionGrant,
      input: body.input ?? {},
      dryRun: body.dryRun,
      inputSchema: body.inputSchema,
      outputSchema: body.outputSchema,
      issuedAt: body.issuedAt,
    })
    const signedRequest = await signInvocationRequest(
      request,
      privateKeyBytes(body.privateKey),
      body.verificationMethod ?? body.sessionGrant.requester_agent_id
    )
    return this.invoke({
      sessionId: body.sessionGrant.session_id,
      input: body.input,
      dryRun: body.dryRun,
      signedRequest,
    })
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

function privateKeyBytes(key: Uint8Array | string): Uint8Array {
  const bytes = typeof key === 'string' ? Uint8Array.from(Buffer.from(key, 'hex')) : key
  if (bytes.length !== 32) {
    throw new FidesClientError('Ed25519 private key must be 32 bytes', 0, {}, undefined)
  }
  return bytes
}
