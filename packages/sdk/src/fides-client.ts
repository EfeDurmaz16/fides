import {
  type AgentIdentity,
  type ApprovalDecision,
  type ApprovalRequest,
  type CapabilityControl,
  type DelegationToken,
  type IdentityTrustAnchor,
  type IncidentRecordV2,
  type KillSwitchRule,
  type PrincipalIdentity,
  type PublisherIdentity,
  type RevocationRecordV2,
  type ReputationRecord,
  type TrustResult,
  createInvocationRequest,
  isErrorEnvelope,
  signInvocationRequest,
  type ErrorEnvelope,
  type InvocationRequest,
  type InvocationResult,
  type RuntimeAttestation,
  type SessionGrantV2,
  type SignedSessionGrantV2,
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

export type FidesIdentityType = 'agent' | 'publisher' | 'principal'
export type FidesIdentity = AgentIdentity | PublisherIdentity | PrincipalIdentity

export interface FidesIdentityResponse {
  type: FidesIdentityType
  did: string
  publicKeyHex: string
  createdAt: string
  identity: FidesIdentity
  [key: string]: unknown
}

export interface FidesIdentityListResponse {
  identities: Array<Omit<FidesIdentityResponse, 'identity'> & { identity?: FidesIdentity }>
  [key: string]: unknown
}

export interface FidesDiscoveryQuery {
  intent?: string
  capability: string
  constraints?: Record<string, unknown>
  supported_versions?: string[]
  required_versions?: string[]
}

export const FIDES_DISCOVERY_PROVIDERS = ['local', 'well-known', 'registry', 'relay', 'dht', 'federation'] as const
export type FidesDiscoveryProviderName = typeof FIDES_DISCOVERY_PROVIDERS[number]

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

export interface FidesDiscoveryProviderSuccess {
  provider: FidesDiscoveryProviderName
  ok: true
  result: FidesDiscoveryResponse
}

export interface FidesDiscoveryProviderFailure {
  provider: FidesDiscoveryProviderName
  ok: false
  authorityGranted: false
  error: {
    message: string
    status?: number
    code?: string
    payload?: unknown
  }
}

export type FidesDiscoveryProviderResult = FidesDiscoveryProviderSuccess | FidesDiscoveryProviderFailure

export interface FidesAllProvidersDiscoveryResponse {
  query: FidesDiscoveryQuery
  authorityGranted: false
  results: FidesDiscoveryProviderResult[]
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

export type FidesEvidenceEventType =
  | 'agent.registered'
  | 'agent.updated'
  | 'agent.revoked'
  | 'discovery.performed'
  | 'trust.computed'
  | 'policy.evaluated'
  | 'approval.requested'
  | 'approval.granted'
  | 'approval.denied'
  | 'session.requested'
  | 'session.granted'
  | 'session.denied'
  | 'capability.invoked'
  | 'capability.completed'
  | 'capability.failed'
  | 'attestation.issued'
  | 'attestation.verified'
  | 'attestation.failed'
  | 'revocation.recorded'
  | 'incident.reported'
  | 'kill_switch.triggered'

export type FidesEvidencePrivacyMode = 'public' | 'private' | 'redacted' | 'hash_only'

export interface FidesEvidenceEventV2 {
  schema_version: 'fides.evidence_event.v1'
  id: string
  event_id: string
  issuer: string
  type: FidesEvidenceEventType
  actor: string
  subject?: string
  principal?: string
  capability?: string
  input_hash?: string
  output_hash?: string
  policy_hash?: string
  decision?: string
  risk_level?: 'low' | 'medium' | 'high' | 'critical'
  privacy_mode: FidesEvidencePrivacyMode
  issued_at: string
  timestamp: string
  prev_event_hash: string
  payload_hash: string
  event_hash: string
  signature: string
  metadata?: Record<string, unknown>
}

export interface FidesEvidenceAppendResponse {
  accepted: boolean
  event: FidesEvidenceEventV2
  authorityGranted: false
  [key: string]: unknown
}

export interface FidesEvidenceEventResponse {
  event: FidesEvidenceEventV2
  authorityGranted: false
  [key: string]: unknown
}

export interface FidesEvidenceListResponse {
  events: FidesEvidenceEventV2[]
  count: number
  valid: boolean
  lastHash: string | null
  authorityGranted: false
  [key: string]: unknown
}

export interface FidesEvidenceVerificationResponse {
  valid: boolean
  count: number
  lastHash: string | null
  scope: 'root-local-evidence-ledger'
  checkedAt: string
  [key: string]: unknown
}

export interface FidesEvidenceExportResponse {
  format: 'json'
  exportedAt: string
  valid: boolean
  count: number
  privacyMode: FidesEvidencePrivacyMode | 'event_default'
  includeMetadata: boolean | null
  events: FidesEvidenceEventV2[]
  [key: string]: unknown
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

export interface FidesIdentityAttestation {
  id: string
  schema_version: 'fides.identity_attestation.v1'
  identity: string
  trust_anchor: IdentityTrustAnchor
  issued_at: string
  mode: 'local_mock'
  [key: string]: unknown
}

export interface FidesIdentityAttestationResponse {
  attestation: FidesIdentityAttestation
  identity: FidesIdentityResponse
  evidenceRefs?: string[]
  authorityGranted: false
  [key: string]: unknown
}

export interface FidesRuntimeAttestationResponse {
  attestation: RuntimeAttestation
  evidenceRefs?: string[]
  authorityGranted?: false
  [key: string]: unknown
}

export interface FidesRuntimeAttestationVerificationResponse extends FidesRuntimeAttestationResponse {
  id: string
  valid: boolean
  error?: string
}

export type FidesAttestationResponse = FidesIdentityAttestationResponse | FidesRuntimeAttestationResponse

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

export interface FidesTrustEvaluationResponse {
  trust: TrustResult
  authorityGranted: false
  explanation: string
  [key: string]: unknown
}

export interface FidesTrustListResponse {
  agentId: string
  trust: TrustResult[]
  authorityGranted: false
  [key: string]: unknown
}

export interface FidesReputationUpdateResponse {
  reputation: ReputationRecord
  authorityGranted: false
  [key: string]: unknown
}

export interface FidesReputationListResponse {
  agentId: string
  reputations: ReputationRecord[]
  authorityGranted: false
  [key: string]: unknown
}

export interface FidesDelegationResponse {
  token: DelegationToken
  signed: boolean
  authorityGranted: false
  explanation: string
  [key: string]: unknown
}

export interface FidesApprovalRequestResponse {
  approval: ApprovalRequest
  evidenceRefs: string[]
  authorityGranted: false
  explanation?: string
  [key: string]: unknown
}

export interface FidesApprovalDecisionResponse {
  approval: ApprovalRequest
  decision: ApprovalDecision
  evidenceRefs: string[]
  authorityGranted: false
  explanation?: string
  [key: string]: unknown
}

export interface FidesApprovalListResponse {
  approvals: ApprovalRequest[]
  decisions: ApprovalDecision[]
  authorityGranted: false
  [key: string]: unknown
}

export interface FidesKillSwitchRuleResponse {
  rule: KillSwitchRule
  evidenceRefs?: string[]
  authorityOverride?: boolean
  explanation?: string
  [key: string]: unknown
}

export interface FidesKillSwitchListResponse {
  rules: KillSwitchRule[]
  active: KillSwitchRule[]
  [key: string]: unknown
}

export interface FidesRevocationRecordResponse {
  record: RevocationRecordV2
  evidenceRefs?: string[]
  authorityOverride?: boolean
  explanation?: string
  [key: string]: unknown
}

export interface FidesRevocationListResponse {
  records: RevocationRecordV2[]
  active: RevocationRecordV2[]
  [key: string]: unknown
}

export interface FidesRevocationStatusResponse {
  id: string
  revoked: boolean
  record?: RevocationRecordV2
  [key: string]: unknown
}

export interface FidesIncidentRecordResponse {
  record: IncidentRecordV2
  evidenceRefs?: string[]
  explanation?: string
  [key: string]: unknown
}

export interface FidesIncidentListResponse {
  records: IncidentRecordV2[]
  open: IncidentRecordV2[]
  [key: string]: unknown
}

export interface FidesSessionResponse {
  authorized: boolean
  authorityGranted: boolean
  authorityMode?: 'full' | 'dry_run_only'
  allowedActions?: Array<'execute' | 'dry_run'>
  session: SessionGrantV2
  signedSession?: SignedSessionGrantV2
  signedSessionVerified?: boolean
  policy?: FidesPolicyDecision
  trust?: TrustResult
  evidenceRefs?: string[]
  [key: string]: unknown
}

export interface FidesSessionVerifyResponse {
  valid: boolean
  signatureValid: boolean
  notExpired: boolean
  session?: SessionGrantV2
  authorityGranted?: boolean
  [key: string]: unknown
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
    createAgent: (body: Record<string, unknown> = {}): Promise<FidesIdentityResponse> => (
      this.post('/identities', { ...body, type: 'agent' }) as Promise<FidesIdentityResponse>
    ),
    createPublisher: (body: Record<string, unknown> = {}): Promise<FidesIdentityResponse> => (
      this.post('/identities', { ...body, type: 'publisher' }) as Promise<FidesIdentityResponse>
    ),
    createPrincipal: (body: Record<string, unknown> = {}): Promise<FidesIdentityResponse> => (
      this.post('/identities', { ...body, type: 'principal' }) as Promise<FidesIdentityResponse>
    ),
    list: (): Promise<FidesIdentityListResponse> => this.get('/identities') as Promise<FidesIdentityListResponse>,
    show: (id: string): Promise<FidesIdentityResponse> => (
      this.get(`/identities/${encodeURIComponent(id)}`) as Promise<FidesIdentityResponse>
    ),
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
    allProviders: (
      query: FidesDiscoveryQuery,
      providers: readonly FidesDiscoveryProviderName[] = FIDES_DISCOVERY_PROVIDERS
    ): Promise<FidesAllProvidersDiscoveryResponse> => this.discoverAllProviders(query, providers),
  }

  readonly trust = {
    evaluate: (body: Record<string, unknown>): Promise<FidesTrustEvaluationResponse> => (
      this.post('/trust/evaluate', body) as Promise<FidesTrustEvaluationResponse>
    ),
    get: (agentId: string): Promise<FidesTrustListResponse> => (
      this.get(`/trust/${encodeURIComponent(agentId)}`) as Promise<FidesTrustListResponse>
    ),
  }

  readonly reputation = {
    update: (body: Record<string, unknown>): Promise<FidesReputationUpdateResponse> => (
      this.post('/reputation/update', body) as Promise<FidesReputationUpdateResponse>
    ),
    get: (agentId: string): Promise<FidesReputationListResponse> => (
      this.get(`/reputation/${encodeURIComponent(agentId)}`) as Promise<FidesReputationListResponse>
    ),
  }

  readonly policy = {
    evaluate: (body: Record<string, unknown>): Promise<FidesPolicyEvaluationResponse> => (
      this.post('/policy/evaluate', body) as Promise<FidesPolicyEvaluationResponse>
    ),
  }

  readonly delegations = {
    create: (body: Record<string, unknown>): Promise<FidesDelegationResponse> => (
      this.post('/delegations', body) as Promise<FidesDelegationResponse>
    ),
  }

  readonly approvals = {
    create: (body: Record<string, unknown>): Promise<FidesApprovalRequestResponse> => (
      this.post('/approvals', body) as Promise<FidesApprovalRequestResponse>
    ),
    list: (): Promise<FidesApprovalListResponse> => this.get('/approvals') as Promise<FidesApprovalListResponse>,
    approve: (approvalId: string, body: Record<string, unknown> = {}): Promise<FidesApprovalDecisionResponse> => (
      this.post(`/approvals/${encodeURIComponent(approvalId)}/approve`, body) as Promise<FidesApprovalDecisionResponse>
    ),
    deny: (approvalId: string, body: Record<string, unknown> = {}): Promise<FidesApprovalDecisionResponse> => (
      this.post(`/approvals/${encodeURIComponent(approvalId)}/deny`, body) as Promise<FidesApprovalDecisionResponse>
    ),
  }

  readonly killSwitch = {
    enable: (body: Record<string, unknown>): Promise<FidesKillSwitchRuleResponse> => (
      this.post('/killswitch', body) as Promise<FidesKillSwitchRuleResponse>
    ),
    list: (): Promise<FidesKillSwitchListResponse> => this.get('/killswitch') as Promise<FidesKillSwitchListResponse>,
    disable: (ruleId: string): Promise<FidesKillSwitchRuleResponse> => (
      this.delete(`/killswitch/${encodeURIComponent(ruleId)}`) as Promise<FidesKillSwitchRuleResponse>
    ),
  }

  readonly revocations = {
    create: (body: Record<string, unknown>): Promise<FidesRevocationRecordResponse> => (
      this.post('/revocations', body) as Promise<FidesRevocationRecordResponse>
    ),
    list: (): Promise<FidesRevocationListResponse> => this.get('/revocations') as Promise<FidesRevocationListResponse>,
    get: (recordId: string): Promise<FidesRevocationStatusResponse> => (
      this.get(`/revocations/${encodeURIComponent(recordId)}`) as Promise<FidesRevocationStatusResponse>
    ),
  }

  readonly incidents = {
    report: (body: Record<string, unknown>): Promise<FidesIncidentRecordResponse> => (
      this.post('/incidents', body) as Promise<FidesIncidentRecordResponse>
    ),
    list: (): Promise<FidesIncidentListResponse> => this.get('/incidents') as Promise<FidesIncidentListResponse>,
    get: (recordId: string): Promise<FidesIncidentRecordResponse> => (
      this.get(`/incidents/${encodeURIComponent(recordId)}`) as Promise<FidesIncidentRecordResponse>
    ),
    resolve: (recordId: string, body: Record<string, unknown> = {}): Promise<FidesIncidentRecordResponse> => (
      this.post(`/incidents/${encodeURIComponent(recordId)}/resolve`, body) as Promise<FidesIncidentRecordResponse>
    ),
  }

  readonly attestations = {
    create: (body: Record<string, unknown>): Promise<FidesAttestationResponse> => (
      this.post('/attestations', body) as Promise<FidesAttestationResponse>
    ),
    github: (body: FidesGithubAttestationRequest): Promise<FidesIdentityAttestationResponse> => (
      this.post('/attestations', { type: 'github', ...body }) as Promise<FidesIdentityAttestationResponse>
    ),
    email: (body: FidesEmailAttestationRequest): Promise<FidesIdentityAttestationResponse> => (
      this.post('/attestations', { type: 'email', ...body }) as Promise<FidesIdentityAttestationResponse>
    ),
    domain: (body: FidesDomainAttestationRequest): Promise<FidesIdentityAttestationResponse> => (
      this.post('/attestations', { type: 'domain', ...body }) as Promise<FidesIdentityAttestationResponse>
    ),
    package: (body: FidesPackageAttestationRequest): Promise<FidesIdentityAttestationResponse> => (
      this.post('/attestations', { type: 'package', ...body }) as Promise<FidesIdentityAttestationResponse>
    ),
    wallet: (body: FidesWalletAttestationRequest): Promise<FidesIdentityAttestationResponse> => (
      this.post('/attestations', { type: 'wallet', ...body }) as Promise<FidesIdentityAttestationResponse>
    ),
    get: (attestationId: string): Promise<FidesRuntimeAttestationResponse> => (
      this.get(`/attestations/${encodeURIComponent(attestationId)}`) as Promise<FidesRuntimeAttestationResponse>
    ),
    verify: (attestationId: string): Promise<FidesRuntimeAttestationVerificationResponse> => (
      this.post(`/attestations/${encodeURIComponent(attestationId)}/verify`, {}) as Promise<FidesRuntimeAttestationVerificationResponse>
    ),
  }

  readonly sessions = {
    request: (body: Record<string, unknown>): Promise<FidesSessionResponse> => (
      this.post('/sessions', body) as Promise<FidesSessionResponse>
    ),
    verify: (sessionId: string): Promise<FidesSessionVerifyResponse> => (
      this.post(`/sessions/${encodeURIComponent(sessionId)}/verify`, {}) as Promise<FidesSessionVerifyResponse>
    ),
    get: (sessionId: string): Promise<FidesSessionResponse> => (
      this.get(`/sessions/${encodeURIComponent(sessionId)}`) as Promise<FidesSessionResponse>
    ),
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
    append: (body: Record<string, unknown>): Promise<FidesEvidenceAppendResponse> => (
      this.post('/evidence', body) as Promise<FidesEvidenceAppendResponse>
    ),
    list: (): Promise<FidesEvidenceListResponse> => this.get('/evidence') as Promise<FidesEvidenceListResponse>,
    inspect: (eventId: string): Promise<FidesEvidenceEventResponse> => (
      this.get(`/evidence/${encodeURIComponent(eventId)}`) as Promise<FidesEvidenceEventResponse>
    ),
    verify: (): Promise<FidesEvidenceVerificationResponse> => (
      this.post('/evidence/verify', {}) as Promise<FidesEvidenceVerificationResponse>
    ),
    export: (body: FidesEvidenceExportRequest = {}): Promise<FidesEvidenceExportResponse> => (
      this.post('/evidence/export', body) as Promise<FidesEvidenceExportResponse>
    ),
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

  private async discoverAllProviders(
    query: FidesDiscoveryQuery,
    providers: readonly FidesDiscoveryProviderName[]
  ): Promise<FidesAllProvidersDiscoveryResponse> {
    const results = await Promise.all(providers.map(async (provider): Promise<FidesDiscoveryProviderResult> => {
      const path = provider === 'local' ? '/discover/local' : `/discover/${provider}`
      try {
        return {
          provider,
          ok: true,
          result: await this.post(path, query) as FidesDiscoveryResponse,
        }
      } catch (err) {
        return {
          provider,
          ok: false,
          authorityGranted: false,
          error: discoveryProviderError(err),
        }
      }
    }))

    return {
      query,
      authorityGranted: false,
      results,
    }
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

function discoveryProviderError(err: unknown): FidesDiscoveryProviderFailure['error'] {
  if (err instanceof FidesClientError) {
    return {
      message: err.message,
      status: err.status || undefined,
      code: err.error?.code,
      payload: err.payload,
    }
  }
  return {
    message: err instanceof Error ? err.message : String(err),
  }
}

function privateKeyBytes(key: Uint8Array | string): Uint8Array {
  const bytes = typeof key === 'string' ? Uint8Array.from(Buffer.from(key, 'hex')) : key
  if (bytes.length !== 32) {
    throw new FidesClientError('Ed25519 private key must be 32 bytes', 0, {}, undefined)
  }
  return bytes
}
