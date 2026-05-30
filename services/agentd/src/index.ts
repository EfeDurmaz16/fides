/**
 * FIDES v2 Local Daemon (agentd)
 *
 * Provides a local HTTP API proxying to the FIDES trust fabric services.
 * Connects to discovery, trust-graph, and registry services.
 */

import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { cors } from 'hono/cors'
import { bodyLimit } from 'hono/body-limit'
import { resolveTxt } from 'node:dns/promises'
import { rateLimitMiddleware, MetricsCollector, metricsMiddleware } from '@fides/sdk'
import {
  appendEvidenceEvent,
  appendEvidenceEventV2,
  createEvidenceChain,
  createEvidenceEventV2,
  exportEvidenceEventsV2,
  normalizeEvidenceEventsV2,
  verifyEvidenceChain,
  verifyEvidenceEventsV2,
  type EvidenceEventV2,
  type EvidenceEventV2Input,
} from '@fides/evidence'
import { MockTEEProvider as RuntimeMockTEEProvider, InMemoryKillSwitch } from '@fides/runtime'
import { evaluateFidesPolicy, evaluatePolicy, type FidesPolicyDecision, type PolicyBundle } from '@fides/policy'
import { createTrustContext, evaluateGuard } from '@fides/guard'
import {
  aggregateIncidentImpact,
  authorizeDelegation,
  authorizeDelegationV2,
  authorizeSessionInvocation,
  createAttestation,
  createAgentIdentity,
  computeCapabilityReputation,
  computeTrustResult,
  createApprovalDecision,
  createApprovalRequest,
  createCapabilityDescriptor,
  createIncidentRecordV2,
  createInvocationRequest,
  createInvocationResult,
  createKillSwitchRule,
  createDelegationToken,
  createDHTPointerRecord,
  createErrorEnvelope,
  createRegistryIndexRecord,
  createRegistryPeerRecord,
  createPrincipalIdentity,
  createPublisherIdentity,
  createRevocationRecordV2,
  createSessionGrantV2,
  hashAgentCard,
  hashProtocolPayload,
  isAttestationExpired,
  isKillSwitchRuleActive,
  MockTEEProvider as CoreMockTEEProvider,
  negotiateProtocolVersion,
  normalizeAgentCard,
  resolveIncidentRecordV2,
  signAgentCard,
  signDelegationToken,
  signDHTPointerRecord,
  signRegistryIndexRecord,
  signRegistryPeerRecord,
  signSessionGrantV2,
  verifySignedInvocationRequestIssuer,
  signInvocationResult,
  validateAgentCard,
  verifyDHTPointerRecord,
  verifySignedInvocationResult,
  verifySignedRegistryIndexRecord,
  verifySignedRegistryPeerRecord,
  verifySignedAgentCard,
  verifySignedAgentCardIdentity,
  verifySignedSessionGrantV2Issuer,
  verifyDelegationTokenSignature,
  verifyDomainDid,
  evaluateInvocationPreflight,
  validateInvocationRequestAgainstSessionGrant,
  validateJsonSchemaValue,
  verifyIncidentRecord,
  verifyRevocationRecord,
  type Attestation,
  type AgentIdentity,
  type AgentCard,
  type ApprovalDecision,
  type ApprovalRequest,
  type DelegationConstraint,
  type DHTPointerRecord,
  type IncidentRecord,
  type IncidentRecordV2,
  type FidesErrorCode,
  type IdentityTrustAnchor,
  type KillSwitchRule,
  type DelegationToken,
  type SignedDelegationTokenV2,
  type PrincipalIdentity,
  type PublisherIdentity,
  type ReputationRecord,
  type RevocationRecord,
  type RevocationRecordV2,
  type RuntimeAttestation,
  type SessionGrantV2,
  type SignedSessionGrantV2,
  type SignedInvocationRequest,
  type SignedRegistryIndexRecord,
  type SignedRegistryPeerRecord,
  type SignedAgentCard,
  type TrustAnchorType,
  type TrustResult,
  type VersionNegotiationRecord,
} from '@fides/core'
import { createAuthorityStore, createLocalDaemonStateStore, emptyLocalDaemonStateSnapshot } from './storage.js'
import type {
  AuthorityPropagationRecord,
  AuthorityPropagationRecordType,
  AuthorityPropagationStatus,
  LocalDaemonStateSnapshot,
} from './storage.js'
import { logger } from './middleware/logger.js'
import { securityHeaders } from './middleware/security.js'
import { errorHandler } from './middleware/error-handler.js'
import { agentdScopeForRequest, apiKeyAuth } from './middleware/auth.js'

const app = new Hono()
const collector = new MetricsCollector()

const DISCOVERY_URL = process.env.DISCOVERY_URL || 'http://localhost:3100'
const TRUST_GRAPH_URL = process.env.TRUST_GRAPH_URL || 'http://localhost:3200'
const REGISTRY_URL = process.env.REGISTRY_URL || 'http://localhost:7346'
const TRUST_GRAPH_SERVICE_ID = 'trust-graph'
const PROPAGATION_MAX_ATTEMPTS = parseInt(process.env.AGENTD_PROPAGATION_MAX_ATTEMPTS || '5', 10)

function localError(
  code: FidesErrorCode,
  message: string,
  details?: Record<string, unknown>,
): { error: ReturnType<typeof createErrorEnvelope>; authorityGranted: false } {
  return {
    error: createErrorEnvelope(code, {
      message,
      ...(details ? { details } : {}),
    }),
    authorityGranted: false,
  }
}

const teeProvider = new RuntimeMockTEEProvider()
const runtimeAttestationProvider = new CoreMockTEEProvider()
const killSwitch = new InMemoryKillSwitch()
const authorityStore = createAuthorityStore()
const localStateStore = createLocalDaemonStateStore()
const localDhtPointers: Array<Record<string, unknown>> = []
type LocalIdentityType = 'agent' | 'publisher' | 'principal'
interface LocalIdentityRecord {
  type: LocalIdentityType
  identity: AgentIdentity | PublisherIdentity | PrincipalIdentity
  publicKeyHex: string
  privateKeyHex: string
  createdAt: string
}
const localIdentities = new Map<string, LocalIdentityRecord>()
const localAgentCards = new Map<string, AgentCard>()
const localSignedAgentCards = new Map<string, SignedAgentCard>()
const localRegistryRecords = new Map<string, Record<string, unknown>>()
const localRelayRecords = new Map<string, Record<string, unknown>>()
interface LocalRegisteredAgent {
  agentId: string
  cardId: string
  registeredAt: string
  signed: boolean
}
const localAgents = new Map<string, LocalRegisteredAgent>()
const localTrustResults = new Map<string, TrustResult>()
const localReputationRecords = new Map<string, ReputationRecord>()
const localDelegationTokens = new Map<string, DelegationToken>()
const localApprovals = new Map<string, ApprovalRequest>()
const localApprovalDecisions = new Map<string, ApprovalDecision>()
const localKillSwitchRules = new Map<string, KillSwitchRule>()
const localRevocationRecords = new Map<string, RevocationRecordV2>()
const localIncidentRecords = new Map<string, IncidentRecordV2>()
const localGenericAttestations = new Map<string, Attestation>()
const localRuntimeAttestations = new Map<string, RuntimeAttestation>()
let localEvidenceEvents: EvidenceEventV2[] = []
interface LocalSessionRecord {
  session: SessionGrantV2
  signedSession: SignedSessionGrantV2
  policy: FidesPolicyDecision
  trust: TrustResult
}
const localSessionGrants = new Map<string, LocalSessionRecord>()
let localStateLoaded = false
const fullDemoSteps = [
  'initialize_daemon',
  'create_principal_identity',
  'create_publisher_identity',
  'add_github_attestation',
  'add_email_attestation',
  'add_domain_attestation',
  'create_calendar_agent',
  'create_invoice_agent',
  'create_payment_agent',
  'create_payment_runtime_attestation',
  'sign_agent_cards',
  'register_agents_locally',
  'publish_invoice_agent_to_registry',
  'publish_calendar_agent_to_relay',
  'publish_payment_pointer_to_dht',
  'verify_signed_registry_index_record',
  'verify_signed_relay_agent_card_reference',
  'verify_signed_dht_pointer_record',
  'discover_calendar_locally',
  'discover_invoice_through_registry',
  'discover_payment_through_dht',
  'verify_agent_cards',
  'evaluate_trust',
  'show_capability_reputation',
  'request_invoice_session',
  'invoke_invoice_agent',
  'emit_invocation_evidence',
  'deny_high_risk_payment_without_attestation',
  'add_runtime_attestation',
  'request_payment_dry_run_session',
  'invoke_payment_dry_run',
  'report_malicious_agent_incident',
  'apply_trust_penalty',
  'revoke_malicious_agent',
  'verify_revoked_agent_not_trusted',
  'verify_evidence_hash_chain',
  'export_evidence_log',
  'print_final_trust_graph',
] as const

const startTime = Date.now()

function getCorsOrigin(): string {
  const corsOrigin = process.env.CORS_ORIGIN
  if (process.env.NODE_ENV === 'production') {
    if (!corsOrigin) {
      console.warn('CORS_ORIGIN not set in production — using restrictive default')
    }
    return corsOrigin || 'https://localhost'
  }
  return corsOrigin || '*'
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}

function mapValues<T>(items: T[]): Map<string, T> {
  return new Map(items.flatMap((item) => {
    const id = typeof item === 'object' && item !== null
      ? (item as Record<string, unknown>).id
      : undefined
    return typeof id === 'string' ? [[id, item] as const] : []
  }))
}

function hydrateLocalState(snapshot: LocalDaemonStateSnapshot): void {
  localIdentities.clear()
  for (const record of snapshot.identities as LocalIdentityRecord[]) {
    if (record?.identity?.did) localIdentities.set(record.identity.did, record)
  }
  localAgentCards.clear()
  for (const card of snapshot.agentCards as AgentCard[]) {
    if (card?.id) localAgentCards.set(card.id, card)
  }
  localSignedAgentCards.clear()
  for (const signed of snapshot.signedAgentCards as SignedAgentCard[]) {
    if (signed?.payload?.id) localSignedAgentCards.set(signed.payload.id, signed)
  }
  localAgents.clear()
  for (const record of snapshot.agents as LocalRegisteredAgent[]) {
    if (record?.agentId) localAgents.set(record.agentId, record)
  }
  localDhtPointers.length = 0
  localDhtPointers.push(...snapshot.dhtPointers as Array<Record<string, unknown>>)
  localRegistryRecords.clear()
  for (const record of snapshot.registryRecords as Array<Record<string, unknown>>) {
    if (typeof record.id === 'string') localRegistryRecords.set(record.id, record)
  }
  localRelayRecords.clear()
  for (const record of snapshot.relayRecords as Array<Record<string, unknown>>) {
    const id = typeof record.agentId === 'string' ? record.agentId : typeof record.id === 'string' ? record.id : undefined
    if (id) localRelayRecords.set(id, record)
  }
  localTrustResults.clear()
  for (const trust of snapshot.trustResults as TrustResult[]) {
    if (trust?.agent_id && trust?.capability) localTrustResults.set(localCapabilityKey(trust.agent_id, trust.capability), trust)
  }
  localReputationRecords.clear()
  for (const record of snapshot.reputationRecords as ReputationRecord[]) {
    if (record?.agent_id && record?.capability) localReputationRecords.set(localCapabilityKey(record.agent_id, record.capability), record)
  }
  localDelegationTokens.clear()
  for (const token of snapshot.delegationTokens as DelegationToken[]) {
    if (token?.id) localDelegationTokens.set(token.id, token)
  }
  replaceMap(localApprovals, mapValues(snapshot.approvals as ApprovalRequest[]))
  replaceMap(localApprovalDecisions, mapValues(snapshot.approvalDecisions as ApprovalDecision[]))
  replaceMap(localKillSwitchRules, mapValues(snapshot.killSwitchRules as KillSwitchRule[]))
  replaceMap(localRevocationRecords, mapValues(snapshot.revocationRecords as RevocationRecordV2[]))
  replaceMap(localIncidentRecords, mapValues(snapshot.incidentRecords as IncidentRecordV2[]))
  replaceMap(localGenericAttestations, mapValues(snapshot.genericAttestations as Attestation[]))
  localRuntimeAttestations.clear()
  for (const attestation of snapshot.runtimeAttestations as RuntimeAttestation[]) {
    if (attestation?.attestation_id) localRuntimeAttestations.set(attestation.attestation_id, attestation)
  }
  localEvidenceEvents = normalizeEvidenceEventsV2(snapshot.evidenceEvents as Array<Record<string, unknown>>)
  localSessionGrants.clear()
  for (const record of snapshot.sessionGrants as LocalSessionRecord[]) {
    if (record?.session?.session_id && record.signedSession) localSessionGrants.set(record.session.session_id, record)
  }
}

function replaceMap<K, V>(target: Map<K, V>, source: Map<K, V>): void {
  target.clear()
  for (const [key, value] of source) target.set(key, value)
}

function localStateSnapshot(): LocalDaemonStateSnapshot {
  return {
    ...emptyLocalDaemonStateSnapshot(),
    identities: Array.from(localIdentities.values()),
    agentCards: Array.from(localAgentCards.values()),
    signedAgentCards: Array.from(localSignedAgentCards.values()),
    agents: Array.from(localAgents.values()),
    dhtPointers: [...localDhtPointers],
    registryRecords: Array.from(localRegistryRecords.values()),
    relayRecords: Array.from(localRelayRecords.values()),
    trustResults: Array.from(localTrustResults.values()),
    reputationRecords: Array.from(localReputationRecords.values()),
    delegationTokens: Array.from(localDelegationTokens.values()),
    approvals: Array.from(localApprovals.values()),
    approvalDecisions: Array.from(localApprovalDecisions.values()),
    killSwitchRules: Array.from(localKillSwitchRules.values()),
    revocationRecords: Array.from(localRevocationRecords.values()),
    incidentRecords: Array.from(localIncidentRecords.values()),
    genericAttestations: Array.from(localGenericAttestations.values()),
    runtimeAttestations: Array.from(localRuntimeAttestations.values()),
    evidenceEvents: localEvidenceEvents,
    sessionGrants: Array.from(localSessionGrants.values()),
  }
}

async function ensureLocalStateLoaded(): Promise<void> {
  if (localStateLoaded) return
  const snapshot = await localStateStore.load()
  if (snapshot) hydrateLocalState(snapshot)
  localStateLoaded = true
}

async function persistLocalState(): Promise<void> {
  if (!localStateLoaded) return
  await localStateStore.save(localStateSnapshot())
}

function shouldPersistLocalState(method: string, path: string, status: number): boolean {
  if (status >= 500) return false
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) return false
  return [
    '/identities',
    '/agent-cards',
    '/agents',
    '/trust',
    '/reputation',
    '/delegations',
    '/sessions',
    '/invoke',
    '/approvals',
    '/killswitch',
    '/revocations',
    '/incidents',
    '/attestations',
    '/dht',
    '/registry',
    '/relay',
    '/evidence',
    '/demo',
    '/simulate',
  ].some(prefix => path === prefix || path.startsWith(`${prefix}/`))
}

async function createLocalIdentity(
  type: LocalIdentityType,
  input: { name?: string; domain?: string }
): Promise<LocalIdentityRecord> {
  if (type === 'agent') {
    const issued = await createAgentIdentity()
    return {
      type,
      identity: {
        ...issued.identity,
        metadata: { name: input.name ?? 'Agent' },
      },
      publicKeyHex: bytesToHex(issued.publicKey),
      privateKeyHex: bytesToHex(issued.privateKey),
      createdAt: issued.identity.createdAt,
    }
  }

  if (type === 'publisher') {
    const issued = await createPublisherIdentity({
      name: input.name ?? 'Publisher',
      ...(input.domain !== undefined && { domain: input.domain }),
      publisherType: input.domain ? 'domain_verified' : 'self_signed',
      verificationMethod: input.domain ? 'dns' : 'self_signed',
      verified: false,
    })
    return {
      type,
      identity: issued.identity,
      publicKeyHex: bytesToHex(issued.publicKey),
      privateKeyHex: bytesToHex(issued.privateKey),
      createdAt: new Date().toISOString(),
    }
  }

  const issued = await createPrincipalIdentity({
    type: 'individual',
    displayName: input.name ?? 'Principal',
    ...(input.domain !== undefined && { domain: input.domain }),
    verificationMethod: input.domain ? 'dns' : 'self_signed',
    verified: false,
  })
  return {
    type,
    identity: issued.identity,
    publicKeyHex: bytesToHex(issued.publicKey),
    privateKeyHex: bytesToHex(issued.privateKey),
    createdAt: new Date().toISOString(),
  }
}

async function getLocalAuthorityIdentity(): Promise<LocalIdentityRecord> {
  const existing = Array.from(localIdentities.values()).find(record => (
    record.type === 'agent' &&
    (record.identity as AgentIdentity).metadata?.role === 'agentd_local_authority'
  ))
  if (existing) return existing

  const authority = await createLocalIdentity('agent', { name: 'agentd Local Authority' })
  authority.identity = {
    ...(authority.identity as AgentIdentity),
    metadata: {
      ...((authority.identity as AgentIdentity).metadata ?? {}),
      role: 'agentd_local_authority',
    },
  }
  localIdentities.set(authority.identity.did, authority)
  return authority
}

function safeIdentitySummary(record: LocalIdentityRecord): Record<string, unknown> {
  return {
    type: record.type,
    did: record.identity.did,
    publicKeyHex: record.publicKeyHex,
    createdAt: record.createdAt,
  }
}

function safeIdentityRecord(record: LocalIdentityRecord): Record<string, unknown> {
  return {
    ...safeIdentitySummary(record),
    identity: record.identity,
  }
}

function safeRegisteredAgent(record: LocalRegisteredAgent): Record<string, unknown> {
  const card = localAgentCards.get(record.cardId)
  const signed = localSignedAgentCards.has(record.cardId) || record.signed
  return {
    ...record,
    signed,
    verified: signed,
    authority: 'candidate_only',
    capabilities: card?.capabilities.map(capability => capability.id) ?? [],
    authorityGranted: false,
    reasons: [
      signed ? 'identity_bound_signed_agent_card_verified' : 'signed_agent_card_not_verified',
      'local_registration_candidate_only',
      'discovery_does_not_grant_authority',
    ],
  }
}

function sessionAuthorityFor(policy: FidesPolicyDecision): {
  authorityGranted: boolean
  authorityMode: 'full' | 'dry_run_only'
  allowedActions: Array<'execute' | 'dry_run'>
} {
  if (policy.decision === 'allow') {
    return { authorityGranted: true, authorityMode: 'full', allowedActions: ['execute', 'dry_run'] }
  }
  return { authorityGranted: false, authorityMode: 'dry_run_only', allowedActions: ['dry_run'] }
}

function localCapabilityKey(agentId: string, capability: string): string {
  return `${agentId}::${capability}`
}

function findLocalCapability(
  agentId: string,
  capabilityId: string
): { record: LocalRegisteredAgent; card: AgentCard; capability: AgentCard['capabilities'][number] } | undefined {
  const record = localAgents.get(agentId)
  if (!record) return undefined

  const card = localAgentCards.get(record.cardId)
  if (!card) return undefined

  const capability = card.capabilities.find(candidate => candidate.id === capabilityId)
  if (!capability) return undefined

  return { record, card, capability }
}

function computeLocalTrustResult(agentId: string, capabilityId: string): TrustResult | undefined {
  const found = findLocalCapability(agentId, capabilityId)
  if (!found) return undefined

  const signed = localSignedAgentCards.has(found.record.cardId)
  const reputation = localReputationRecords.get(localCapabilityKey(agentId, capabilityId))
  const highRisk = found.capability.riskLevel === 'high' || found.capability.riskLevel === 'critical'

  const trust = computeTrustResult({
    agentId,
    capability: found.capability,
    components: {
      identity: signed ? 1 : 0.65,
      publisher: 0.5,
      trustAnchors: 0.2,
      capabilityFit: 1,
      evidence: reputation ? Math.min(1, reputation.score + 0.2) : 0.3,
      policyCompliance: 0.7,
      runtimeSafety: highRisk ? 0.2 : 0.8,
      peerAttestation: 0.2,
      incidentPenalty: reputation ? Math.min(1, reputation.incident_count * 0.18) : 0,
      noveltyPenalty: reputation ? Math.max(0, 0.4 - reputation.score) : 0.35,
      contextBoundaryPenalty: reputation?.context_boundary_penalty ?? 0,
    },
  })
  localTrustResults.set(localCapabilityKey(agentId, capabilityId), trust)
  return trust
}

function activeLocalKillSwitchFor(input: {
  agentId: string
  capability: string
  principalId: string
  requesterAgentId: string
  riskLevel: string
  sessionId?: string
}): KillSwitchRule | undefined {
  return Array.from(localKillSwitchRules.values()).find((rule) => {
    if (!isKillSwitchRuleActive(rule)) return false
    if (rule.target_type === 'agent') return rule.target === input.agentId
    if (rule.target_type === 'capability') return rule.target === input.capability
    if (rule.target_type === 'principal') return rule.target === input.principalId
    if (rule.target_type === 'session') return rule.target === input.sessionId
    if (rule.target_type === 'risk_class') return rule.target === input.riskLevel
    return false
  })
}

function isActiveLocalRevocation(record: RevocationRecordV2): boolean {
  if (record.status !== 'active') return false
  return !record.expires_at || new Date(record.expires_at).getTime() > Date.now()
}

function activeLocalRevocationFor(input: {
  agentId: string
  capability: string
  principalId: string
  requesterAgentId: string
  sessionId?: string
}): RevocationRecordV2 | undefined {
  return Array.from(localRevocationRecords.values()).find((record) => {
    if (!isActiveLocalRevocation(record)) return false
    if (record.target_type === 'agent') return record.target_id === input.agentId
    if (record.target_type === 'capability') return record.target_id === input.capability
    if (record.target_type === 'identity') return record.target_id === input.agentId || record.target_id === input.principalId || record.target_id === input.requesterAgentId
    if (record.target_type === 'session') return record.target_id === input.sessionId
    return false
  })
}

function activeLocalIncidentFor(agentId: string): IncidentRecordV2 | undefined {
  return Array.from(localIncidentRecords.values()).find((record) => {
    return record.target_agent_id === agentId && record.resolution_status === 'open'
  })
}

function policyErrorEnvelope(policy: FidesPolicyDecision) {
  const code = policy.reason_codes.includes('KILL_SWITCH_ACTIVE')
    ? 'KILL_SWITCH_ACTIVE'
    : policy.reason_codes.includes('REVOCATION_ACTIVE')
      ? 'REVOCATION_ACTIVE'
      : policy.reason_codes.includes('HIGH_RISK_REQUIRES_ATTESTATION_OR_APPROVAL') || policy.reason_codes.includes('CRITICAL_REQUIRES_EXPLICIT_APPROVAL')
        ? 'APPROVAL_REQUIRED'
        : 'POLICY_DENIED'

  return createErrorEnvelope(code, {
    message: policy.human_reasons[0] ?? undefined,
    details: {
      decision: policy.decision,
      reason_codes: policy.reason_codes,
      required_controls: policy.required_controls,
    },
  })
}

function isSignedInvocationRequest(value: unknown): value is SignedInvocationRequest {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<SignedInvocationRequest>
  return Boolean(candidate.payload && typeof candidate.payload === 'object' && candidate.proof && typeof candidate.proof === 'object')
}

async function verifyLocalRuntimeAttestation(attestationId: string | undefined, agentId: string): Promise<boolean | undefined> {
  if (!attestationId) return undefined
  const attestation = localRuntimeAttestations.get(attestationId)
  if (!attestation || attestation.agent_id !== agentId) return false
  return runtimeAttestationProvider.verify(attestation)
}

// Global middleware stack
app.use('*', metricsMiddleware(collector))
app.use('*', logger())
app.use('*', securityHeaders())
app.use('*', cors({
  origin: getCorsOrigin(),
  exposeHeaders: ['X-Request-Id'],
}))
app.use('*', async (c, next) => {
  await ensureLocalStateLoaded()
  await next()
  if (shouldPersistLocalState(c.req.method, new URL(c.req.url).pathname, c.res.status)) {
    await persistLocalState()
  }
})
// Auth on mutating endpoints (skip GET /health)
app.use('/v1/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/dht/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/registry/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/relay/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/evidence', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/evidence/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/demo/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/simulate/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/identities', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/identities/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/agent-cards', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/agent-cards/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/agents', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/agents/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/discover', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/discover/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/trust/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/reputation/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/policy/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/delegations', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/sessions', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/sessions/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/invoke', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/approvals', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/approvals/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/killswitch', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/killswitch/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/revocations', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/revocations/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/incidents', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/incidents/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/attestations', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.use('/attestations/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth(agentdScopeForRequest(c.req.method, new URL(c.req.url).pathname))
  return auth(c, next)
})
app.post('*', rateLimitMiddleware({ maxRequests: process.env.NODE_ENV === 'test' ? 1000 : 100, windowMs: 60_000 }))
app.get('*', rateLimitMiddleware({ maxRequests: 300, windowMs: 60_000 }))
app.use('*', bodyLimit({ maxSize: 1024 * 1024 }))

app.onError(errorHandler)

// Metrics endpoint
app.get('/metrics', (c) => {
  return c.text(collector.toPrometheus(), 200, { 'Content-Type': 'text/plain; version=0.0.4' })
})

// ─── Health ───────────────────────────────────────────────────────
app.get('/health', async (c) => {
  const probe = async (url: string): Promise<{ reachable: boolean }> => {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 2000)
      const resp = await fetch(`${url}/health`, { signal: controller.signal })
      clearTimeout(timeout)
      return { reachable: resp.ok }
    } catch {
      return { reachable: false }
    }
  }

  const [discovery, trustGraph, registry, authority, localState] = await Promise.all([
    probe(DISCOVERY_URL),
    probe(TRUST_GRAPH_URL),
    probe(REGISTRY_URL),
    authorityStore.healthCheck(),
    localStateStore.healthCheck(),
  ])

  const allOk = discovery.reachable && trustGraph.reachable && registry.reachable && authority.ok && localState.ok
  const status = allOk ? 'healthy' : 'degraded'

  return c.json({
    status,
    service: 'agentd',
    uptime: Math.floor((Date.now() - startTime) / 1000),
    timestamp: new Date().toISOString(),
    checks: {
      discovery: discovery.reachable ? 'connected' : 'unreachable',
      trustGraph: trustGraph.reachable ? 'connected' : 'unreachable',
      registry: registry.reachable ? 'connected' : 'unreachable',
      authorityStore: authority.ok ? 'ready' : 'unready',
      localStateStore: localState.ok ? 'ready' : 'unready',
    },
    authorityStore: {
      kind: authority.kind,
      ok: authority.ok,
      detail: authority.detail,
    },
    localStateStore,
  }, allOk ? 200 : 503)
})

// ─── Root FIDES v2 Identity API ──────────────────────────────────
app.post('/identities', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const type = body.type
  if (type !== 'agent' && type !== 'publisher' && type !== 'principal') {
    return c.json(localError('REQUEST_INVALID', 'type must be agent, publisher, or principal', { field: 'type' }), 400)
  }

  const record = await createLocalIdentity(type, {
    name: typeof body.name === 'string' ? body.name : undefined,
    domain: typeof body.domain === 'string' ? body.domain : undefined,
  })
  localIdentities.set(record.identity.did, record)
  return c.json(safeIdentityRecord(record), 201)
})

app.get('/identities', (c) => {
  return c.json({
    identities: Array.from(localIdentities.values()).map(safeIdentitySummary),
  })
})

app.get('/identities/:id', (c) => {
  const id = c.req.param('id')
  const record = localIdentities.get(id)
  if (!record) {
    return c.json(localError('IDENTITY_NOT_FOUND', 'identity not found', { id }), 404)
  }
  return c.json(safeIdentityRecord(record))
})

// ─── Root FIDES v2 AgentCard API ─────────────────────────────────
app.post('/agent-cards', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const did = typeof body.agentId === 'string'
    ? body.agentId
    : typeof body.agent_id === 'string'
      ? body.agent_id
      : typeof body.identity?.did === 'string'
        ? body.identity.did
        : undefined
  if (!did) {
    return c.json(localError('REQUEST_INVALID', 'identity.did or agentId is required', { fields: ['identity.did', 'agentId'] }), 400)
  }

  const localIdentity = localIdentities.get(did)
  if (!localIdentity || localIdentity.type !== 'agent') {
    return c.json(localError('IDENTITY_NOT_FOUND', 'agent identity not found in local daemon', { did }), 404)
  }

  const capabilities = Array.isArray(body.capabilities)
    ? body.capabilities.map((capability: Record<string, unknown>) => createCapabilityDescriptor({
      id: String(capability.id),
      name: typeof capability.name === 'string' ? capability.name : undefined,
      description: typeof capability.description === 'string' ? capability.description : undefined,
      inputSchema: typeof capability.inputSchema === 'object' && capability.inputSchema !== null ? capability.inputSchema as any : undefined,
      outputSchema: typeof capability.outputSchema === 'object' && capability.outputSchema !== null ? capability.outputSchema as any : undefined,
      riskLevel: typeof capability.riskLevel === 'string' ? capability.riskLevel as any : undefined,
      requiredScopes: Array.isArray(capability.requiredScopes) ? capability.requiredScopes.map(String) : undefined,
      supportedControls: Array.isArray(capability.supportedControls) ? capability.supportedControls as any : undefined,
      supportsDryRun: typeof capability.supportsDryRun === 'boolean' ? capability.supportsDryRun : undefined,
      supportsHumanApproval: typeof capability.supportsHumanApproval === 'boolean' ? capability.supportsHumanApproval : undefined,
      supportsPolicyProof: typeof capability.supportsPolicyProof === 'boolean' ? capability.supportsPolicyProof : undefined,
    }))
    : []

  const now = new Date().toISOString()
  const publisherId = typeof body.publisherId === 'string'
    ? body.publisherId
    : typeof body.publisher_id === 'string'
      ? body.publisher_id
      : undefined
  const publisher = publisherId ? localIdentities.get(publisherId) : undefined
  if (publisherId && (!publisher || publisher.type !== 'publisher')) {
    return c.json(localError('IDENTITY_NOT_FOUND', 'publisher identity not found in local daemon', { publisherId }), 404)
  }
  const runtimeAttestationIds: string[] = Array.isArray(body.runtimeAttestationIds)
    ? body.runtimeAttestationIds.map(String)
    : Array.isArray(body.runtime_attestation_ids)
      ? body.runtime_attestation_ids.map(String)
      : []
  const runtimeAttestations = runtimeAttestationIds
    .map((id: string) => localRuntimeAttestations.get(id))
    .filter((attestation: RuntimeAttestation | undefined): attestation is RuntimeAttestation => Boolean(attestation))
  if (runtimeAttestationIds.length !== runtimeAttestations.length) {
    return c.json(localError('ATTESTATION_NOT_FOUND', 'one or more runtime attestations were not found', { runtimeAttestationIds }), 404)
  }

  const card = normalizeAgentCard({
    schema_version: 'fides.agent_card.v1',
    id: did,
    agent_id: did,
    identity: {
      ...(localIdentity.identity as AgentIdentity),
      metadata: {
        ...(localIdentity.identity as AgentIdentity).metadata,
        ...(typeof body.name === 'string' && { name: body.name }),
      },
    },
    ...(publisher?.identity && { publisher: publisher.identity as PublisherIdentity }),
    capabilities,
    endpoints: Array.isArray(body.endpoints) ? body.endpoints : [],
    ...(Array.isArray(body.transports) && { transports: body.transports }),
    policies: Array.isArray(body.policies)
      ? body.policies
      : [{ requiresRuntimeAttestation: false, requiresApproval: false }],
    ...(localIdentity.identity.trustAnchors?.length && { trustAnchors: localIdentity.identity.trustAnchors }),
    ...(runtimeAttestations.length > 0 && { runtimeAttestations }),
    ...(typeof body.revocationUrl === 'string' && { revocationUrl: body.revocationUrl }),
    ...(typeof body.revocationRef === 'string' && { revocationRef: body.revocationRef }),
    protocolVersions: Array.isArray(body.protocolVersions) ? body.protocolVersions.map(String) : ['fides.v2.0'],
    createdAt: now,
    updatedAt: now,
    ...(typeof body.expiresAt === 'string' && { expiresAt: body.expiresAt }),
  })

  const validation = validateAgentCard(card)
  if (!validation.valid) {
    return c.json({ validation, card }, 400)
  }

  localAgentCards.set(card.id, card)
  localSignedAgentCards.delete(card.id)
  return c.json({ card, validation }, 201)
})

app.post('/agent-cards/:id/sign', async (c) => {
  const id = c.req.param('id')
  const card = localAgentCards.get(id)
  if (!card) {
    return c.json(localError('AGENT_CARD_NOT_FOUND', 'AgentCard not found', { id }), 404)
  }
  const identity = localIdentities.get(card.identity.did)
  if (!identity) {
    return c.json(localError('IDENTITY_NOT_FOUND', 'AgentCard identity key not found', { did: card.identity.did }), 404)
  }

  const signed = await signAgentCard(card, Buffer.from(identity.privateKeyHex, 'hex'), card.identity.did)
  localSignedAgentCards.set(card.id, signed)
  return c.json({ signed })
})

app.post('/agent-cards/:id/verify', async (c) => {
  const id = c.req.param('id')
  const signed = localSignedAgentCards.get(id)
  if (signed) {
    const canonicalValid = await verifySignedAgentCard(signed)
    const identityBound = await verifySignedAgentCardIdentity(signed)
    return c.json({
      valid: identityBound,
      signed: true,
      canonicalValid,
      identityBound,
    })
  }

  const card = localAgentCards.get(id)
  if (!card) {
    return c.json({
      valid: false,
      ...localError('AGENT_CARD_NOT_FOUND', 'AgentCard not found', { id }),
    }, 404)
  }
  const validation = validateAgentCard(card)
  return c.json({ valid: validation.valid, signed: false, validation })
})

app.get('/agent-cards/:id', (c) => {
  const id = c.req.param('id')
  const card = localAgentCards.get(id)
  if (!card) {
    return c.json(localError('AGENT_CARD_NOT_FOUND', 'AgentCard not found', { id }), 404)
  }
  return c.json({
    card,
    signed: localSignedAgentCards.get(id) ?? null,
  })
})

// ─── Root FIDES v2 Agent Registration and Discovery API ──────────
app.post('/agents/register', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const cardId = typeof body.agentCardId === 'string'
    ? body.agentCardId
    : typeof body.cardId === 'string'
      ? body.cardId
      : typeof body.id === 'string'
        ? body.id
        : typeof body.agent_id === 'string'
          ? body.agent_id
          : undefined
  if (!cardId) {
    return c.json(localError('REQUEST_INVALID', 'agentCardId is required', { field: 'agentCardId' }), 400)
  }

  const card = localAgentCards.get(cardId)
  if (!card) {
    return c.json(localError('AGENT_CARD_NOT_FOUND', 'AgentCard not found', { cardId }), 404)
  }
  const signedCard = localSignedAgentCards.get(card.id)
  if (!signedCard) {
    return c.json(localError('AGENT_CARD_INVALID_SIGNATURE', 'Identity-bound signed AgentCard is required before registration', { cardId }), 400)
  }
  if (!await verifySignedAgentCardIdentity(signedCard)) {
    return c.json(localError('IDENTITY_KEY_UNBOUND', 'Signed AgentCard is not bound to the advertised agent identity', { cardId }), 400)
  }

  const record: LocalRegisteredAgent = {
    agentId: card.identity.did,
    cardId: card.id,
    registeredAt: new Date().toISOString(),
    signed: true,
  }
  localAgents.set(record.agentId, record)

  return c.json({
    registered: true,
    ...safeRegisteredAgent(record),
    reason: 'registration records a candidate only; it does not grant invocation authority',
  }, 201)
})

app.get('/agents', (c) => {
  return c.json({
    agents: Array.from(localAgents.values()).map(safeRegisteredAgent),
    authorityGranted: false,
  })
})

app.get('/agents/:id', (c) => {
  const id = c.req.param('id')
  const record = localAgents.get(id)
  if (!record) {
    return c.json(localError('AGENT_NOT_REGISTERED', 'agent not registered', { id }), 404)
  }

  return c.json({
    ...safeRegisteredAgent(record),
    card: localAgentCards.get(record.cardId) ?? null,
    signedCard: localSignedAgentCards.get(record.cardId) ?? null,
  })
})

function stringArray(value: unknown): string[] | undefined {
  return Array.isArray(value) ? value.map(String) : undefined
}

function discoveryVersionNegotiation(
  body: Record<string, unknown>,
  card: AgentCard
): VersionNegotiationRecord {
  return negotiateProtocolVersion({
    localSupported: stringArray(body.supported_versions ?? body.supportedVersions),
    localRequired: stringArray(body.required_versions ?? body.requiredVersions),
    peerSupported: card.protocolVersions?.length ? card.protocolVersions : ['fides.v2.0'],
    peerRequired: stringArray((card as unknown as Record<string, unknown>).required_versions),
  })
}

function localCardForProviderRecord(record: Record<string, unknown>): AgentCard | undefined {
  const cardId = typeof record.cardId === 'string'
    ? record.cardId
    : typeof record.card_id === 'string'
      ? record.card_id
      : undefined
  if (cardId) {
    const card = localAgentCards.get(cardId)
    if (card) return card
  }

  const agentId = typeof record.agentId === 'string'
    ? record.agentId
    : typeof record.agent_id === 'string'
      ? record.agent_id
      : undefined
  const registered = agentId ? localAgents.get(agentId) : undefined
  return registered ? localAgentCards.get(registered.cardId) : undefined
}

function filterVersionCompatibleProviderRecords(
  body: Record<string, unknown>,
  records: Array<Record<string, unknown>>,
  rejectedKey = 'rejectedRecords'
): { records: Array<Record<string, unknown>>; rejected: Array<Record<string, unknown>>; rejectedKey: string } {
  const rejected: Array<Record<string, unknown>> = []
  const compatible: Array<Record<string, unknown>> = []
  for (const record of records) {
    const card = localCardForProviderRecord(record)
    if (!card) {
      rejected.push({
        ...record,
        authorityGranted: false,
        protocolCompatibility: 'card_unresolved',
        reasons: [
          'provider_record_card_unresolved',
          'discovery_does_not_grant_authority',
        ],
      })
      continue
    }

    const versionNegotiation = discoveryVersionNegotiation(body, card)
    if (!versionNegotiation.compatible) {
      rejected.push({
        ...record,
        authorityGranted: false,
        versionNegotiation,
        reasons: [
          'provider_record_matched_capability',
          'protocol_version_incompatible',
          'discovery_does_not_grant_authority',
        ],
      })
      continue
    }

    compatible.push({
      ...record,
      versionNegotiation,
      reasons: [
        'provider_record_matched_capability',
        'protocol_version_compatible',
        'discovery_does_not_grant_authority',
      ],
    })
  }

  return { records: compatible, rejected, rejectedKey }
}

function dhtPointerRecordOnly(pointer: Record<string, unknown>): DHTPointerRecord {
  return {
    schema_version: 'fides.dht.pointer.v1',
    record_type: 'capability_pointer',
    capability: String(pointer.capability),
    capability_hash: String(pointer.capability_hash),
    agent_id: String(pointer.agent_id),
    agent_card_url: String(pointer.agent_card_url),
    agent_card_hash: String(pointer.agent_card_hash),
    publisher_id: String(pointer.publisher_id),
    expires_at: String(pointer.expires_at),
    sequence: typeof pointer.sequence === 'number' ? pointer.sequence : Number(pointer.sequence ?? 1),
    signature: String(pointer.signature ?? ''),
  }
}

async function localDiscoveryResult(body: Record<string, unknown>, provider = 'local') {
  const capability = typeof body.capability === 'string' ? body.capability : undefined
  if (!capability) {
    return { error: localError('REQUEST_INVALID', 'capability is required', { field: 'capability' }) }
  }

  const rejectedCandidates: Array<Record<string, unknown>> = []
  const candidateSets = await Promise.all(Array.from(localAgents.values()).map(async (record) => {
    const card = localAgentCards.get(record.cardId)
    if (!card) return []

    const descriptor = card.capabilities.find(candidate => candidate.id === capability)
    if (!descriptor) return []

    const signedCard = localSignedAgentCards.get(record.cardId)
    if (!signedCard || !await verifySignedAgentCardIdentity(signedCard)) {
      rejectedCandidates.push({
        agentId: record.agentId,
        cardId: record.cardId,
        capability,
        authorityGranted: false,
        reasons: [
          'candidate_matched_capability',
          'agent_card_identity_bound_signature_required',
          'discovery_does_not_grant_authority',
        ],
      })
      return []
    }

    const versionNegotiation = discoveryVersionNegotiation(body, card)
    if (!versionNegotiation.compatible) {
      rejectedCandidates.push({
        agentId: record.agentId,
        cardId: record.cardId,
        capability,
        authorityGranted: false,
        versionNegotiation,
        reasons: [
          'candidate_matched_capability',
          'protocol_version_incompatible',
          'discovery_does_not_grant_authority',
        ],
      })
      return []
    }

    return [{
      agentId: record.agentId,
      cardId: record.cardId,
      capability,
      signed: true,
      authorityGranted: false,
      versionNegotiation,
      resolution: {
        mode: provider === 'well-known' ? 'local_well_known_agent_card' : 'local_agent_card',
        provider,
        urlRequired: false,
        authorityGranted: false,
        hint: 'Local discovery resolves from daemon-held AgentCards; endpoint URLs are optional transport metadata.',
      },
      descriptor,
      card,
      reasons: [
        'candidate_matched_capability',
        'protocol_version_compatible',
        'discovery_does_not_grant_authority',
        'url_not_required_for_local_discovery',
      ],
    }]
  }))
  const candidates = candidateSets.flat()

  return {
    query: body,
    provider,
    candidates,
    rejectedCandidates,
    count: candidates.length,
    authorityGranted: false,
    explanation: 'Discovery returns candidates only. Policy evaluation and scoped session grants are required before invocation.',
  }
}

function appendDiscoveryEvidence<T extends Record<string, unknown>>(
  provider: string,
  body: Record<string, unknown>,
  result: T
): T & { evidenceRefs: string[]; evidence_refs: string[] } {
  const capability = typeof body.capability === 'string' ? body.capability : undefined
  const candidates = Array.isArray(result.candidates) ? result.candidates.length : 0
  const records = Array.isArray(result.records) ? result.records.length : 0
  const pointers = Array.isArray(result.pointers) ? result.pointers.length : 0
  const rejectedCandidates = Array.isArray(result.rejectedCandidates) ? result.rejectedCandidates.length : 0
  const rejectedRecords = Array.isArray(result.rejectedRecords) ? result.rejectedRecords.length : 0
  const rejectedPointers = Array.isArray(result.rejectedPointers) ? result.rejectedPointers.length : 0
  const event = appendRootEvidence({
    type: 'discovery.performed',
    actor: 'did:fides:agentd:local-daemon',
    subject: `fides.discovery.${provider}`,
    capability,
    input: {
      provider,
      capability,
      constraints: body.constraints,
      supported_versions: body.supported_versions ?? body.supportedVersions,
      required_versions: body.required_versions ?? body.requiredVersions,
    },
    output: {
      candidates,
      records,
      pointers,
      rejectedCandidates,
      rejectedRecords,
      rejectedPointers,
      authorityGranted: false,
    },
    decision: 'candidate_only',
    privacy_mode: 'hash_only',
    metadata: {
      provider,
      capability,
      candidates,
      records,
      pointers,
      rejectedCandidates,
      rejectedRecords,
      rejectedPointers,
      authorityGranted: false,
    },
  })
  return {
    ...result,
    evidenceRefs: [event.event_id],
    evidence_refs: [event.event_id],
  }
}

app.post('/discover', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const result = await localDiscoveryResult(body)
  if ('error' in result) return c.json(result.error, 400)
  return c.json(appendDiscoveryEvidence('local', body, result))
})

app.post('/discover/local', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const result = await localDiscoveryResult(body, 'local')
  if ('error' in result) return c.json(result.error, 400)
  return c.json(appendDiscoveryEvidence('local', body, result))
})

app.post('/discover/well-known', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const result = await localDiscoveryResult(body, 'well-known')
  if ('error' in result) return c.json(result.error, 400)
  return c.json(appendDiscoveryEvidence('well-known', body, result))
})

app.post('/trust/evaluate', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const agentId = typeof body.agentId === 'string'
    ? body.agentId
    : typeof body.agent_id === 'string'
      ? body.agent_id
      : typeof body.targetAgentId === 'string'
        ? body.targetAgentId
        : undefined
  const capability = typeof body.capability === 'string'
    ? body.capability
    : typeof body.capabilityId === 'string'
      ? body.capabilityId
      : undefined

  if (!agentId || !capability) {
    return c.json(localError('REQUEST_INVALID', 'agentId and capability are required', { fields: ['agentId', 'capability'] }), 400)
  }

  const trust = computeLocalTrustResult(agentId, capability)
  if (!trust) {
    return c.json(localError('CAPABILITY_NOT_FOUND', 'registered agent capability not found', { agentId, capability }), 404)
  }

  return c.json({
    trust,
    authorityGranted: false,
    explanation: 'Trust is a signal only. Policy evaluation and scoped session grants are required before invocation.',
  })
})

app.get('/trust/:agentId', (c) => {
  const agentId = c.req.param('agentId')
  const trust = Array.from(localTrustResults.values()).filter(record => record.agent_id === agentId)
  return c.json({ agentId, trust, authorityGranted: false })
})

app.post('/reputation/update', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const agentId = typeof body.agentId === 'string'
    ? body.agentId
    : typeof body.agent_id === 'string'
      ? body.agent_id
      : undefined
  const capability = typeof body.capability === 'string'
    ? body.capability
    : typeof body.capabilityId === 'string'
      ? body.capabilityId
      : undefined

  if (!agentId || !capability) {
    return c.json(localError('REQUEST_INVALID', 'agentId and capability are required', { fields: ['agentId', 'capability'] }), 400)
  }

  const found = findLocalCapability(agentId, capability)
  if (!found) {
    return c.json(localError('CAPABILITY_NOT_FOUND', 'registered agent capability not found', { agentId, capability }), 404)
  }

  const reputation = computeCapabilityReputation({
    agentId,
    publisherId: typeof body.publisherId === 'string' ? body.publisherId : undefined,
    principalId: typeof body.principalId === 'string' ? body.principalId : undefined,
    capability,
    successfulInvocations: typeof body.successfulInvocations === 'number' ? body.successfulInvocations : undefined,
    failedInvocations: typeof body.failedInvocations === 'number' ? body.failedInvocations : undefined,
    incidentCount: typeof body.incidentCount === 'number' ? body.incidentCount : undefined,
    publisherWeight: typeof body.publisherWeight === 'number' ? body.publisherWeight : undefined,
    contextBoundaryMismatch: typeof body.contextBoundaryMismatch === 'boolean' ? body.contextBoundaryMismatch : undefined,
  })
  localReputationRecords.set(localCapabilityKey(agentId, capability), reputation)

  return c.json({ reputation, authorityGranted: false })
})

app.get('/reputation/:agentId', (c) => {
  const agentId = c.req.param('agentId')
  const reputations = Array.from(localReputationRecords.values()).filter(record => record.agent_id === agentId)
  return c.json({ agentId, reputations, authorityGranted: false })
})

app.post('/policy/evaluate', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const targetAgentId = typeof body.targetAgentId === 'string'
    ? body.targetAgentId
    : typeof body.agentId === 'string'
      ? body.agentId
      : typeof body.agent_id === 'string'
        ? body.agent_id
        : undefined
  const capabilityId = typeof body.capability === 'string'
    ? body.capability
    : typeof body.capabilityId === 'string'
      ? body.capabilityId
      : undefined

  if (!targetAgentId || !capabilityId) {
    return c.json(localError('REQUEST_INVALID', 'agentId and capability are required', { fields: ['agentId', 'capability'] }), 400)
  }

  const found = findLocalCapability(targetAgentId, capabilityId)
  if (!found) {
    return c.json(localError('CAPABILITY_NOT_FOUND', 'registered agent capability not found', { agentId: targetAgentId, capability: capabilityId }), 404)
  }

  const trustResult = computeLocalTrustResult(targetAgentId, capabilityId)
  if (!trustResult) {
    return c.json(localError('TRUST_BELOW_THRESHOLD', 'trust result unavailable', { agentId: targetAgentId, capability: capabilityId }), 404)
  }

  const policy = evaluateFidesPolicy({
    principalId: typeof body.principalId === 'string' ? body.principalId : 'did:fides:principal:local',
    requesterAgentId: typeof body.requesterAgentId === 'string' ? body.requesterAgentId : 'did:fides:requester:local',
    targetAgentId,
    capability: found.capability,
    trustResult,
    requestedScopes: Array.isArray(body.requestedScopes) ? body.requestedScopes.map(String) : [],
    runtimeAttestationValid: typeof body.runtimeAttestationValid === 'boolean' ? body.runtimeAttestationValid : undefined,
    revocationActive: typeof body.revocationActive === 'boolean' ? body.revocationActive : undefined,
    killSwitchActive: typeof body.killSwitchActive === 'boolean' ? body.killSwitchActive : undefined,
    incidentsActive: typeof body.incidentsActive === 'boolean' ? body.incidentsActive : undefined,
    approvalGranted: typeof body.approvalGranted === 'boolean' ? body.approvalGranted : undefined,
    evidenceRefs: Array.isArray(body.evidenceRefs) ? body.evidenceRefs.map(String) : undefined,
  })

  return c.json({
    policy,
    trust: trustResult,
    authorityGranted: false,
    requiresSessionGrant: policy.decision === 'allow',
    explanation: 'Policy decisions do not execute capabilities. Allowed decisions require a scoped SessionGrant before invocation.',
  })
})

app.post('/delegations', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const delegator = typeof body.delegator === 'string'
    ? body.delegator
    : typeof body.principalId === 'string'
      ? body.principalId
      : undefined
  const delegatee = typeof body.delegatee === 'string'
    ? body.delegatee
    : typeof body.requesterAgentId === 'string'
      ? body.requesterAgentId
      : typeof body.agentId === 'string'
        ? body.agentId
        : undefined
  const capabilities = Array.isArray(body.capabilities)
    ? body.capabilities.map(String)
    : typeof body.capability === 'string'
      ? [body.capability]
      : []

  if (!delegator || !delegatee || capabilities.length === 0) {
    return c.json(localError('REQUEST_INVALID', 'delegator, delegatee, and capabilities are required', { fields: ['delegator', 'delegatee', 'capabilities'] }), 400)
  }

  const expiresAt = typeof body.expiresAt === 'string'
    ? body.expiresAt
    : new Date(Date.now() + 60 * 60 * 1000).toISOString()
  const token = createDelegationToken({
    delegator,
    delegatee,
    capabilities,
    constraints: typeof body.constraints === 'object' && body.constraints !== null
      ? body.constraints as DelegationConstraint
      : {},
    expiresAt,
    audience: Array.isArray(body.audience) ? body.audience.map(String) : undefined,
  })
  const delegatorIdentity = localIdentities.get(delegator)
  const signedToken = delegatorIdentity
    ? await signDelegationToken(token, Buffer.from(delegatorIdentity.privateKeyHex, 'hex'))
    : token
  localDelegationTokens.set(signedToken.id, signedToken)

  return c.json({
    token: signedToken,
    signed: Boolean(delegatorIdentity),
    authorityGranted: false,
    explanation: delegatorIdentity
      ? 'Delegation records signed scoped authorization intent. It must still be converted into a policy-checked SessionGrant before invocation.'
      : 'Delegation records scoped authorization intent. It must be signed and converted into a policy-checked SessionGrant before invocation.',
  }, 201)
})

app.post('/sessions', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const targetAgentId = typeof body.targetAgentId === 'string'
    ? body.targetAgentId
    : typeof body.agentId === 'string'
      ? body.agentId
      : typeof body.agent_id === 'string'
        ? body.agent_id
        : undefined
  const capabilityId = typeof body.capability === 'string'
    ? body.capability
    : typeof body.capabilityId === 'string'
      ? body.capabilityId
      : undefined

  if (!targetAgentId || !capabilityId) {
    return c.json({ error: createErrorEnvelope('CAPABILITY_NOT_FOUND', {
      message: 'agentId and capability are required',
      details: { agentId: targetAgentId, capability: capabilityId },
    }) }, 400)
  }

  const found = findLocalCapability(targetAgentId, capabilityId)
  if (!found) {
    return c.json({ error: createErrorEnvelope('CAPABILITY_NOT_FOUND', {
      message: 'Registered agent capability was not found',
      details: { agentId: targetAgentId, capability: capabilityId },
    }), agentId: targetAgentId, capability: capabilityId }, 404)
  }

  const trust = computeLocalTrustResult(targetAgentId, capabilityId)
  if (!trust) {
    return c.json({ error: createErrorEnvelope('TRUST_BELOW_THRESHOLD', {
      message: 'Trust result is unavailable',
      details: { agentId: targetAgentId, capability: capabilityId },
    }), agentId: targetAgentId, capability: capabilityId }, 404)
  }

  const requestedScopes = Array.isArray(body.requestedScopes) ? body.requestedScopes.map(String) : []
  const principalId = typeof body.principalId === 'string' ? body.principalId : 'did:fides:principal:local'
  const requesterAgentId = typeof body.requesterAgentId === 'string' ? body.requesterAgentId : 'did:fides:requester:local'
  const activeKillSwitch = activeLocalKillSwitchFor({
    agentId: targetAgentId,
    capability: capabilityId,
    principalId,
    requesterAgentId,
    riskLevel: found.capability.riskLevel,
  })
  const activeRevocation = activeLocalRevocationFor({
    agentId: targetAgentId,
    capability: capabilityId,
    principalId,
    requesterAgentId,
  })
  const activeIncident = activeLocalIncidentFor(targetAgentId)
  const runtimeAttestationValid = typeof body.runtimeAttestationValid === 'boolean'
    ? body.runtimeAttestationValid
    : await verifyLocalRuntimeAttestation(typeof body.attestationId === 'string' ? body.attestationId : undefined, targetAgentId)
  const policy = evaluateFidesPolicy({
    principalId,
    requesterAgentId,
    targetAgentId,
    capability: found.capability,
    trustResult: trust,
    requestedScopes,
    killSwitchActive: activeKillSwitch !== undefined,
    revocationActive: activeRevocation !== undefined,
    incidentsActive: activeIncident !== undefined,
    runtimeAttestationValid,
    approvalGranted: typeof body.approvalGranted === 'boolean' ? body.approvalGranted : undefined,
  })

  if (policy.decision !== 'allow' && policy.decision !== 'dry_run_only') {
    const deniedEvidence = appendRootEvidence({
      type: 'session.denied',
      actor: requesterAgentId,
      subject: targetAgentId,
      principal: principalId,
      capability: capabilityId,
      policy: policy,
      decision: policy.decision,
      risk_level: found.capability.riskLevel,
      privacy_mode: 'hash_only',
      metadata: {
        reason_codes: policy.reason_codes,
        kill_switch: activeKillSwitch?.id,
        revocation: activeRevocation?.id,
        incident: activeIncident?.id,
      },
    })
    return c.json({
      authorized: false,
      authorityGranted: false,
      error: policyErrorEnvelope(policy),
      policy,
      trust,
      killSwitch: activeKillSwitch,
      revocation: activeRevocation,
      incident: activeIncident,
      evidenceRefs: [deniedEvidence.event_id],
    }, 409)
  }

  const expiresAt = typeof body.expiresAt === 'string'
    ? body.expiresAt
    : new Date(Date.now() + 60 * 60 * 1000).toISOString()
  const authority = await getLocalAuthorityIdentity()
  const sessionAuthority = sessionAuthorityFor(policy)
  const requestedConstraints = typeof body.constraints === 'object' && body.constraints !== null ? body.constraints as Record<string, unknown> : {}
  const sessionConstraints = policy.decision === 'dry_run_only'
    ? { ...requestedConstraints, dryRunOnly: true }
    : requestedConstraints
  const sessionVersionNegotiation = negotiateProtocolVersion({
    localSupported: stringArray(body.supported_versions ?? body.supportedVersions),
    localRequired: stringArray(body.required_versions ?? body.requiredVersions),
    peerSupported: found.card.protocolVersions?.length ? found.card.protocolVersions : ['fides.v2.0'],
    peerRequired: stringArray((found.card as unknown as Record<string, unknown>).required_versions),
  })
  if (!sessionVersionNegotiation.compatible || !sessionVersionNegotiation.negotiated_version) {
    return c.json({
      authorized: false,
      authorityGranted: false,
      error: createErrorEnvelope('VERSION_INCOMPATIBLE', {
        message: 'SessionGrant cannot be issued for incompatible protocol versions',
        details: { versionNegotiation: sessionVersionNegotiation },
      }),
      versionNegotiation: sessionVersionNegotiation,
    }, 409)
  }
  const session = createSessionGrantV2({
    requesterAgentId,
    targetAgentId,
    principalId,
    capability: capabilityId,
    scopes: requestedScopes,
    constraints: sessionConstraints,
    policyHash: hashProtocolPayload(policy),
    trustResultHash: hashProtocolPayload(trust),
    audience: Array.isArray(body.audience) ? body.audience.map(String) : [targetAgentId],
    supportedVersions: sessionVersionNegotiation.supported_versions,
    requiredVersions: sessionVersionNegotiation.required_versions,
    negotiatedVersion: sessionVersionNegotiation.negotiated_version,
    issuer: authority.identity.did,
    expiresAt,
  })
  const signedSession = await signSessionGrantV2(session, Buffer.from(authority.privateKeyHex, 'hex'), authority.identity.did)
  localSessionGrants.set(session.session_id, { session, signedSession, policy, trust })
  const sessionEvidence = appendRootEvidence({
    type: 'session.granted',
    actor: requesterAgentId,
    subject: targetAgentId,
    principal: principalId,
    capability: capabilityId,
    policy: policy,
    decision: policy.decision,
    risk_level: found.capability.riskLevel,
    privacy_mode: 'hash_only',
    metadata: {
      session_id: session.session_id,
      authority_granted: sessionAuthority.authorityGranted,
      authority_mode: sessionAuthority.authorityMode,
      allowed_actions: sessionAuthority.allowedActions,
      negotiated_version: session.negotiated_version,
    },
  })

  return c.json({
    authorized: true,
    ...sessionAuthority,
    session,
    signedSession,
    signedSessionVerified: await verifySignedSessionGrantV2Issuer(signedSession),
    versionNegotiation: sessionVersionNegotiation,
    policy,
    trust,
    evidenceRefs: [sessionEvidence.event_id],
  }, 201)
})

app.get('/sessions/:id', async (c) => {
  const record = localSessionGrants.get(c.req.param('id'))
  if (!record) {
    return c.json({ error: createErrorEnvelope('SESSION_NOT_FOUND', {
      message: 'Session was not found or is no longer available',
      details: { sessionId: c.req.param('id') },
    }) }, 404)
  }
  return c.json({
    session: record.session,
    signedSession: record.signedSession,
    signedSessionVerified: await verifySignedSessionGrantV2Issuer(record.signedSession),
    policy: record.policy,
    trust: record.trust,
  })
})

app.post('/sessions/:id/verify', async (c) => {
  const record = localSessionGrants.get(c.req.param('id'))
  if (!record) {
    return c.json({
      valid: false,
      error: createErrorEnvelope('SESSION_NOT_FOUND', {
        message: 'Session was not found or is no longer available',
        details: { sessionId: c.req.param('id') },
      }),
    }, 404)
  }

  const signatureValid = await verifySignedSessionGrantV2Issuer(record.signedSession)
  const notExpired = new Date(record.session.expires_at).getTime() > Date.now()
  return c.json({
    valid: signatureValid && notExpired,
    signatureValid,
    notExpired,
    session: record.session,
    signedSession: record.signedSession,
  })
})

app.post('/invoke', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const sessionId = typeof body.sessionId === 'string'
    ? body.sessionId
    : typeof body.session_id === 'string'
      ? body.session_id
      : undefined
  if (!sessionId) {
    return c.json({ error: createErrorEnvelope('SESSION_SCOPE_INVALID', {
      message: 'sessionId is required',
    }) }, 400)
  }

  const record = localSessionGrants.get(sessionId)
  if (!record) {
    return c.json({ error: createErrorEnvelope('SESSION_NOT_FOUND', {
      message: 'Session was not found or is no longer available',
      details: { sessionId },
    }), sessionId }, 404)
  }

  const signedSessionVerified = await verifySignedSessionGrantV2Issuer(record.signedSession)
  if (!signedSessionVerified) {
    return c.json({ error: createErrorEnvelope('IDENTITY_INVALID_SIGNATURE', {
      message: 'SessionGrant signature is invalid or not bound to its issuer',
      details: { sessionId },
    }), sessionId, authorityGranted: false }, 401)
  }

  if (new Date(record.session.expires_at).getTime() <= Date.now()) {
    return c.json({ error: createErrorEnvelope('SESSION_EXPIRED', {
      details: { sessionId, expires_at: record.session.expires_at },
    }), sessionId, authorityGranted: false }, 409)
  }

  const found = findLocalCapability(record.session.target_agent_id, record.session.capability)
  if (!found) {
    return c.json({ error: createErrorEnvelope('CAPABILITY_NOT_FOUND', {
      message: 'Registered agent capability was not found',
      details: {
        sessionId,
        agentId: record.session.target_agent_id,
        capability: record.session.capability,
      },
    }), sessionId, authorityGranted: false }, 404)
  }

  const inputValidation = validateJsonSchemaValue(found.capability.inputSchema, body.input ?? {})
  if (!inputValidation.valid) {
    return c.json({ error: createErrorEnvelope('CAPABILITY_SCHEMA_INVALID', {
      message: 'Invocation input does not satisfy the capability input schema',
      details: {
        sessionId,
        capability: record.session.capability,
        errors: inputValidation.errors,
      },
    }), authorityGranted: false }, 400)
  }

  const effectiveDryRun = typeof body.dryRun === 'boolean'
    ? body.dryRun
    : record.session.constraints?.dryRunOnly === true

  let request = createInvocationRequest({
    issuer: record.session.requester_agent_id,
    sessionGrant: record.session,
    input: body.input ?? {},
    dryRun: effectiveDryRun,
    inputSchema: found.capability.inputSchema,
    outputSchema: found.capability.outputSchema,
  })
  let signedRequest: SignedInvocationRequest | undefined
  let signedRequestVerified = false
  if (body.signedRequest !== undefined) {
    if (!isSignedInvocationRequest(body.signedRequest)) {
      return c.json({ error: createErrorEnvelope('IDENTITY_INVALID_SIGNATURE', {
        message: 'signedRequest must be a canonical signed InvocationRequest',
      }), authorityGranted: false }, 400)
    }

    const candidateSignedRequest = body.signedRequest
    signedRequest = candidateSignedRequest
    signedRequestVerified = await verifySignedInvocationRequestIssuer(candidateSignedRequest)
    const signedPayload = candidateSignedRequest.payload
    const expectedInputHash = hashProtocolPayload(body.input ?? {})
    const grantValidation = validateInvocationRequestAgainstSessionGrant({
      request: signedPayload,
      sessionGrant: record.session,
    })
    const payloadMatchesInput = signedPayload.input_hash === expectedInputHash &&
      signedPayload.dry_run === effectiveDryRun

    if (!signedRequestVerified || !grantValidation.valid || !payloadMatchesInput) {
      return c.json({ error: createErrorEnvelope('IDENTITY_INVALID_SIGNATURE', {
        message: 'Signed invocation request failed verification or does not match the session and input',
        details: {
          signedRequestVerified,
          grantValidation,
          payloadMatchesInput,
          sessionId,
          request_id: signedPayload.id,
        },
      }), authorityGranted: false }, 401)
    }

    request = signedPayload
  }
  const preflight = evaluateInvocationPreflight({
    request,
    policyDecision: record.policy,
  })
  const output = preflight.can_execute ? { ok: true, capability: record.session.capability } : undefined
  const outputValidation = output === undefined
    ? { valid: true, errors: [] }
    : validateJsonSchemaValue(found.capability.outputSchema, output)
  if (!outputValidation.valid) {
    const failedEvidence = appendRootEvidence({
      type: 'capability.failed',
      actor: record.session.target_agent_id,
      subject: record.session.requester_agent_id,
      principal: record.session.principal_id,
      capability: record.session.capability,
      policy_hash: record.session.policy_hash,
      decision: 'failed',
      privacy_mode: 'hash_only',
      metadata: {
        session_id: record.session.session_id,
        invocation_request_id: request.id,
        schema_errors: outputValidation.errors,
      },
    })
    const failedResult = createInvocationResult({
      issuer: record.session.target_agent_id,
      invocationRequestId: request.id,
      status: 'failed',
      errorCode: 'CAPABILITY_SCHEMA_INVALID',
      evidenceRefs: [failedEvidence.event_id],
    })
    const targetIdentity = localIdentities.get(record.session.target_agent_id)
    const signedFailedResult = targetIdentity
      ? await signInvocationResult(failedResult, Buffer.from(targetIdentity.privateKeyHex, 'hex'), record.session.target_agent_id)
      : undefined

    return c.json({
      authorityGranted: false,
      session: record.session,
      request,
      signedRequest,
      signedRequestVerified,
      preflight: {
        ...preflight,
        status: 'failed',
        can_execute: false,
        reason_codes: [...preflight.reason_codes, 'CAPABILITY_SCHEMA_INVALID'],
      },
      result: failedResult,
      signedResult: signedFailedResult,
      signedResultVerified: signedFailedResult ? await verifySignedInvocationResult(signedFailedResult) : false,
      error: createErrorEnvelope('CAPABILITY_SCHEMA_INVALID', {
        message: 'Invocation output does not satisfy the capability output schema',
        details: {
          sessionId,
          capability: record.session.capability,
          errors: outputValidation.errors,
        },
      }),
    }, 422)
  }
  const invokedEvidence = appendRootEvidence({
    type: 'capability.invoked',
    actor: record.session.requester_agent_id,
    subject: record.session.target_agent_id,
    principal: record.session.principal_id,
    capability: record.session.capability,
    input: body.input ?? {},
    policy_hash: record.session.policy_hash,
    decision: record.policy.decision,
    privacy_mode: 'hash_only',
    metadata: {
      session_id: record.session.session_id,
      invocation_request_id: request.id,
      dry_run: request.dry_run,
    },
  })
  const status = preflight.can_execute ? 'completed' : preflight.status
  const completedEvidence = appendRootEvidence({
    type: preflight.can_execute ? 'capability.completed' : 'capability.failed',
    actor: record.session.target_agent_id,
    subject: record.session.requester_agent_id,
    principal: record.session.principal_id,
    capability: record.session.capability,
    output,
    policy_hash: record.session.policy_hash,
    decision: status,
    privacy_mode: 'hash_only',
    metadata: {
      session_id: record.session.session_id,
      invocation_request_id: request.id,
      preflight_status: preflight.status,
      can_execute: preflight.can_execute,
    },
  })
  const result = createInvocationResult({
    issuer: record.session.target_agent_id,
    invocationRequestId: request.id,
    status,
    output,
    errorCode: preflight.can_execute ? undefined : preflight.reason_codes[0],
    evidenceRefs: [invokedEvidence.event_id, completedEvidence.event_id],
  })
  const targetIdentity = localIdentities.get(record.session.target_agent_id)
  const signedResult = targetIdentity
    ? await signInvocationResult(result, Buffer.from(targetIdentity.privateKeyHex, 'hex'), record.session.target_agent_id)
    : undefined
  const signedResultVerified = signedResult ? await verifySignedInvocationResult(signedResult) : false

  return c.json({
    authorityGranted: preflight.can_execute,
    session: record.session,
    signedSession: record.signedSession,
    signedSessionVerified,
    request,
    signedRequest,
    signedRequestVerified,
    preflight,
    result,
    signedResult,
    signedResultVerified,
  })
})

app.post('/approvals', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const requesterAgentId = typeof body.requesterAgentId === 'string' ? body.requesterAgentId : 'did:fides:requester:local'
  const targetAgentId = typeof body.targetAgentId === 'string'
    ? body.targetAgentId
    : typeof body.agentId === 'string'
      ? body.agentId
      : 'did:fides:agent:local'
  const principalId = typeof body.principalId === 'string' ? body.principalId : 'did:fides:principal:local'
  const capability = typeof body.capability === 'string'
    ? body.capability
    : typeof body.capabilityId === 'string'
      ? body.capabilityId
      : undefined
  if (!capability) {
    return c.json(localError('REQUEST_INVALID', 'capability is required', { field: 'capability' }), 400)
  }

  const approval = createApprovalRequest({
    requesterAgentId,
    targetAgentId,
    principalId,
    capability,
    requestedScopes: Array.isArray(body.requestedScopes) ? body.requestedScopes.map(String) : [],
    riskLevel: body.riskLevel === 'low' || body.riskLevel === 'medium' || body.riskLevel === 'high' || body.riskLevel === 'critical'
      ? body.riskLevel
      : 'high',
    policyDecisionHash: typeof body.policyDecisionHash === 'string' ? body.policyDecisionHash : undefined,
    evidenceRefs: Array.isArray(body.evidenceRefs) ? body.evidenceRefs.map(String) : [],
    expiresAt: typeof body.expiresAt === 'string' ? body.expiresAt : undefined,
  })
  localApprovals.set(approval.id, approval)
  const event = appendRootEvidence({
    type: 'approval.requested',
    actor: requesterAgentId,
    subject: targetAgentId,
    principal: principalId,
    capability,
    decision: 'requested',
    risk_level: approval.risk_level,
    privacy_mode: 'hash_only',
    metadata: {
      approval_id: approval.id,
      requested_scopes: approval.requested_scopes,
      upstream_evidence_refs: approval.evidence_refs,
    },
  })

  return c.json({
    approval,
    evidenceRefs: [event.event_id],
    authorityGranted: false,
    explanation: 'Approval records human authorization intent; it does not grant invocation authority without policy and a scoped SessionGrant.',
  }, 201)
})

app.get('/approvals', (c) => {
  return c.json({
    approvals: Array.from(localApprovals.values()),
    decisions: Array.from(localApprovalDecisions.values()),
    authorityGranted: false,
  })
})

app.post('/approvals/:id/approve', async (c) => {
  const id = c.req.param('id')
  const approval = localApprovals.get(id)
  if (!approval) {
    return c.json(localError('APPROVAL_NOT_FOUND', 'approval request not found', { id }), 404)
  }

  const body = await c.req.json().catch(() => ({}))
  const decision = createApprovalDecision({
    approvalRequestId: id,
    approverId: typeof body.approverId === 'string' ? body.approverId : 'did:fides:approver:local',
    decision: 'approved',
    reason: typeof body.reason === 'string' ? body.reason : 'Approved',
    constraints: typeof body.constraints === 'object' && body.constraints !== null ? body.constraints as Record<string, unknown> : {},
    evidenceRefs: Array.isArray(body.evidenceRefs) ? body.evidenceRefs.map(String) : [],
  })
  const updated: ApprovalRequest = { ...approval, status: 'approved' }
  localApprovals.set(id, updated)
  localApprovalDecisions.set(decision.id, decision)
  const event = appendRootEvidence({
    type: 'approval.granted',
    actor: decision.approver_id,
    subject: approval.target_agent_id,
    principal: approval.principal_id,
    capability: approval.capability,
    output: decision,
    decision: decision.decision,
    risk_level: approval.risk_level,
    privacy_mode: 'hash_only',
    metadata: {
      approval_id: approval.id,
      approval_decision_id: decision.id,
      upstream_evidence_refs: decision.evidence_refs,
    },
  })

  return c.json({
    approval: updated,
    decision,
    evidenceRefs: [event.event_id],
    authorityGranted: false,
    explanation: 'Approval has been recorded. A policy evaluation and scoped SessionGrant are still required before invocation.',
  })
})

app.post('/approvals/:id/deny', async (c) => {
  const id = c.req.param('id')
  const approval = localApprovals.get(id)
  if (!approval) {
    return c.json(localError('APPROVAL_NOT_FOUND', 'approval request not found', { id }), 404)
  }

  const body = await c.req.json().catch(() => ({}))
  const decision = createApprovalDecision({
    approvalRequestId: id,
    approverId: typeof body.approverId === 'string' ? body.approverId : 'did:fides:approver:local',
    decision: 'denied',
    reason: typeof body.reason === 'string' ? body.reason : 'Denied',
    constraints: typeof body.constraints === 'object' && body.constraints !== null ? body.constraints as Record<string, unknown> : {},
    evidenceRefs: Array.isArray(body.evidenceRefs) ? body.evidenceRefs.map(String) : [],
  })
  const updated: ApprovalRequest = { ...approval, status: 'denied' }
  localApprovals.set(id, updated)
  localApprovalDecisions.set(decision.id, decision)
  const event = appendRootEvidence({
    type: 'approval.denied',
    actor: decision.approver_id,
    subject: approval.target_agent_id,
    principal: approval.principal_id,
    capability: approval.capability,
    output: decision,
    decision: decision.decision,
    risk_level: approval.risk_level,
    privacy_mode: 'hash_only',
    metadata: {
      approval_id: approval.id,
      approval_decision_id: decision.id,
      upstream_evidence_refs: decision.evidence_refs,
    },
  })

  return c.json({
    approval: updated,
    decision,
    evidenceRefs: [event.event_id],
    authorityGranted: false,
  })
})

app.post('/killswitch', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const targetType = typeof body.targetType === 'string'
    ? body.targetType
    : typeof body.target_type === 'string'
      ? body.target_type
      : undefined
  if (
    targetType !== 'agent' &&
    targetType !== 'publisher' &&
    targetType !== 'capability' &&
    targetType !== 'session' &&
    targetType !== 'principal' &&
    targetType !== 'risk_class'
  ) {
    return c.json(localError('REQUEST_INVALID', 'targetType must be agent, publisher, capability, session, principal, or risk_class', { field: 'targetType' }), 400)
  }

  const target = typeof body.target === 'string' ? body.target : undefined
  if (!target) {
    return c.json(localError('REQUEST_INVALID', 'target is required', { field: 'target' }), 400)
  }

  const rule = createKillSwitchRule({
    issuer: typeof body.issuer === 'string' ? body.issuer : 'did:fides:operator:local',
    targetType,
    target,
    reason: typeof body.reason === 'string' ? body.reason : 'No reason provided',
    enabled: typeof body.enabled === 'boolean' ? body.enabled : true,
    expiresAt: typeof body.expiresAt === 'string' ? body.expiresAt : undefined,
  })
  localKillSwitchRules.set(rule.id, rule)
  const event = appendRootEvidence({
    type: 'kill_switch.triggered',
    actor: rule.issuer,
    subject: rule.target,
    decision: rule.enabled ? 'enabled' : 'created_disabled',
    privacy_mode: 'hash_only',
    metadata: {
      rule_id: rule.id,
      target_type: rule.target_type,
      target: rule.target,
      enabled: rule.enabled,
      reason: rule.reason,
    },
  })

  return c.json({
    rule,
    evidenceRefs: [event.event_id],
    authorityOverride: true,
    explanation: 'Kill switch rules override normal trust and policy evaluation while active.',
  }, 201)
})

app.get('/killswitch', (c) => {
  const rules = Array.from(localKillSwitchRules.values())
  return c.json({
    rules,
    active: rules.filter(rule => isKillSwitchRuleActive(rule)),
  })
})

app.delete('/killswitch/:id', (c) => {
  const id = c.req.param('id')
  const rule = localKillSwitchRules.get(id)
  if (!rule) {
    return c.json(localError('KILL_SWITCH_RULE_NOT_FOUND', 'kill switch rule not found', { id }), 404)
  }
  const { payload_hash: _payloadHash, ...rulePayload } = rule
  const disabledPayload = { ...rulePayload, enabled: false }
  const disabled: KillSwitchRule = { ...disabledPayload, payload_hash: hashProtocolPayload(disabledPayload) }
  localKillSwitchRules.set(id, disabled)
  return c.json({ rule: disabled })
})

app.post('/revocations', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const targetType = typeof body.targetType === 'string'
    ? body.targetType
    : typeof body.target_type === 'string'
      ? body.target_type
      : undefined
  if (
    targetType !== 'key' &&
    targetType !== 'identity' &&
    targetType !== 'agent' &&
    targetType !== 'agent_card' &&
    targetType !== 'capability' &&
    targetType !== 'session' &&
    targetType !== 'attestation' &&
    targetType !== 'publisher'
  ) {
    return c.json(localError('REQUEST_INVALID', 'targetType must be key, identity, agent, agent_card, capability, session, attestation, or publisher', { field: 'targetType' }), 400)
  }

  const targetId = typeof body.targetId === 'string'
    ? body.targetId
    : typeof body.target_id === 'string'
      ? body.target_id
      : undefined
  if (!targetId) {
    return c.json(localError('REQUEST_INVALID', 'targetId is required', { field: 'targetId' }), 400)
  }

  const record = createRevocationRecordV2({
    issuer: typeof body.issuer === 'string' ? body.issuer : 'did:fides:operator:local',
    targetType,
    targetId,
    reason: typeof body.reason === 'string' ? body.reason : 'No reason provided',
    evidenceRefs: Array.isArray(body.evidenceRefs) ? body.evidenceRefs.map(String) : [],
    expiresAt: typeof body.expiresAt === 'string' ? body.expiresAt : undefined,
  })
  localRevocationRecords.set(record.id, record)
  const event = appendRootEvidence({
    type: 'revocation.recorded',
    actor: record.issuer,
    subject: record.target_id,
    decision: record.status,
    privacy_mode: 'hash_only',
    metadata: {
      revocation_id: record.id,
      target_type: record.target_type,
      upstream_evidence_refs: record.evidence_refs,
    },
  })

  return c.json({
    record,
    evidenceRefs: [event.event_id],
    authorityOverride: true,
    explanation: 'Active revocation records override normal trust and policy evaluation for matching requests.',
  }, 201)
})

app.get('/revocations', (c) => {
  const records = Array.from(localRevocationRecords.values())
  return c.json({
    records,
    active: records.filter(record => isActiveLocalRevocation(record)),
  })
})

app.get('/revocations/:id', (c) => {
  const id = c.req.param('id')
  const record = localRevocationRecords.get(id) ?? Array.from(localRevocationRecords.values()).find(item => item.target_id === id)
  if (!record) {
    return c.json({
      ...localError('REVOCATION_NOT_FOUND', 'revocation record not found', { id }),
      id,
      revoked: false,
    }, 404)
  }
  return c.json({ id, revoked: isActiveLocalRevocation(record), record })
})

app.post('/incidents', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const severity = typeof body.severity === 'string' ? body.severity : undefined
  if (severity !== 'low' && severity !== 'medium' && severity !== 'high' && severity !== 'critical') {
    return c.json(localError('INCIDENT_INVALID', 'severity must be low, medium, high, or critical', { field: 'severity' }), 400)
  }

  const category = typeof body.category === 'string' ? body.category : undefined
  if (
    category !== 'policy_violation' &&
    category !== 'data_exfiltration' &&
    category !== 'malicious_output' &&
    category !== 'sandbox_escape' &&
    category !== 'unauthorized_action' &&
    category !== 'prompt_injection_failure' &&
    category !== 'payment_error' &&
    category !== 'suspicious_behavior'
  ) {
    return c.json(localError('INCIDENT_INVALID', 'category is invalid', { field: 'category' }), 400)
  }

  const targetAgentId = typeof body.targetAgentId === 'string'
    ? body.targetAgentId
    : typeof body.target_agent_id === 'string'
      ? body.target_agent_id
      : undefined
  if (!targetAgentId) {
    return c.json(localError('INCIDENT_INVALID', 'targetAgentId is required', { field: 'targetAgentId' }), 400)
  }

  const description = typeof body.description === 'string' ? body.description : undefined
  if (!description) {
    return c.json(localError('INCIDENT_INVALID', 'description is required', { field: 'description' }), 400)
  }

  const record = createIncidentRecordV2({
    reporter: typeof body.reporter === 'string' ? body.reporter : 'did:fides:reporter:local',
    targetAgentId,
    severity,
    category,
    description,
    evidenceRefs: Array.isArray(body.evidenceRefs) ? body.evidenceRefs.map(String) : [],
    trustPenalty: typeof body.trustPenalty === 'number' ? body.trustPenalty : undefined,
    reputationPenalty: typeof body.reputationPenalty === 'number' ? body.reputationPenalty : undefined,
  })
  localIncidentRecords.set(record.id, record)
  const event = appendRootEvidence({
    type: 'incident.reported',
    actor: record.reporter,
    subject: record.target_agent_id,
    decision: record.resolution_status,
    risk_level: record.severity,
    privacy_mode: 'hash_only',
    metadata: {
      incident_id: record.id,
      category: record.category,
      trust_penalty: record.trust_penalty,
      reputation_penalty: record.reputation_penalty,
      upstream_evidence_refs: record.evidence_refs,
    },
  })

  return c.json({
    record,
    evidenceRefs: [event.event_id],
    explanation: 'Open incident records require policy review for matching target agents until resolved.',
  }, 201)
})

app.get('/incidents', (c) => {
  const records = Array.from(localIncidentRecords.values())
  return c.json({
    records,
    open: records.filter(record => record.resolution_status === 'open'),
  })
})

app.get('/incidents/:id', (c) => {
  const id = c.req.param('id')
  const record = localIncidentRecords.get(id)
  if (!record) {
    return c.json(localError('INCIDENT_NOT_FOUND', 'incident record not found', { id }), 404)
  }
  return c.json({ record })
})

app.post('/incidents/:id/resolve', async (c) => {
  const id = c.req.param('id')
  const record = localIncidentRecords.get(id)
  if (!record) {
    return c.json(localError('INCIDENT_NOT_FOUND', 'incident record not found', { id }), 404)
  }
  const body = await c.req.json().catch(() => ({}))
  const status = body.status === 'dismissed' || body.status === 'false_positive' ? body.status : 'resolved'
  const resolved = resolveIncidentRecordV2(record, status)
  localIncidentRecords.set(id, resolved)
  return c.json({ record: resolved })
})

app.post('/attestations', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const identityAttestation = issueLocalIdentityAttestation(body)
  if (identityAttestation) {
    return c.json(identityAttestation.body, identityAttestation.status)
  }

  const genericAttestation = issueLocalGenericAttestation(body)
  if (genericAttestation) {
    return c.json(genericAttestation.body, genericAttestation.status)
  }

  const agentId = typeof body.agentId === 'string'
    ? body.agentId
    : typeof body.agent_id === 'string'
      ? body.agent_id
      : undefined
  if (!agentId) {
    return c.json(localError('REQUEST_INVALID', 'agentId is required', { field: 'agentId' }), 400)
  }

  const codeHash = typeof body.codeHash === 'string'
    ? body.codeHash
    : typeof body.code_hash === 'string'
      ? body.code_hash
      : undefined
  const runtimeHash = typeof body.runtimeHash === 'string'
    ? body.runtimeHash
    : typeof body.runtime_hash === 'string'
      ? body.runtime_hash
      : undefined
  const policyHash = typeof body.policyHash === 'string'
    ? body.policyHash
    : typeof body.policy_hash === 'string'
      ? body.policy_hash
      : undefined
  if (!codeHash || !runtimeHash || !policyHash) {
    return c.json(localError('REQUEST_INVALID', 'codeHash, runtimeHash, and policyHash are required', { fields: ['codeHash', 'runtimeHash', 'policyHash'] }), 400)
  }

  const attestation = await runtimeAttestationProvider.issue({
    agentId,
    codeHash,
    runtimeHash,
    policyHash,
    enclaveMeasurement: typeof body.enclaveMeasurement === 'string'
      ? body.enclaveMeasurement
      : typeof body.enclave_measurement === 'string'
        ? body.enclave_measurement
        : undefined,
    expiresAt: typeof body.expiresAt === 'string'
      ? body.expiresAt
      : typeof body.expires_at === 'string'
        ? body.expires_at
        : undefined,
  })
  localRuntimeAttestations.set(attestation.attestation_id, attestation)
  const event = appendRootEvidence({
    type: 'attestation.issued',
    actor: agentId,
    subject: agentId,
    output: attestation,
    decision: 'issued',
    privacy_mode: 'hash_only',
    metadata: {
      attestation_id: attestation.attestation_id,
      provider: attestation.provider,
      code_hash: attestation.code_hash,
      runtime_hash: attestation.runtime_hash,
      policy_hash: attestation.policy_hash,
    },
  })

  return c.json({ attestation, evidenceRefs: [event.event_id], authorityGranted: false }, 201)
})

app.get('/attestations/:id', (c) => {
  const id = c.req.param('id')
  const genericAttestation = localGenericAttestations.get(id)
  if (genericAttestation) {
    return c.json({ attestation: genericAttestation, authorityGranted: false })
  }

  const attestation = localRuntimeAttestations.get(id)
  if (!attestation) {
    return c.json(localError('ATTESTATION_NOT_FOUND', 'attestation not found', { id }), 404)
  }
  return c.json({ attestation })
})

app.post('/attestations/:id/verify', async (c) => {
  const id = c.req.param('id')
  const genericAttestation = localGenericAttestations.get(id)
  if (genericAttestation) {
    const valid = verifyLocalGenericAttestation(genericAttestation)
    const event = appendRootEvidence({
      type: valid ? 'attestation.verified' : 'attestation.failed',
      actor: genericAttestation.issuer,
      subject: genericAttestation.subject,
      output: { valid, attestation_id: id },
      decision: valid ? 'verified' : 'failed',
      privacy_mode: 'hash_only',
      metadata: {
        attestation_id: id,
        provider: genericAttestation.provider,
        subject_type: genericAttestation.subject_type,
      },
    })
    return c.json({ id, valid, attestation: genericAttestation, evidenceRefs: [event.event_id], authorityGranted: false })
  }

  const attestation = localRuntimeAttestations.get(id)
  if (!attestation) {
    const failed = appendRootEvidence({
      type: 'attestation.failed',
      actor: 'did:fides:agentd:local',
      subject: id,
      decision: 'not_found',
      privacy_mode: 'hash_only',
      metadata: { attestation_id: id },
    })
    return c.json({
      id,
      valid: false,
      ...localError('ATTESTATION_NOT_FOUND', 'attestation not found', { id }),
      evidenceRefs: [failed.event_id],
    }, 404)
  }
  const valid = await runtimeAttestationProvider.verify(attestation)
  const event = appendRootEvidence({
    type: valid ? 'attestation.verified' : 'attestation.failed',
    actor: attestation.agent_id,
    subject: attestation.agent_id,
    output: { valid, attestation_id: id },
    decision: valid ? 'verified' : 'failed',
    privacy_mode: 'hash_only',
    metadata: {
      attestation_id: id,
      provider: attestation.provider,
    },
  })
  return c.json({ id, valid, attestation, evidenceRefs: [event.event_id], authorityGranted: false })
})

function issueLocalIdentityAttestation(body: Record<string, unknown>): { body: Record<string, unknown>; status: 201 | 400 | 404 } | null {
  const identityId = typeof body.identity === 'string'
    ? body.identity
    : typeof body.identityId === 'string'
      ? body.identityId
      : typeof body.identity_id === 'string'
        ? body.identity_id
        : undefined
  if (!identityId) return null

  const record = localIdentities.get(identityId)
  if (!record) {
    return {
      status: 404,
      body: {
        ...localError('IDENTITY_NOT_FOUND', 'identity not found', { identity: identityId }),
        identity: identityId,
      },
    }
  }

  const anchor = createLocalIdentityTrustAnchor(body)
  if (!anchor) {
    return {
      status: 400,
      body: {
        ...localError('REQUEST_INVALID', 'attestation type and value are required', { fields: ['type', 'value'] }),
        identity: identityId,
      },
    }
  }

  record.identity = {
    ...record.identity,
    trustAnchors: [
      ...(record.identity.trustAnchors ?? []),
      anchor,
    ],
  } as LocalIdentityRecord['identity']
  localIdentities.set(identityId, record)

  const event = appendRootEvidence({
    type: 'attestation.issued',
    actor: identityId,
    subject: identityId,
    output: anchor,
    decision: 'issued',
    privacy_mode: 'hash_only',
    metadata: {
      trust_anchor_type: anchor.type,
      trust_anchor_value: anchor.value,
      mock: true,
    },
  })

  return {
    status: 201,
    body: {
      attestation: {
        id: `att_${crypto.randomUUID()}`,
        schema_version: 'fides.identity_attestation.v1',
        identity: identityId,
        trust_anchor: anchor,
        issued_at: anchor.verifiedAt,
        mode: 'local_mock',
      },
      identity: safeIdentityRecord(record),
      evidenceRefs: [event.event_id],
      authorityGranted: false,
    },
  }
}

function issueLocalGenericAttestation(body: Record<string, unknown>): { body: Record<string, unknown>; status: 201 | 400 } | null {
  const schemaVersion = typeof body.schema_version === 'string' ? body.schema_version : undefined
  const subject = typeof body.subject === 'string' ? body.subject : undefined
  const subjectType = typeof body.subjectType === 'string'
    ? body.subjectType
    : typeof body.subject_type === 'string'
      ? body.subject_type
      : undefined
  const provider = typeof body.provider === 'string' ? body.provider : undefined
  const issuer = typeof body.issuer === 'string' ? body.issuer : undefined

  if (schemaVersion !== 'fides.attestation.v1' && (!subject || !subjectType || !provider || !issuer)) {
    return null
  }
  if (!subject || !subjectType || !provider || !issuer) {
    return {
      status: 400,
      body: localError('REQUEST_INVALID', 'issuer, subject, subjectType, and provider are required for generic attestations', {
        fields: ['issuer', 'subject', 'subjectType', 'provider'],
      }),
    }
  }
  if (!isAttestationSubjectType(subjectType)) {
    return {
      status: 400,
      body: localError('REQUEST_INVALID', 'subjectType must be agent, publisher, principal, domain, package, wallet, passkey, runtime, build, or peer', { field: 'subjectType' }),
    }
  }

  const claims = isRecord(body.claims) ? body.claims : {}
  const evidenceRefs = Array.isArray(body.evidenceRefs)
    ? body.evidenceRefs.map(String)
    : Array.isArray(body.evidence_refs)
      ? body.evidence_refs.map(String)
      : []
  const attestation = createAttestation({
    issuer,
    subject,
    subjectType,
    provider,
    claims,
    evidenceRefs,
    issuedAt: typeof body.issuedAt === 'string'
      ? body.issuedAt
      : typeof body.issued_at === 'string'
        ? body.issued_at
        : undefined,
    expiresAt: typeof body.expiresAt === 'string'
      ? body.expiresAt
      : typeof body.expires_at === 'string'
        ? body.expires_at
        : undefined,
    signature: typeof body.signature === 'string' && body.signature.length > 0
      ? body.signature
      : undefined,
  })
  const stored = {
    ...attestation,
    signature: attestation.signature || localGenericAttestationSignature(attestation),
  }
  localGenericAttestations.set(stored.id, stored)
  const event = appendRootEvidence({
    type: 'attestation.issued',
    actor: issuer,
    subject,
    output: stored,
    decision: 'issued',
    privacy_mode: 'hash_only',
    metadata: {
      attestation_id: stored.id,
      provider,
      subject_type: subjectType,
    },
  })

  return {
    status: 201,
    body: { attestation: stored, evidenceRefs: [event.event_id], authorityGranted: false },
  }
}

function verifyLocalGenericAttestation(attestation: Attestation): boolean {
  const { payload_hash: _payloadHash, signature: _signature, ...payload } = attestation
  const expectedPayloadHash = hashProtocolPayload(payload)
  return attestation.schema_version === 'fides.attestation.v1' &&
    attestation.payload_hash === expectedPayloadHash &&
    !isAttestationExpired(attestation) &&
    attestation.signature === localGenericAttestationSignature(attestation)
}

function localGenericAttestationSignature(attestation: Attestation): string {
  return `local-attestation:${attestation.payload_hash.slice('sha256:'.length)}`
}

function isAttestationSubjectType(value: string): value is Attestation['subject_type'] {
  return value === 'agent' ||
    value === 'publisher' ||
    value === 'principal' ||
    value === 'domain' ||
    value === 'package' ||
    value === 'wallet' ||
    value === 'passkey' ||
    value === 'runtime' ||
    value === 'build' ||
    value === 'peer'
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function createLocalIdentityTrustAnchor(body: Record<string, unknown>): IdentityTrustAnchor | null {
  const rawType = typeof body.type === 'string'
    ? body.type
    : typeof body.provider === 'string'
      ? body.provider
      : undefined
  const type = normalizeTrustAnchorType(rawType, body)
  if (!type) return null
  const value = identityTrustAnchorValue(type, body)
  if (!value) return null
  return {
    type,
    value,
    verified: true,
    verifiedAt: new Date().toISOString(),
  }
}

function normalizeTrustAnchorType(rawType: string | undefined, body: Record<string, unknown>): TrustAnchorType | null {
  if (rawType === 'package') {
    const registry = typeof body.registry === 'string' ? body.registry.toLowerCase() : ''
    if (registry === 'npm') return 'npm'
    if (registry === 'pypi') return 'pypi'
    return null
  }
  if (
    rawType === 'domain' ||
    rawType === 'github' ||
    rawType === 'email' ||
    rawType === 'npm' ||
    rawType === 'pypi' ||
    rawType === 'wallet' ||
    rawType === 'passkey' ||
    rawType === 'organization_invitation' ||
    rawType === 'runtime_attestation' ||
    rawType === 'build_attestation' ||
    rawType === 'peer_attestation'
  ) {
    return rawType
  }
  return null
}

function identityTrustAnchorValue(type: TrustAnchorType, body: Record<string, unknown>): string | null {
  if (type === 'github') return stringField(body, 'handle')
  if (type === 'email') return stringField(body, 'email')
  if (type === 'domain') return stringField(body, 'domain')
  if (type === 'wallet') return stringField(body, 'address')
  if (type === 'npm' || type === 'pypi') return stringField(body, 'package') ?? stringField(body, 'name')
  return stringField(body, 'value')
}

function stringField(record: Record<string, unknown>, key: string): string | null {
  const value = record[key]
  return typeof value === 'string' && value.length > 0 ? value : null
}

// ─── FIDES v2 Local API Aliases ───────────────────────────────────
app.post('/dht/start', (c) => {
  return c.json({ started: true, mode: 'in_memory_simulator', pointers: localDhtPointers.length })
})

app.post('/dht/publish', async (c) => {
  const body = await c.req.json()
  if (!body.capability) {
    return c.json(localError('REQUEST_INVALID', 'capability is required', { field: 'capability' }), 400)
  }

  const capability = String(body.capability)
  const cardId = typeof body.agentCardId === 'string'
    ? body.agentCardId
    : typeof body.cardId === 'string'
      ? body.cardId
      : undefined
  const agentId = typeof body.agentId === 'string'
    ? body.agentId
    : typeof body.agent_id === 'string'
      ? body.agent_id
      : undefined
  const registered = cardId
    ? Array.from(localAgents.values()).find(record => record.cardId === cardId)
    : agentId
      ? localAgents.get(agentId)
      : undefined
  const card = registered ? localAgentCards.get(registered.cardId) : undefined
  const identity = card ? localIdentities.get(card.identity.did) : undefined

  if (card && identity) {
    if (!card.capabilities.some(candidate => candidate.id === capability)) {
      return c.json(localError('CAPABILITY_NOT_FOUND', 'AgentCard does not advertise capability', { capability, cardId: card.id }), 400)
    }
    const publisherId = typeof body.publisherId === 'string'
      ? body.publisherId
      : typeof body.publisher_id === 'string'
        ? body.publisher_id
        : card.publisher?.did ?? card.identity.did
    const publisherIdentity = localIdentities.get(publisherId)
    if (!publisherIdentity) {
      return c.json(localError('IDENTITY_NOT_FOUND', 'DHT pointer publisher key not found', { publisherId }), 404)
    }

    const pointer = await signDHTPointerRecord(createDHTPointerRecord({
      capability,
      agentId: card.identity.did,
      agentCardUrl: typeof body.agentCardUrl === 'string'
        ? body.agentCardUrl
        : typeof body.agent_card_url === 'string'
          ? body.agent_card_url
          : `local://agent-cards/${encodeURIComponent(card.id)}`,
      agentCardHash: hashAgentCard(card),
      publisherId,
      expiresAt: typeof body.expiresAt === 'string'
        ? body.expiresAt
        : typeof body.expires_at === 'string'
          ? body.expires_at
          : new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      sequence: typeof body.sequence === 'number' ? body.sequence : undefined,
    }), Buffer.from(publisherIdentity.privateKeyHex, 'hex'), publisherId)
    const storedPointer = {
      ...pointer,
      id: body.id ?? crypto.randomUUID(),
      agentId: pointer.agent_id,
      agentCardUrl: pointer.agent_card_url,
      agentCardHash: pointer.agent_card_hash,
      publisherId: pointer.publisher_id,
      cardId: card.id,
      signed: true,
      publishedAt: new Date().toISOString(),
      source: 'agentd-signed-dht-pointer',
    }
    localDhtPointers.push(storedPointer)
    return c.json({ accepted: true, pointer: storedPointer, authorityGranted: false }, 201)
  }

  const pointer = {
    id: body.id ?? crypto.randomUUID(),
    capability,
    agentId: agentId,
    agentCardUrl: body.agentCardUrl ?? body.agent_card_url ?? body.agentCard,
    signed: false,
    verification: {
      valid: false,
      errors: ['DHT pointer signature is required'],
    },
    publishedAt: new Date().toISOString(),
    source: 'agentd-in-memory-dht',
  }
  localDhtPointers.push(pointer)
  return c.json({ accepted: true, pointer, authorityGranted: false }, 201)
})

async function findLocalDhtPointers(capability?: string) {
  const matched = capability
    ? localDhtPointers.filter(pointer => pointer.capability === capability)
    : localDhtPointers
  const rejectedPointers: Array<Record<string, unknown>> = []
  const pointers: Array<Record<string, unknown>> = []
  for (const pointer of matched) {
    if (pointer.schema_version === 'fides.dht.pointer.v1') {
      const pointerRecord = dhtPointerRecordOnly(pointer)
      const card = localCardForProviderRecord(pointer)
      const verification = await verifyDHTPointerRecord(pointerRecord, {
        ...(card && { card }),
        verificationMethod: typeof pointer.publisher_id === 'string' ? pointer.publisher_id : undefined,
      })
      const enriched = { ...pointer, verification }
      if (!verification.valid) {
        rejectedPointers.push({
          ...enriched,
          authorityGranted: false,
          reasons: [
            'dht_pointer_verification_failed',
            'discovery_does_not_grant_authority',
          ],
        })
        continue
      }
      pointers.push(enriched)
      continue
    }
    pointers.push(pointer)
  }
  return { capability: capability ?? null, pointers, rejectedPointers }
}

app.get('/dht/find', async (c) => {
  return c.json(await findLocalDhtPointers(c.req.query('capability')))
})

app.post('/dht/find', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const capability = typeof body.capability === 'string' ? body.capability : undefined
  return c.json(await findLocalDhtPointers(capability))
})

app.post('/discover/dht', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const capability = typeof body.capability === 'string' ? body.capability : undefined
  const found = await findLocalDhtPointers(capability)
  const filtered = filterVersionCompatibleProviderRecords(
    body,
    found.pointers as Array<Record<string, unknown>>,
    'rejectedPointers'
  )
  const result = {
    provider: 'dht',
    capability: found.capability,
    pointers: filtered.records,
    rejectedPointers: [
      ...found.rejectedPointers,
      ...filtered.rejected,
    ],
    authorityGranted: false,
    explanation: 'DHT discovery returns signed pointer candidates only; trust, policy, and session grants are evaluated separately.',
  }
  return c.json(appendDiscoveryEvidence('dht', body, result))
})

async function localRegistryRecordFor(cardId: string, mode: 'public' | 'private' = 'public') {
  const card = localAgentCards.get(cardId)
  const registered = card ? localAgents.get(card.identity.did) : undefined
  const identity = card ? localIdentities.get(card.identity.did) : undefined
  if (!card || !registered) {
    return null
  }
  const signedCard = localSignedAgentCards.get(card.id)
  if (!signedCard || !await verifySignedAgentCardIdentity(signedCard)) {
    return null
  }
  const registryIndexRecord = createRegistryIndexRecord({
    issuer: card.identity.did,
    mode,
    agentCardId: card.id,
    agentId: card.identity.did,
    capabilityIds: card.capabilities.map(capability => capability.id),
    agentCardHash: hashAgentCard(card),
    registryUrl: 'local://registry',
    supportedVersions: card.protocolVersions?.length ? card.protocolVersions : ['fides.v2.0'],
  })
  const signedRegistryIndexRecord = identity
    ? await signRegistryIndexRecord(registryIndexRecord, Buffer.from(identity.privateKeyHex, 'hex'), card.identity.did)
    : null
  return {
    id: `reg_${card.id}`,
    agentId: card.identity.did,
    cardId: card.id,
    mode,
    capabilities: card.capabilities.map(capability => capability.id),
    signed: true,
    agentCardUrl: `local://agent-cards/${encodeURIComponent(card.id)}`,
    agentCardHash: registryIndexRecord.agent_card_hash,
    registryIndexRecord,
    signedRegistryIndexRecord,
    registryIndexProof: signedRegistryIndexRecord?.proof ?? null,
    registryIndexVerified: signedRegistryIndexRecord ? await verifySignedRegistryIndexRecord(signedRegistryIndexRecord) : false,
    publishedAt: new Date().toISOString(),
    authorityGranted: false,
    source: 'agentd-local-registry',
  }
}

function signedRegistryIndexFor(record: Record<string, unknown>): SignedRegistryIndexRecord | undefined {
  const signed = record.signedRegistryIndexRecord
  if (!signed || typeof signed !== 'object') return undefined
  const candidate = signed as Partial<SignedRegistryIndexRecord>
  if (!candidate.payload || !candidate.proof) return undefined
  return candidate as SignedRegistryIndexRecord
}

async function filterVerifiedLocalRegistryRecords(records: Array<Record<string, unknown>>) {
  const verifiedRecords: Array<Record<string, unknown>> = []
  const rejectedRecords: Array<Record<string, unknown>> = []
  for (const record of records) {
    const signed = signedRegistryIndexFor(record)
    if (!signed) {
      rejectedRecords.push({
        ...record,
        authorityGranted: false,
        registryIndexVerification: 'missing_signed_registry_index',
        reasons: [
          'registry_index_signature_required',
          'discovery_does_not_grant_authority',
        ],
      })
      continue
    }
    const valid = await verifySignedRegistryIndexRecord(signed)
    const enriched = { ...record, registryIndexVerified: valid }
    if (!valid) {
      rejectedRecords.push({
        ...enriched,
        authorityGranted: false,
        reasons: [
          'registry_index_signature_invalid',
          'discovery_does_not_grant_authority',
        ],
      })
      continue
    }
    verifiedRecords.push(enriched)
  }
  return { records: verifiedRecords, rejectedRecords }
}

async function localFederationPeerRecord(): Promise<{ signed: SignedRegistryPeerRecord | null; verified: boolean }> {
  const identity = Array.from(localIdentities.values())[0]
  const record = createRegistryPeerRecord({
    issuer: identity?.identity.did ?? 'did:fides:agentd:local-registry',
    peerId: 'local_registry_peer',
    registryUrl: 'local://registry',
    peeringMode: 'federated',
    supportedVersions: ['fides.v2.0'],
    capabilities: ['registry_search', 'revocation_propagation', 'incident_propagation'],
  })
  if (!identity) return { signed: null, verified: false }
  const signed = await signRegistryPeerRecord(record, Buffer.from(identity.privateKeyHex, 'hex'), identity.identity.did)
  return { signed, verified: await verifySignedRegistryPeerRecord(signed) }
}

async function localRelayRecordFor(agentId: string, endpointHints: unknown[] = []) {
  const registered = localAgents.get(agentId)
  const card = registered ? localAgentCards.get(registered.cardId) : undefined
  if (!registered || !card) {
    return null
  }
  const signedCard = localSignedAgentCards.get(card.id)
  if (!signedCard || !await verifySignedAgentCardIdentity(signedCard)) {
    return null
  }
  return {
    id: `relay_${agentId}`,
    agentId,
    cardId: registered.cardId,
    capabilities: card.capabilities.map(capability => capability.id),
    endpointHints,
    online: true,
    agentCardUrl: `local://agent-cards/${encodeURIComponent(card.id)}`,
    agentCardHash: hashAgentCard(card),
    signedAgentCard: true,
    agentCardProof: signedCard.proof,
    registeredAt: new Date().toISOString(),
    authorityGranted: false,
    source: 'agentd-local-relay',
  }
}

app.post('/registry/publish', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const cardId = typeof body.agentCardId === 'string'
    ? body.agentCardId
    : typeof body.cardId === 'string'
      ? body.cardId
      : undefined
  if (!cardId) {
    return c.json(localError('REQUEST_INVALID', 'agentCardId is required', { field: 'agentCardId' }), 400)
  }
  const record = await localRegistryRecordFor(cardId, body.mode === 'private' ? 'private' : 'public')
  if (!record) {
    return c.json(localError('AGENT_CARD_NOT_FOUND', 'registered local AgentCard not found', { cardId }), 404)
  }
  localRegistryRecords.set(String(record.id), record)
  return c.json({ accepted: true, record, authorityGranted: false }, 201)
})

app.post('/registry/search', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const capability = typeof body.capability === 'string' ? body.capability : undefined
  const matched = Array.from(localRegistryRecords.values()).filter((record) => (
    !capability || (record.capabilities as string[] | undefined)?.includes(capability)
  ))
  const verified = await filterVerifiedLocalRegistryRecords(matched)
  const filtered = filterVersionCompatibleProviderRecords(body, verified.records)
  return c.json({
    capability: capability ?? null,
    records: filtered.records,
    rejectedRecords: [
      ...verified.rejectedRecords,
      ...filtered.rejected,
    ],
    authorityGranted: false,
  })
})

app.post('/discover/registry', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const capability = typeof body.capability === 'string' ? body.capability : undefined
  const matched = Array.from(localRegistryRecords.values()).filter((record) => (
    !capability || (record.capabilities as string[] | undefined)?.includes(capability)
  ))
  const verified = await filterVerifiedLocalRegistryRecords(matched)
  const filtered = filterVersionCompatibleProviderRecords(body, verified.records)
  const result = {
    provider: 'registry',
    capability: capability ?? null,
    records: filtered.records,
    rejectedRecords: [
      ...verified.rejectedRecords,
      ...filtered.rejected,
    ],
    authorityGranted: false,
    explanation: 'Registry discovery returns registry records only; registration does not grant invocation authority.',
  }
  return c.json(appendDiscoveryEvidence('registry', body, result))
})

app.post('/discover/federation', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const capability = typeof body.capability === 'string' ? body.capability : undefined
  const matched = Array.from(localRegistryRecords.values()).filter((record) => (
    !capability || (record.capabilities as string[] | undefined)?.includes(capability)
  ))
  const verified = await filterVerifiedLocalRegistryRecords(matched)
  const filtered = filterVersionCompatibleProviderRecords(body, verified.records)
  const peer = await localFederationPeerRecord()
  const federatedRecords = filtered.records.map((record) => ({
    ...record,
    provider: 'federation',
    federationPeerId: peer.signed?.payload.peer_id ?? 'local_registry_peer',
    federationPeerRecord: peer.signed?.payload ?? null,
    federationPeerProof: peer.signed?.proof ?? null,
    federationPeerVerified: peer.verified,
    authorityGranted: false,
    reasons: [
      ...(Array.isArray(record.reasons) ? record.reasons.map(String) : []),
      'federation_peer_matched_capability',
      'federation_does_not_grant_authority',
    ],
  }))
  const result = {
    provider: 'federation',
    mode: 'local_mock_federation',
    capability: capability ?? null,
    records: federatedRecords,
    rejectedRecords: [
      ...verified.rejectedRecords,
      ...filtered.rejected,
    ],
    federationPeerRecord: peer.signed?.payload ?? null,
    federationPeerProof: peer.signed?.proof ?? null,
    federationPeerVerified: peer.verified,
    authorityGranted: false,
    explanation: 'Federation expands discovery to registry peers only; federated results are candidates and never invocation authority.',
  }
  return c.json(appendDiscoveryEvidence('federation', body, result))
})

app.get('/registry/index', async (c) => {
  const verified = await filterVerifiedLocalRegistryRecords(Array.from(localRegistryRecords.values()))
  return c.json({
    mode: 'local_mock_registry',
    records: verified.records,
    rejectedRecords: verified.rejectedRecords,
    authorityGranted: false,
  })
})

app.post('/registry/start', (c) => {
  return c.json({
    started: true,
    mode: 'local_mock_registry',
    records: localRegistryRecords.size,
    authorityGranted: false,
  })
})

app.post('/relay/start', (c) => {
  return c.json({
    started: true,
    mode: 'local_mock_relay',
    records: localRelayRecords.size,
    authorityGranted: false,
  })
})

app.post('/relay/register', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const agentId = typeof body.agentId === 'string'
    ? body.agentId
    : typeof body.agent_id === 'string'
      ? body.agent_id
      : undefined
  if (!agentId) {
    return c.json(localError('REQUEST_INVALID', 'agentId is required', { field: 'agentId' }), 400)
  }
  const record = await localRelayRecordFor(
    agentId,
    Array.isArray(body.endpointHints) ? body.endpointHints : []
  )
  if (!record) {
    return c.json(localError('AGENT_NOT_REGISTERED', 'registered local agent not found', { agentId }), 404)
  }
  localRelayRecords.set(agentId, record)
  return c.json({ accepted: true, record, authorityGranted: false }, 201)
})

app.post('/relay/discover', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const capability = typeof body.capability === 'string' ? body.capability : undefined
  const matched = Array.from(localRelayRecords.values()).filter((record) => (
    !capability || (record.capabilities as string[] | undefined)?.includes(capability)
  ))
  const filtered = filterVersionCompatibleProviderRecords(body, matched)
  return c.json({
    capability: capability ?? null,
    records: filtered.records,
    [filtered.rejectedKey]: filtered.rejected,
    authorityGranted: false,
  })
})

app.post('/discover/relay', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const capability = typeof body.capability === 'string' ? body.capability : undefined
  const matched = Array.from(localRelayRecords.values()).filter((record) => (
    !capability || (record.capabilities as string[] | undefined)?.includes(capability)
  ))
  const filtered = filterVersionCompatibleProviderRecords(body, matched)
  const result = {
    provider: 'relay',
    capability: capability ?? null,
    records: filtered.records,
    [filtered.rejectedKey]: filtered.rejected,
    authorityGranted: false,
    explanation: 'Relay discovery returns presence records only; relay presence is not authority.',
  }
  return c.json(appendDiscoveryEvidence('relay', body, result))
})

app.get('/.well-known/fides.json', (c) => {
  return c.json({
    schema_version: 'fides.well_known.v1',
    protocol: 'fides.v2',
    supported_versions: ['fides.v2.0'],
    endpoints: {
      agents: '/.well-known/agents.json',
      registry: '/registry/index',
      discovery: '/discover',
    },
  })
})

app.get('/.well-known/agents.json', (c) => {
  return c.json({
    schema_version: 'fides.well_known.agents.v1',
    agents: Array.from(localAgents.values()).map(record => ({
      agentId: record.agentId,
      cardId: record.cardId,
      signed: record.signed,
      cardUrl: `/.well-known/agents/${encodeURIComponent(record.agentId)}.json`,
      authorityGranted: false,
    })),
  })
})

app.get('/.well-known/agents/*', (c) => {
  const rawId = c.req.path.slice('/.well-known/agents/'.length).replace(/\.json$/, '')
  const id = decodeURIComponent(rawId)
  if (!id) {
    return c.json(localError('REQUEST_INVALID', 'agent id is required', { field: 'agentId' }), 400)
  }
  const registered = localAgents.get(id)
  const card = registered ? localAgentCards.get(registered.cardId) : undefined
  if (!registered || !card) {
    return c.json(localError('AGENT_NOT_REGISTERED', 'registered local agent not found', { agentId: id }), 404)
  }
  return c.json({
    agentId: id,
    card,
    signed: localSignedAgentCards.get(card.id) ?? null,
    authorityGranted: false,
  })
})

function appendRootEvidence(input: EvidenceEventV2Input): EvidenceEventV2 {
  const previousHash = localEvidenceEvents.at(-1)?.event_hash ?? '0'
  const event = createEvidenceEventV2(input, previousHash)
  localEvidenceEvents = appendEvidenceEventV2(localEvidenceEvents, event)
  return event
}

app.post('/evidence', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const type = typeof body.type === 'string' ? body.type : undefined
  const actor = typeof body.actor === 'string' ? body.actor : undefined
  if (!type || !actor) {
    return c.json(localError('REQUEST_INVALID', 'type and actor are required', { fields: ['type', 'actor'] }), 400)
  }
  const event = appendRootEvidence({
    type: type as EvidenceEventV2Input['type'],
    actor,
    subject: typeof body.subject === 'string' ? body.subject : undefined,
    principal: typeof body.principal === 'string' ? body.principal : undefined,
    capability: typeof body.capability === 'string' ? body.capability : undefined,
    input: body.input,
    output: body.output,
    policy: body.policy,
    decision: typeof body.decision === 'string' ? body.decision : undefined,
    risk_level: typeof body.riskLevel === 'string' ? body.riskLevel as EvidenceEventV2['risk_level'] : undefined,
    privacy_mode: body.privacyMode === 'public' || body.privacyMode === 'private' || body.privacyMode === 'redacted' || body.privacyMode === 'hash_only'
      ? body.privacyMode
      : 'hash_only',
    metadata: typeof body.metadata === 'object' && body.metadata !== null ? body.metadata as Record<string, unknown> : undefined,
  })
  return c.json({ accepted: true, event, authorityGranted: false }, 201)
})

app.get('/evidence', (c) => {
  const valid = verifyEvidenceEventsV2(localEvidenceEvents)
  return c.json({
    events: localEvidenceEvents,
    count: localEvidenceEvents.length,
    valid,
    lastHash: localEvidenceEvents.at(-1)?.event_hash ?? null,
    authorityGranted: false,
  })
})

app.post('/evidence/verify', (c) => {
  const valid = verifyEvidenceEventsV2(localEvidenceEvents)
  return c.json({
    valid,
    count: localEvidenceEvents.length,
    lastHash: localEvidenceEvents.at(-1)?.event_hash ?? null,
    scope: 'root-local-evidence-ledger',
    checkedAt: new Date().toISOString(),
  })
})

app.post('/evidence/export', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const privacyMode = body.privacy_mode ?? body.privacyMode
  if (
    privacyMode !== undefined &&
    privacyMode !== 'public' &&
    privacyMode !== 'private' &&
    privacyMode !== 'redacted' &&
    privacyMode !== 'hash_only'
  ) {
    return c.json(localError('EVIDENCE_PRIVACY_MODE_INVALID', 'privacy_mode must be public, private, redacted, or hash_only', { field: 'privacy_mode' }), 400)
  }
  const includeMetadata = typeof body.include_metadata === 'boolean'
    ? body.include_metadata
    : typeof body.includeMetadata === 'boolean'
      ? body.includeMetadata
      : undefined
  const events = exportEvidenceEventsV2(localEvidenceEvents, {
    ...(privacyMode !== undefined && { privacy_mode: privacyMode }),
    ...(includeMetadata !== undefined && { include_metadata: includeMetadata }),
  })
  return c.json({
    format: 'json',
    exportedAt: new Date().toISOString(),
    valid: verifyEvidenceEventsV2(localEvidenceEvents),
    count: localEvidenceEvents.length,
    privacyMode: privacyMode ?? 'event_default',
    includeMetadata: includeMetadata ?? null,
    events,
  })
})

app.get('/evidence/:eventId', (c) => {
  const eventId = c.req.param('eventId')
  const event = localEvidenceEvents.find(item => item.event_id === eventId)
  if (!event) {
    return c.json(localError('EVIDENCE_EVENT_NOT_FOUND', 'evidence event not found', { eventId }), 404)
  }
  return c.json({ event, authorityGranted: false })
})

async function createDemoAgent(input: {
  name: string
  capability: ReturnType<typeof createCapabilityDescriptor>
  publisher?: PublisherIdentity
  runtimeAttestations?: RuntimeAttestation[]
}): Promise<{ identity: LocalIdentityRecord; card: AgentCard; signed: SignedAgentCard; registration: LocalRegisteredAgent }> {
  const identity = await createLocalIdentity('agent', { name: input.name })
  localIdentities.set(identity.identity.did, identity)
  const now = new Date().toISOString()
  const card: AgentCard = {
    schema_version: 'fides.agent_card.v1',
    id: identity.identity.did,
    agent_id: identity.identity.did,
    identity: identity.identity as AgentIdentity,
    ...(input.publisher ? { publisher: input.publisher } : {}),
    capabilities: [input.capability],
    endpoints: [],
    policies: [{
      requiresRuntimeAttestation: input.capability.requiresRuntimeAttestation,
      requiresApproval: input.capability.requiresApproval,
    }],
    publicKeys: [{ id: `${identity.identity.did}#ed25519`, type: 'Ed25519', publicKey: identity.publicKeyHex }],
    runtimeAttestations: input.runtimeAttestations ?? [],
    protocolVersions: ['fides.v2.0'],
    createdAt: now,
    updatedAt: now,
  }
  localAgentCards.set(card.id, card)
  const signed = await signAgentCard(card, Buffer.from(identity.privateKeyHex, 'hex'), card.identity.did)
  localSignedAgentCards.set(card.id, signed)
  const registration = {
    agentId: card.identity.did,
    cardId: card.id,
    registeredAt: now,
    signed: true,
  }
  localAgents.set(registration.agentId, registration)
  return { identity, card, signed, registration }
}

async function runLocalFullDemo() {
  const principal = await createLocalIdentity('principal', { name: 'Demo Principal' })
  const publisher = await createLocalIdentity('publisher', { name: 'Demo Publisher', domain: 'demo.fides.local' })
  const requester = await createLocalIdentity('agent', { name: 'Requester Agent' })
  localIdentities.set(principal.identity.did, principal)
  localIdentities.set(publisher.identity.did, publisher)
  localIdentities.set(requester.identity.did, requester)
  const authority = await getLocalAuthorityIdentity()

  const calendarCapability = createCapabilityDescriptor({
    id: 'calendar.schedule',
    riskLevel: 'low',
    requiredScopes: ['calendar:write'],
    supportedControls: ['dry_run', 'policy_proof'],
    supportsDryRun: true,
    supportsPolicyProof: true,
  })
  const invoiceCapability = createCapabilityDescriptor({
    id: 'invoice.reconcile',
    riskLevel: 'medium',
    requiredScopes: ['invoice:read'],
    supportedControls: ['dry_run', 'policy_proof'],
    supportsDryRun: true,
    supportsPolicyProof: true,
  })
  const paymentCapability = createCapabilityDescriptor({
    id: 'payments.prepare',
    riskLevel: 'high',
    requiredScopes: ['payments:prepare'],
    supportedControls: ['dry_run', 'human_approval', 'runtime_attestation', 'policy_proof'],
    supportsDryRun: true,
    supportsHumanApproval: true,
    supportsPolicyProof: true,
  })

  const calendar = await createDemoAgent({ name: 'Calendar Agent', capability: calendarCapability, publisher: publisher.identity as PublisherIdentity })
  const invoice = await createDemoAgent({ name: 'Invoice Agent', capability: invoiceCapability, publisher: publisher.identity as PublisherIdentity })
  const payment = await createDemoAgent({ name: 'Payment Agent', capability: paymentCapability, publisher: publisher.identity as PublisherIdentity })

  const registryRecord = await localRegistryRecordFor(invoice.card.id)
  if (registryRecord) localRegistryRecords.set(String(registryRecord.id), registryRecord)
  const relayRecord = await localRelayRecordFor(calendar.card.identity.did, ['local://calendar-agent'])
  if (relayRecord) localRelayRecords.set(calendar.card.identity.did, relayRecord)
  const dhtPointerRecord = await signDHTPointerRecord(createDHTPointerRecord({
    capability: paymentCapability.id,
    agentId: payment.card.identity.did,
    agentCardUrl: `local://agent-cards/${payment.card.id}`,
    agentCardHash: hashAgentCard(payment.card),
    publisherId: publisher.identity.did,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  }), Buffer.from(publisher.privateKeyHex, 'hex'), publisher.identity.did)
  const dhtPointer = {
    ...dhtPointerRecord,
    id: crypto.randomUUID(),
    agentId: dhtPointerRecord.agent_id,
    agentCardUrl: dhtPointerRecord.agent_card_url,
    agentCardHash: dhtPointerRecord.agent_card_hash,
    publisherId: dhtPointerRecord.publisher_id,
    cardId: payment.card.id,
    signed: true,
    publishedAt: new Date().toISOString(),
    source: 'agentd-demo-signed-dht-pointer',
  }
  localDhtPointers.push(dhtPointer)

  const calendarDiscovery = await localDiscoveryResult({ capability: calendarCapability.id }, 'local')
  const invoiceRegistryRecords = Array.from(localRegistryRecords.values()).filter((record) => (
    (record.capabilities as string[] | undefined)?.includes(invoiceCapability.id)
  ))
  const paymentDhtPointers = await findLocalDhtPointers(paymentCapability.id)
  const verifiedCards = await Promise.all([calendar.signed, invoice.signed, payment.signed].map(verifySignedAgentCardIdentity))

  const invoiceTrust = computeLocalTrustResult(invoice.card.identity.did, invoiceCapability.id)
  const invoiceReputation = computeCapabilityReputation({
    agentId: invoice.card.identity.did,
    publisherId: publisher.identity.did,
    capability: invoiceCapability.id,
    successfulInvocations: 8,
    failedInvocations: 1,
    incidentCount: 0,
    publisherWeight: 0.7,
  })
  localReputationRecords.set(localCapabilityKey(invoice.card.identity.did, invoiceCapability.id), invoiceReputation)

  const invoiceSessionTrust = computeLocalTrustResult(invoice.card.identity.did, invoiceCapability.id)
  const invoicePolicy = evaluateFidesPolicy({
    principalId: principal.identity.did,
    requesterAgentId: requester.identity.did,
    targetAgentId: invoice.card.identity.did,
    capability: invoiceCapability,
    trustResult: invoiceSessionTrust!,
    requestedScopes: ['invoice:read'],
  })
  const invoiceSession = createSessionGrantV2({
    requesterAgentId: requester.identity.did,
    targetAgentId: invoice.card.identity.did,
    principalId: principal.identity.did,
    capability: invoiceCapability.id,
    scopes: ['invoice:read'],
    constraints: {},
    policyHash: hashProtocolPayload(invoicePolicy),
    trustResultHash: hashProtocolPayload(invoiceSessionTrust),
    audience: [invoice.card.identity.did],
    issuer: authority.identity.did,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  })
  const signedInvoiceSession = await signSessionGrantV2(invoiceSession, Buffer.from(authority.privateKeyHex, 'hex'), authority.identity.did)
  localSessionGrants.set(invoiceSession.session_id, { session: invoiceSession, signedSession: signedInvoiceSession, policy: invoicePolicy, trust: invoiceSessionTrust! })
  const invoiceSessionEvidence = appendRootEvidence({
    type: 'session.granted',
    actor: requester.identity.did,
    subject: invoice.card.identity.did,
    principal: principal.identity.did,
    capability: invoiceCapability.id,
    policy: invoicePolicy,
    decision: invoicePolicy.decision,
    risk_level: invoiceCapability.riskLevel,
    privacy_mode: 'hash_only',
    metadata: { session_id: invoiceSession.session_id, demo: true },
  })

  const invoiceRequest = createInvocationRequest({
    issuer: requester.identity.did,
    sessionGrant: invoiceSession,
    input: { invoiceId: 'inv_demo_001' },
    dryRun: false,
    inputSchema: invoiceCapability.inputSchema,
    outputSchema: invoiceCapability.outputSchema,
  })
  const invoicePreflight = evaluateInvocationPreflight({ request: invoiceRequest, policyDecision: invoicePolicy })
  const invoiceInvokeEvidence = appendRootEvidence({
    type: 'capability.invoked',
    actor: requester.identity.did,
    subject: invoice.card.identity.did,
    principal: principal.identity.did,
    capability: invoiceCapability.id,
    input: { invoiceId: 'inv_demo_001' },
    policy_hash: invoiceSession.policy_hash,
    decision: invoicePolicy.decision,
    privacy_mode: 'hash_only',
    metadata: { session_id: invoiceSession.session_id, demo: true },
  })
  const invoiceCompleteEvidence = appendRootEvidence({
    type: 'capability.completed',
    actor: invoice.card.identity.did,
    subject: requester.identity.did,
    principal: principal.identity.did,
    capability: invoiceCapability.id,
    output: { reconciled: true },
    policy_hash: invoiceSession.policy_hash,
    decision: invoicePreflight.can_execute ? 'completed' : invoicePreflight.status,
    privacy_mode: 'hash_only',
    metadata: { session_id: invoiceSession.session_id, demo: true },
  })

  const paymentTrustMissingAttestation = computeLocalTrustResult(payment.card.identity.did, paymentCapability.id)!
  const paymentPolicyWithoutAttestation = evaluateFidesPolicy({
    principalId: principal.identity.did,
    requesterAgentId: requester.identity.did,
    targetAgentId: payment.card.identity.did,
    capability: paymentCapability,
    trustResult: paymentTrustMissingAttestation,
    requestedScopes: ['payments:prepare'],
  })
  const paymentDeniedEvidence = appendRootEvidence({
    type: 'session.denied',
    actor: requester.identity.did,
    subject: payment.card.identity.did,
    principal: principal.identity.did,
    capability: paymentCapability.id,
    policy: paymentPolicyWithoutAttestation,
    decision: paymentPolicyWithoutAttestation.decision,
    risk_level: paymentCapability.riskLevel,
    privacy_mode: 'hash_only',
    metadata: { demo: true, reason: 'missing_runtime_attestation' },
  })

  const paymentAttestation = await runtimeAttestationProvider.issue({
    agentId: payment.card.identity.did,
    codeHash: `sha256:${'a'.repeat(64)}`,
    runtimeHash: `sha256:${'b'.repeat(64)}`,
    policyHash: `sha256:${'c'.repeat(64)}`,
  })
  localRuntimeAttestations.set(paymentAttestation.attestation_id, paymentAttestation)
  const paymentCard = {
    ...payment.card,
    runtimeAttestations: [paymentAttestation],
    updatedAt: new Date().toISOString(),
  }
  localAgentCards.set(paymentCard.id, paymentCard)

  const paymentTrust = computeLocalTrustResult(payment.card.identity.did, paymentCapability.id)!
  const paymentPolicy = evaluateFidesPolicy({
    principalId: principal.identity.did,
    requesterAgentId: requester.identity.did,
    targetAgentId: payment.card.identity.did,
    capability: paymentCapability,
    trustResult: paymentTrust,
    requestedScopes: ['payments:prepare'],
    runtimeAttestationValid: await runtimeAttestationProvider.verify(paymentAttestation),
  })
  const paymentSession = createSessionGrantV2({
    requesterAgentId: requester.identity.did,
    targetAgentId: payment.card.identity.did,
    principalId: principal.identity.did,
    capability: paymentCapability.id,
    scopes: ['payments:prepare'],
    constraints: { dryRunOnly: true },
    policyHash: hashProtocolPayload(paymentPolicy),
    trustResultHash: hashProtocolPayload(paymentTrust),
    audience: [payment.card.identity.did],
    issuer: authority.identity.did,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  })
  const signedPaymentSession = await signSessionGrantV2(paymentSession, Buffer.from(authority.privateKeyHex, 'hex'), authority.identity.did)
  localSessionGrants.set(paymentSession.session_id, { session: paymentSession, signedSession: signedPaymentSession, policy: paymentPolicy, trust: paymentTrust })
  const paymentDryRunRequest = createInvocationRequest({
    issuer: requester.identity.did,
    sessionGrant: paymentSession,
    input: { paymentId: 'pay_demo_001', amount: 100, currency: 'USD' },
    dryRun: true,
    inputSchema: paymentCapability.inputSchema,
    outputSchema: paymentCapability.outputSchema,
  })
  const paymentDryRunPreflight = evaluateInvocationPreflight({ request: paymentDryRunRequest, policyDecision: paymentPolicy })
  const paymentDryRunEvidence = appendRootEvidence({
    type: paymentDryRunPreflight.can_execute ? 'capability.completed' : 'capability.failed',
    actor: payment.card.identity.did,
    subject: requester.identity.did,
    principal: principal.identity.did,
    capability: paymentCapability.id,
    output: paymentDryRunPreflight.can_execute ? { dryRun: true, prepared: true } : undefined,
    policy_hash: paymentSession.policy_hash,
    decision: paymentDryRunPreflight.can_execute ? 'completed' : paymentDryRunPreflight.status,
    privacy_mode: 'hash_only',
    metadata: { session_id: paymentSession.session_id, demo: true },
  })

  const malicious = await createDemoAgent({
    name: 'Malicious Fake Agent',
    capability: createCapabilityDescriptor({ id: 'calendar.schedule', riskLevel: 'low', requiredScopes: ['calendar:write'] }),
    publisher: publisher.identity as PublisherIdentity,
  })
  const incident = createIncidentRecordV2({
    reporter: principal.identity.did,
    targetAgentId: malicious.card.identity.did,
    severity: 'critical',
    category: 'unauthorized_action',
    description: 'Demo malicious agent attempted to launder a high-risk action through a low-risk capability.',
    evidenceRefs: [paymentDeniedEvidence.event_id],
  })
  localIncidentRecords.set(incident.id, incident)
  const maliciousReputation = computeCapabilityReputation({
    agentId: malicious.card.identity.did,
    publisherId: publisher.identity.did,
    capability: 'calendar.schedule',
    successfulInvocations: 0,
    failedInvocations: 3,
    incidentCount: 1,
    publisherWeight: 0.1,
    contextBoundaryMismatch: true,
  })
  localReputationRecords.set(localCapabilityKey(malicious.card.identity.did, 'calendar.schedule'), maliciousReputation)
  const revocation = createRevocationRecordV2({
    issuer: principal.identity.did,
    targetType: 'agent',
    targetId: malicious.card.identity.did,
    reason: 'Demo malicious behavior.',
    evidenceRefs: [incident.id],
  })
  localRevocationRecords.set(revocation.id, revocation)
  const revokedTrust = computeLocalTrustResult(malicious.card.identity.did, 'calendar.schedule')
  const revokedPolicy = evaluateFidesPolicy({
    principalId: principal.identity.did,
    requesterAgentId: requester.identity.did,
    targetAgentId: malicious.card.identity.did,
    capability: malicious.card.capabilities[0]!,
    trustResult: revokedTrust!,
    requestedScopes: ['calendar:write'],
    revocationActive: true,
    incidentsActive: true,
  })

  const evidenceValid = verifyEvidenceEventsV2(localEvidenceEvents)
  return {
    status: 'executed',
    mode: 'local-first',
    steps: fullDemoSteps,
    identities: {
      principal: principal.identity.did,
      publisher: publisher.identity.did,
      requester: requester.identity.did,
      calendar: calendar.card.identity.did,
      invoice: invoice.card.identity.did,
      payment: payment.card.identity.did,
      malicious: malicious.card.identity.did,
    },
    discovery: {
      local: calendarDiscovery,
      registry: { provider: 'registry', records: invoiceRegistryRecords, authorityGranted: false },
      dht: { provider: 'dht', ...paymentDhtPointers, authorityGranted: false },
      relay: { provider: 'relay', records: [relayRecord], authorityGranted: false },
    },
    verification: {
      agentCardsVerified: verifiedCards.every(Boolean),
      evidenceHashChainValid: evidenceValid,
      evidenceEventCount: localEvidenceEvents.length,
      evidenceExport: {
        format: 'json',
        lastHash: localEvidenceEvents.at(-1)?.event_hash ?? null,
      },
    },
    trust: {
      invoice: invoiceTrust,
      payment: paymentTrust,
      maliciousAfterIncident: revokedTrust,
    },
    reputation: {
      invoice: invoiceReputation,
      malicious: maliciousReputation,
    },
    policy: {
      invoice: invoicePolicy,
      paymentWithoutAttestation: paymentPolicyWithoutAttestation,
      paymentWithAttestation: paymentPolicy,
      revokedMalicious: revokedPolicy,
    },
    sessions: {
      invoice: invoiceSession,
      paymentDryRun: paymentSession,
    },
    invocation: {
      invoice: {
        preflight: invoicePreflight,
        evidenceRefs: [invoiceSessionEvidence.event_id, invoiceInvokeEvidence.event_id, invoiceCompleteEvidence.event_id],
      },
      paymentDryRun: {
        preflight: paymentDryRunPreflight,
        evidenceRefs: [paymentDryRunEvidence.event_id],
      },
    },
    governance: {
      incident,
      revocation,
    },
    authority: {
      discoveryGrantsAuthority: false,
      identityEqualsTrust: false,
      trustScoreEqualsPermission: false,
      policyBeforeExecution: true,
      evidenceProduced: localEvidenceEvents.length > 0,
    },
    surfaces: {
      local: true,
      registry: 'local_mock',
      relay: 'local_mock',
      dht: 'in_memory_pointer_records',
      payments: 'dry_run_only',
    },
    limitations: [
      'Uses local mock services for DHT, relay, and registry flows.',
      'Payment execution remains Sardis-specific and is not executed by FIDES.',
      'Demo state is held in the current daemon process.',
    ],
  }
}

app.post('/demo/run', async (c) => {
  const result = await runLocalFullDemo()
  return c.json({
    ...result,
  })
})

async function runLocalAdversarialSimulation() {
  const principal = await createLocalIdentity('principal', { name: 'Simulation Principal' })
  const publisher = await createLocalIdentity('publisher', { name: 'Simulation Publisher' })
  const requester = await createLocalIdentity('agent', { name: 'Simulation Requester' })
  localIdentities.set(principal.identity.did, principal)
  localIdentities.set(publisher.identity.did, publisher)
  localIdentities.set(requester.identity.did, requester)

  const capability = createCapabilityDescriptor({
    id: 'payments.execute',
    riskLevel: 'critical',
    requiredScopes: ['payments:execute'],
    supportedControls: ['human_approval', 'runtime_attestation', 'policy_proof'],
    supportsHumanApproval: true,
    supportsPolicyProof: true,
  })
  const launderingCapability = createCapabilityDescriptor({
    id: 'calendar.schedule',
    riskLevel: 'low',
    requiredScopes: ['calendar:write'],
    supportedControls: ['dry_run'],
    supportsDryRun: true,
  })
  const malicious = await createDemoAgent({
    name: 'Adversarial Payment Agent',
    capability,
    publisher: publisher.identity as PublisherIdentity,
  })

  const scenarioEvents: Record<string, string> = {}
  const recordScenario = (
    name: string,
    decision: string,
    evidenceInput: Omit<EvidenceEventV2Input, 'type' | 'actor' | 'subject' | 'principal' | 'capability' | 'decision' | 'privacy_mode' | 'metadata'>
  ) => {
    const event = appendRootEvidence({
      type: 'policy.evaluated',
      actor: requester.identity.did,
      subject: malicious.card.identity.did,
      principal: principal.identity.did,
      capability: capability.id,
      decision,
      privacy_mode: 'hash_only',
      metadata: { simulation: 'adversarial', scenario: name },
      ...evidenceInput,
    })
    scenarioEvents[name] = event.event_id
    return event
  }

  const fakeAgentTrust = computeTrustResult({
    agentId: 'did:fides:fake-agent',
    capability,
    components: {
      identity: 0,
      publisher: 0,
      trustAnchors: 0,
      capabilityFit: 0.2,
      evidence: 0,
      policyCompliance: 0,
      runtimeSafety: 0,
      peerAttestation: 0,
      incidentPenalty: 0.4,
      noveltyPenalty: 1,
      contextBoundaryPenalty: 0.5,
    },
  })
  const fakeAgentPolicy = evaluateFidesPolicy({
    principalId: principal.identity.did,
    requesterAgentId: requester.identity.did,
    targetAgentId: 'did:fides:fake-agent',
    capability,
    trustResult: fakeAgentTrust,
    requestedScopes: ['payments:execute'],
  })
  recordScenario('fake_agent', fakeAgentPolicy.decision, { policy: fakeAgentPolicy, risk_level: capability.riskLevel })

  const fakePublisherReputation = computeCapabilityReputation({
    agentId: malicious.card.identity.did,
    publisherId: 'did:fides:fake-publisher',
    capability: capability.id,
    successfulInvocations: 0,
    failedInvocations: 2,
    incidentCount: 1,
    publisherWeight: 0,
  })
  const fakePublisherTrust = computeTrustResult({
    agentId: malicious.card.identity.did,
    capability,
    components: {
      identity: 0.8,
      publisher: 0,
      trustAnchors: 0,
      capabilityFit: 0.7,
      evidence: 0.1,
      policyCompliance: 0.1,
      runtimeSafety: 0,
      peerAttestation: 0,
      incidentPenalty: fakePublisherReputation.incident_count,
      noveltyPenalty: 0.8,
      contextBoundaryPenalty: 0,
    },
  })
  recordScenario('fake_publisher', 'trust_penalty', { output: fakePublisherTrust, risk_level: capability.riskLevel })

  const validPointer = await signDHTPointerRecord(createDHTPointerRecord({
    capability: capability.id,
    agentId: malicious.card.identity.did,
    agentCardUrl: `local://agent-cards/${malicious.card.id}`,
    agentCardHash: hashAgentCard(malicious.card),
    publisherId: publisher.identity.did,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  }), Buffer.from(publisher.privateKeyHex, 'hex'), publisher.identity.did)
  const maliciousPointer = { ...validPointer, capability: 'payments.refund' }
  const maliciousPointerResult = await verifyDHTPointerRecord(maliciousPointer, {
    card: malicious.card,
    verificationMethod: publisher.identity.did,
  })
  recordScenario('malicious_dht_pointer', maliciousPointerResult.valid ? 'accepted' : 'rejected', {
    output: maliciousPointerResult,
    risk_level: capability.riskLevel,
  })

  const tamperedSignedCard: SignedAgentCard = {
    ...malicious.signed,
    payload: {
      ...malicious.signed.payload,
      capabilities: [createCapabilityDescriptor({
        id: 'payments.execute',
        riskLevel: 'critical',
        requiredScopes: [],
      })],
    },
  }
  const tamperedAgentCardValid = await verifySignedAgentCard(tamperedSignedCard)
  recordScenario('tampered_agent_card', tamperedAgentCardValid ? 'accepted' : 'signature_rejected', {
    output: { valid: tamperedAgentCardValid },
    risk_level: capability.riskLevel,
  })

  const expiredRuntimeAttestation = await runtimeAttestationProvider.issue({
    agentId: malicious.card.identity.did,
    codeHash: `sha256:${'1'.repeat(64)}`,
    runtimeHash: `sha256:${'2'.repeat(64)}`,
    policyHash: `sha256:${'3'.repeat(64)}`,
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
  })
  const expiredRuntimeAttestationValid = await runtimeAttestationProvider.verify(expiredRuntimeAttestation)
  const expiredAttestationPolicy = evaluateFidesPolicy({
    principalId: principal.identity.did,
    requesterAgentId: requester.identity.did,
    targetAgentId: malicious.card.identity.did,
    capability,
    trustResult: computeLocalTrustResult(malicious.card.identity.did, capability.id)!,
    requestedScopes: ['payments:execute'],
    runtimeAttestationValid: expiredRuntimeAttestationValid,
  })
  recordScenario('expired_runtime_attestation', expiredAttestationPolicy.decision, {
    policy: expiredAttestationPolicy,
    output: { valid: expiredRuntimeAttestationValid, attestation_id: expiredRuntimeAttestation.attestation_id },
    risk_level: capability.riskLevel,
  })

  const revocation = createRevocationRecordV2({
    issuer: principal.identity.did,
    targetType: 'agent',
    targetId: malicious.card.identity.did,
    reason: 'Adversarial simulation revoked malicious agent.',
    evidenceRefs: [scenarioEvents.tampered_agent_card],
  })
  localRevocationRecords.set(revocation.id, revocation)
  const revokedPolicy = evaluateFidesPolicy({
    principalId: principal.identity.did,
    requesterAgentId: requester.identity.did,
    targetAgentId: malicious.card.identity.did,
    capability,
    trustResult: computeLocalTrustResult(malicious.card.identity.did, capability.id)!,
    requestedScopes: ['payments:execute'],
    revocationActive: true,
  })
  recordScenario('revoked_agent', revokedPolicy.decision, {
    policy: revokedPolicy,
    output: revocation,
    risk_level: capability.riskLevel,
  })

  const collusiveTrust = computeTrustResult({
    agentId: malicious.card.identity.did,
    capability,
    components: {
      identity: 0.2,
      publisher: 0.1,
      trustAnchors: 0,
      capabilityFit: 0.4,
      evidence: 0,
      policyCompliance: 0,
      runtimeSafety: 0,
      peerAttestation: 1,
      incidentPenalty: 0.5,
      noveltyPenalty: 0.7,
      contextBoundaryPenalty: 0.2,
    },
  })
  recordScenario('collusive_trust_attestations', 'peer_signal_downweighted', {
    output: collusiveTrust,
    risk_level: capability.riskLevel,
  })

  const contextReputation = computeCapabilityReputation({
    agentId: malicious.card.identity.did,
    publisherId: publisher.identity.did,
    capability: launderingCapability.id,
    successfulInvocations: 4,
    failedInvocations: 3,
    incidentCount: 1,
    publisherWeight: 0.1,
    contextBoundaryMismatch: true,
  })
  const contextTrust = computeTrustResult({
    agentId: malicious.card.identity.did,
    capability: launderingCapability,
    components: {
      identity: 0.8,
      publisher: 0.2,
      trustAnchors: 0.1,
      capabilityFit: 0.3,
      evidence: contextReputation.score,
      policyCompliance: 0.1,
      runtimeSafety: 0.2,
      peerAttestation: 0.1,
      incidentPenalty: 0.4,
      noveltyPenalty: 0.2,
      contextBoundaryPenalty: contextReputation.context_boundary_penalty,
    },
  })
  recordScenario('context_laundering', 'context_boundary_penalty', {
    output: { reputation: contextReputation, trust: contextTrust },
    risk_level: launderingCapability.riskLevel,
  })

  const highRiskPolicy = evaluateFidesPolicy({
    principalId: principal.identity.did,
    requesterAgentId: requester.identity.did,
    targetAgentId: malicious.card.identity.did,
    capability,
    trustResult: computeTrustResult({
      agentId: malicious.card.identity.did,
      capability,
      components: {
        identity: 1,
        publisher: 0.8,
        trustAnchors: 0.8,
        capabilityFit: 1,
        evidence: 0.8,
        policyCompliance: 0.8,
        runtimeSafety: 0.2,
        peerAttestation: 0.4,
        incidentPenalty: 0,
        noveltyPenalty: 0,
        contextBoundaryPenalty: 0,
      },
    }),
    requestedScopes: ['payments:execute'],
  })
  recordScenario('high_risk_capability_abuse', highRiskPolicy.decision, {
    policy: highRiskPolicy,
    risk_level: capability.riskLevel,
  })

  const firstEvidence = createEvidenceEventV2({
    type: 'capability.invoked',
    actor: requester.identity.did,
    subject: malicious.card.identity.did,
    principal: principal.identity.did,
    capability: capability.id,
    input: { amount: 1000 },
    privacy_mode: 'hash_only',
  }, '0')
  const brokenEvidence = {
    ...createEvidenceEventV2({
      type: 'capability.completed',
      actor: malicious.card.identity.did,
      subject: requester.identity.did,
      principal: principal.identity.did,
      capability: capability.id,
      output: { status: 'forged' },
      privacy_mode: 'hash_only',
    }, firstEvidence.event_hash),
    prev_event_hash: 'sha256:forged-previous',
  }
  const brokenEvidenceChainValid = verifyEvidenceEventsV2([firstEvidence, brokenEvidence])
  recordScenario('broken_evidence_chain', brokenEvidenceChainValid ? 'verified' : 'evidence_verification_failed', {
    output: { valid: brokenEvidenceChainValid },
    risk_level: capability.riskLevel,
  })

  const incident = createIncidentRecordV2({
    reporter: principal.identity.did,
    targetAgentId: malicious.card.identity.did,
    severity: 'critical',
    category: 'unauthorized_action',
    description: 'Agent attempted to launder payment execution as a low-risk calendar action.',
    evidenceRefs: Object.values(scenarioEvents),
  })
  localIncidentRecords.set(incident.id, incident)
  const incidentEvidence = appendRootEvidence({
    type: 'incident.reported',
    actor: principal.identity.did,
    subject: malicious.card.identity.did,
    principal: principal.identity.did,
    capability: capability.id,
    decision: 'reported',
    risk_level: capability.riskLevel,
    privacy_mode: 'hash_only',
    metadata: { simulation: 'adversarial', incident_id: incident.id },
  })

  const preflight = evaluateInvocationPreflight({
    request: {
      schema_version: 'fides.invocation.request.v1',
      id: 'inv_req_malicious',
      issuer: requester.identity.did,
      subject: malicious.card.identity.did,
      session_id: 'missing-session',
      requester_agent_id: requester.identity.did,
      target_agent_id: malicious.card.identity.did,
      principal_id: principal.identity.did,
      capability: capability.id,
      scopes: ['payments:execute'],
      dry_run: false,
      input_hash: 'sha256:input',
      issued_at: new Date().toISOString(),
      payload_hash: 'sha256:payload',
    },
    policyDecision: revokedPolicy,
  })

  const scenarios = [
    { name: 'fake_agent', detected: fakeAgentPolicy.decision === 'risk_limit' || fakeAgentPolicy.decision === 'dry_run_only', outcome: 'policy_limited', evidenceRef: scenarioEvents.fake_agent, policy: fakeAgentPolicy, trust: fakeAgentTrust },
    { name: 'fake_publisher', detected: fakePublisherTrust.band === 'unknown' || fakePublisherTrust.band === 'low', outcome: 'trust_penalty', evidenceRef: scenarioEvents.fake_publisher, reputation: fakePublisherReputation, trust: fakePublisherTrust },
    { name: 'malicious_dht_pointer', detected: !maliciousPointerResult.valid, outcome: 'pointer_rejected', evidenceRef: scenarioEvents.malicious_dht_pointer, errors: maliciousPointerResult.errors },
    { name: 'tampered_agent_card', detected: !tamperedAgentCardValid, outcome: 'signature_rejected', evidenceRef: scenarioEvents.tampered_agent_card },
    { name: 'expired_runtime_attestation', detected: !expiredRuntimeAttestationValid && expiredAttestationPolicy.decision === 'require_approval', outcome: 'approval_required_or_denied', evidenceRef: scenarioEvents.expired_runtime_attestation, policy: expiredAttestationPolicy },
    { name: 'revoked_agent', detected: revokedPolicy.decision === 'deny', outcome: 'revocation_denied', evidenceRef: scenarioEvents.revoked_agent, policy: revokedPolicy },
    { name: 'collusive_trust_attestations', detected: collusiveTrust.band === 'unknown' || collusiveTrust.band === 'low', outcome: 'peer_signal_downweighted', evidenceRef: scenarioEvents.collusive_trust_attestations, trust: collusiveTrust },
    { name: 'context_laundering', detected: contextTrust.risk_flags.includes('context_boundary'), outcome: 'context_boundary_penalty', evidenceRef: scenarioEvents.context_laundering, reputation: contextReputation, trust: contextTrust },
    { name: 'high_risk_capability_abuse', detected: highRiskPolicy.decision === 'require_approval', outcome: 'approval_required', evidenceRef: scenarioEvents.high_risk_capability_abuse, policy: highRiskPolicy },
    { name: 'broken_evidence_chain', detected: !brokenEvidenceChainValid, outcome: 'evidence_verification_failed', evidenceRef: scenarioEvents.broken_evidence_chain },
  ]

  return {
    status: scenarios.every(scenario => scenario.detected) ? 'detected' : 'partial',
    mode: 'local-first',
    detections: scenarios.map(scenario => scenario.name),
    scenarios,
    incident,
    revocation,
    preflight,
    evidence: {
      scenarioEvents,
      incidentEvidenceRef: incidentEvidence.event_id,
      rootChainValid: verifyEvidenceEventsV2(localEvidenceEvents),
      rootEventCount: localEvidenceEvents.length,
      brokenEvidenceChainValid,
    },
    authority: {
      discoveryGrantsAuthority: false,
      policyBeforeExecution: true,
      evidenceProduced: Object.keys(scenarioEvents).length === scenarios.length,
    },
    limitations: [
      'Simulation uses local daemon state and mock provider primitives.',
      'DHT, relay, and registry transport behavior is not networked in this harness.',
    ],
  }
}

app.post('/simulate/adversarial', async (c) => {
  const result = await runLocalAdversarialSimulation()
  return c.json(result)
})

// ─── Identity Resolution (proxy to discovery) ─────────────────────
app.get('/v1/identities/domain/verify', async (c) => {
  const domain = c.req.query('domain')
  const did = c.req.query('did')

  if (!domain || !did) {
    return c.json({ error: 'domain and did query parameters are required' }, 400)
  }

  const result = await verifyDomainDid({
    domain,
    did,
    resolver: resolveTxt,
  })

  return c.json(result, result.verified ? 200 : 422)
})

app.get('/v1/identities/:did', async (c) => {
  const did = c.req.param('did')
  try {
    const resp = await fetch(`${DISCOVERY_URL}/v1/identities/${encodeURIComponent(did)}`)
    if (resp.ok) {
      const data = await resp.json()
      return c.json({ did, status: 'resolved', data })
    }
    return c.json({ did, status: 'not-found' }, 404)
  } catch {
    return c.json({ did, status: 'unreachable', service: DISCOVERY_URL }, 502)
  }
})

// ─── AgentCard (proxy to registry) ────────────────────────────────
app.get('/v1/cards/:did', async (c) => {
  const did = c.req.param('did')
  try {
    const resp = await fetch(`${REGISTRY_URL}/v1/cards/${encodeURIComponent(did)}`)
    if (resp.ok) {
      const card = await resp.json()
      return c.json({ did, card })
    }
    if (resp.status === 403) {
      return c.json({ did, card: null, error: 'private card - access denied' }, 403)
    }
    if (resp.status === 404) {
      return c.json({ did, card: null, error: 'not found' }, 404)
    }
    return c.json({ did, card: null, error: 'registry error' }, 502)
  } catch {
    return c.json({ did, card: null, error: 'registry unreachable' }, 502)
  }
})

// ─── Trust Score (proxy to trust-graph) ───────────────────────────
app.get('/v1/trust/:did/score', async (c) => {
  const did = c.req.param('did')
  try {
    const resp = await fetch(`${TRUST_GRAPH_URL}/v1/trust/${encodeURIComponent(did)}/score`)
    if (resp.ok) {
      const score = await resp.json()
      return c.json({ did, ...score })
    }
    return c.json({ did, score: 0.5, directTrusters: 0, transitiveTrusters: 0, source: 'default' })
  } catch {
    return c.json({ did, score: 0.5, directTrusters: 0, transitiveTrusters: 0, source: 'fallback' })
  }
})

// ─── Policy Evaluation (local) ────────────────────────────────────
app.post('/v1/policy/evaluate', async (c) => {
  const body = await c.req.json()
  if (!body.policy) {
    return c.json({
      decision: 'allow',
      matchedRules: [],
      explanation: {
        decision: 'No policy provided, default allow',
        factors: [],
      },
    })
  }

  const policy = body.policy as PolicyBundle
  const context = {
    ...(body.context ?? {}),
    agentDid: body.agentDid,
    capabilityId: body.capabilityId,
  }

  return c.json(evaluatePolicy(policy, context))
})

// ─── Delegation Sessions (local) ─────────────────────────────────
app.post('/v1/sessions', async (c) => {
  const body = await c.req.json()
  const signedToken = body.signedToken ?? (body.token?.payload && body.token?.proof ? body.token : undefined)
  if (signedToken) {
    const result = await authorizeDelegationV2({
      signedToken: signedToken as SignedDelegationTokenV2,
      store: authorityStore,
      capabilityId: body.capabilityId,
      audience: body.audience,
      boundTo: body.boundTo,
      ttlMs: body.ttlMs,
    })

    if (!result.ok) {
      return c.json({ authorized: false, errors: result.errors }, 409)
    }

    return c.json({
      authorized: true,
      session: redactSessionKey(result.session!),
      signedDelegationVerified: true,
    }, 201)
  }

  if (!body.token) {
    return c.json({ error: 'token or signedToken is required' }, 400)
  }

  const signatureErrors = await verifyOptionalSignature(
    body.delegatorPublicKey,
    async (publicKey) => verifyDelegationTokenSignature(body.token as DelegationToken, publicKey),
    'DelegationToken',
    authoritySignatureVerificationRequired()
  )
  if (signatureErrors.length > 0) {
    return c.json({ authorized: false, errors: signatureErrors }, 409)
  }

  const result = await authorizeDelegation({
    token: body.token as DelegationToken,
    store: authorityStore,
    capabilityId: body.capabilityId,
    audience: body.audience,
    boundTo: body.boundTo,
    ttlMs: body.ttlMs,
  })

  if (!result.ok) {
    return c.json({ authorized: false, errors: result.errors }, 409)
  }

  return c.json({ authorized: true, session: redactSessionKey(result.session!) }, 201)
})

app.get('/v1/sessions/:id', async (c) => {
  const session = await authorityStore.getSession(c.req.param('id'))
  if (!session) {
    return c.json({ error: 'session not found' }, 404)
  }
  return c.json({ session: redactSessionKey(session) })
})

app.post('/v1/sessions/:id/revoke', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const session = await authorityStore.revokeSession(c.req.param('id'), body.reason)
  if (!session) {
    return c.json({ error: 'session not found' }, 404)
  }
  return c.json({ revoked: true, session: redactSessionKey(session) })
})

// ─── Revocation and Incidents (local) ────────────────────────────
app.post('/v1/revocations', async (c) => {
  const body = await c.req.json()
  const record = body.record as RevocationRecord | undefined
  if (!isSignedRevocationRecord(record)) {
    return c.json({ error: 'signed revocation record is required' }, 400)
  }
  const signatureError = await verifyOptionalSignature(
    body.revokerPublicKey,
    async (publicKey) => verifyRevocationRecord(record, publicKey),
    'revocation',
    authoritySignatureVerificationRequired()
  )
  if (signatureError.length > 0) {
    return c.json({ error: signatureError.join('; ') }, 400)
  }

  await authorityStore.putRevocation(record)
  const propagation = await propagateRevocation(record)
  const outbox = await persistPropagationOutcome(record.did, 'revocation', record.id, propagation)

  return c.json({ revoked: true, record, propagation: propagationResponse(propagation, outbox) }, 201)
})

app.get('/v1/revocations/:did', async (c) => {
  const did = c.req.param('did')
  const record = await authorityStore.getRevocation(did)
  if (!record) {
    return c.json({ did, revoked: false })
  }
  return c.json({ did, revoked: true, record })
})

app.post('/v1/incidents', async (c) => {
  const body = await c.req.json()
  const record = body.record as IncidentRecord | undefined
  if (!isSignedIncidentRecord(record)) {
    return c.json({ error: 'signed incident record is required' }, 400)
  }
  const signatureError = await verifyOptionalSignature(
    body.reporterPublicKey,
    async (publicKey) => verifyIncidentRecord(record, publicKey),
    'incident',
    authoritySignatureVerificationRequired()
  )
  if (signatureError.length > 0) {
    return c.json({ error: signatureError.join('; ') }, 400)
  }

  await authorityStore.putIncident(record)
  const incidents = await authorityStore.listIncidents(record.actor)
  const propagation = await propagateIncident(record)
  const outbox = await persistPropagationOutcome(record.actor, 'incident', record.id, propagation)

  return c.json({ recorded: true, record, impact: aggregateIncidentImpact(incidents), propagation: propagationResponse(propagation, outbox) }, 201)
})

app.get('/v1/incidents/:did', async (c) => {
  const did = c.req.param('did')
  const incidents = await authorityStore.listIncidents(did)
  return c.json({ did, incidents, impact: aggregateIncidentImpact(incidents) })
})

app.get('/v1/authority/propagations/pending', async (c) => {
  const limit = parsePositiveInt(c.req.query('limit'), 25)
  const pending = await authorityStore.listPendingPropagations(new Date().toISOString(), limit)
  return c.json({ count: pending.length, propagations: pending })
})

app.post('/v1/authority/propagations/retry', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const limit = parsePositiveInt(body.limit, 25)
  const result = await retryPendingPropagations(limit)
  return c.json(result)
})

// ─── Unified Authorization (local) ───────────────────────────────
app.post('/v1/authorize', async (c) => {
  const body = await c.req.json()
  if (!body.agentDid || !body.capabilityId) {
    return c.json({ error: 'agentDid and capabilityId are required' }, 400)
  }

  const sessionResult = body.sessionId
    ? await authorizeSessionInvocation({
      sessionId: body.sessionId,
      store: authorityStore,
      capabilityId: body.capabilityId,
      audience: body.audience,
    })
    : null

  if (sessionResult && !sessionResult.ok) {
    await appendLocalEvidence(body.agentDid, 'authorization.denied', {
      capabilityId: body.capabilityId,
      errors: sessionResult.errors,
      source: 'session',
    })
    return c.json({ decision: 'deny', explanation: sessionResult.errors.join('; '), errors: sessionResult.errors }, 403)
  }

  const activeRevocation = await authorityStore.getRevocation(body.agentDid)
  const incidents = await authorityStore.listIncidents(body.agentDid)
  const impact = aggregateIncidentImpact(incidents)
  const policy = (body.policy ?? { id: 'default-agentd-policy', version: '1.0.0', rules: [], defaultAction: 'allow' }) as PolicyBundle
  const attestation = body.attestationValid
    ? await teeProvider.attest(body.agentDid)
    : null
  const scores = await resolveAuthorizationScores(body)
  if (!scores.ok) {
    await appendLocalEvidence(body.agentDid, 'authorization.denied', {
      capabilityId: body.capabilityId,
      explanation: scores.error,
      source: 'trust-graph',
    })
    return c.json({ decision: 'deny', explanation: scores.error, errors: [scores.error] }, 503)
  }

  const trust = createTrustContext({
    reputationScore: clampScore(scores.reputationScore - impact.totalReputationPenalty),
    capabilityScore: scores.capabilityScore,
    attestation,
    evidenceChain: await authorityStore.getEvidenceChain(body.agentDid),
    killSwitchEngaged: killSwitch.isEngaged({ type: 'global' }) || killSwitch.isEngaged({ type: 'agent', did: body.agentDid }) || killSwitch.isEngaged({ type: 'capability', id: body.capabilityId }),
    recentIncidents: impact.incidentCount,
    agentRevoked: Boolean(activeRevocation),
    sessionRevoked: sessionResult?.session?.revoked ?? false,
    revocationReason: activeRevocation?.reason ?? sessionResult?.session?.revocationReason,
    capabilityHighRisk: body.capabilityHighRisk ?? impact.allRevokedCapabilities.includes(body.capabilityId),
    requiresRuntimeAttestation: body.requiresRuntimeAttestation ?? false,
    requiresApproval: body.requiresApproval ?? false,
    approvalGranted: requestApprovalGranted(body),
  })

  const decision = await evaluateGuard({
    agentDid: body.agentDid,
    capabilityId: body.capabilityId,
    policy,
    context: body.context ?? {},
    trust,
  })

  await appendLocalEvidence(body.agentDid, `authorization.${decision.decision}`, {
    capabilityId: body.capabilityId,
    sessionId: body.sessionId,
    explanation: decision.explanation,
    factors: decision.factors,
  })

  return c.json({
    ...decision,
    session: sessionResult?.session ? redactSessionKey(sessionResult.session) : undefined,
    incidentImpact: impact,
    revoked: Boolean(activeRevocation),
  }, decision.decision === 'deny' ? 403 : 200)
})

// ─── Evidence Ledger (local) ──────────────────────────────────────
app.post('/v1/evidence', async (c) => {
  const body = await c.req.json()
  const did = body.actor || body.did
  if (!did) {
    return c.json({ error: 'actor or did is required' }, 400)
  }

  let chain = await authorityStore.getEvidenceChain(did) || createEvidenceChain()
  chain = appendEvidenceEvent(chain, {
    id: body.id || crypto.randomUUID(),
    type: body.type || 'custom',
    timestamp: new Date().toISOString(),
    actor: did,
    action: body.action || 'event',
    target: body.target,
    payload: body.payload || {},
    privacy: body.privacy || { level: 'public' },
  }, body.signature || 'local')

  await authorityStore.setEvidenceChain(did, chain)
  return c.json({ accepted: true, id: chain.events[chain.events.length - 1].hash }, 201)
})

app.get('/v1/evidence/:did', async (c) => {
  const did = c.req.param('did')
  const chain = await authorityStore.getEvidenceChain(did)
  if (!chain) {
    return c.json({ did, events: [], valid: true })
  }
  const valid = verifyEvidenceChain(chain)
  return c.json({ did, events: chain.events, count: chain.events.length, valid, merkleRoot: chain.merkleRoot })
})

app.get('/v1/evidence/:did/verify', async (c) => {
  const did = c.req.param('did')
  const chain = await authorityStore.getEvidenceChain(did)
  if (!chain) {
    return c.json({ did, valid: true, count: 0, merkleRoot: null, lastHash: null, checkedAt: new Date().toISOString() })
  }
  const lastEvent = chain.events.at(-1)
  return c.json({
    did,
    valid: verifyEvidenceChain(chain),
    count: chain.events.length,
    merkleRoot: chain.merkleRoot,
    lastHash: lastEvent?.hash ?? null,
    checkedAt: new Date().toISOString(),
  })
})

async function appendLocalEvidence(actor: string, action: string, payload: Record<string, unknown>) {
  let chain = await authorityStore.getEvidenceChain(actor) || createEvidenceChain()
  chain = appendEvidenceEvent(chain, {
    id: crypto.randomUUID(),
    type: 'authorization',
    timestamp: new Date().toISOString(),
    actor,
    action,
    payload,
    privacy: { level: 'private' },
  }, 'local-agentd')
  await authorityStore.setEvidenceChain(actor, chain)
}

async function appendPropagationEvidence(
  actor: string,
  recordType: AuthorityPropagationRecordType,
  recordId: string,
  propagation: PropagationResult
) {
  await appendLocalEvidence(actor, `authority.${recordType}.propagation.${propagation.ok ? 'confirmed' : 'failed'}`, {
    recordId,
    target: propagation.target,
    path: propagation.path,
    status: propagation.status,
    attemptedAt: propagation.attemptedAt,
    error: propagation.error,
  })
}

async function persistPropagationOutcome(
  actor: string,
  recordType: AuthorityPropagationRecordType,
  recordId: string,
  propagation: PropagationResult
): Promise<AuthorityPropagationRecord | null> {
  await appendPropagationEvidence(actor, recordType, recordId, propagation)
  if (propagation.ok) return null

  const now = propagation.attemptedAt
  const status = propagationStatusForFailure(propagation.status, 1, PROPAGATION_MAX_ATTEMPTS)
  const outbox: AuthorityPropagationRecord = {
    id: crypto.randomUUID(),
    actor,
    recordType,
    recordId,
    target: propagation.target,
    path: propagation.path,
    body: propagation.body,
    status,
    attempts: 1,
    maxAttempts: PROPAGATION_MAX_ATTEMPTS,
    nextAttemptAt: now,
    lastAttemptAt: now,
    lastStatus: propagation.status,
    lastError: propagation.error,
    createdAt: now,
    updatedAt: now,
  }
  await authorityStore.enqueuePropagation(outbox)
  return outbox
}

function propagationResponse(propagation: PropagationResult, outbox: AuthorityPropagationRecord | null) {
  return {
    attempted: propagation.attempted,
    ok: propagation.ok,
    status: propagation.status,
    target: propagation.target,
    path: propagation.path,
    attemptedAt: propagation.attemptedAt,
    error: propagation.error,
    queued: Boolean(outbox && outbox.status === 'pending'),
    outboxId: outbox?.id,
    attempts: outbox?.attempts ?? 1,
  }
}

function redactSessionKey<T extends { sessionKey: string }>(session: T): Omit<T, 'sessionKey'> & { sessionKey: string } {
  return { ...session, sessionKey: 'redacted' }
}

function clampScore(score: number): number {
  return Math.max(0, Math.min(1, score))
}

async function propagateRevocation(record: RevocationRecord) {
  return postToTrustGraph('/v1/revocations', {
    did: record.did,
    reason: record.reason,
    revokedBy: record.revokedBy,
    revokedAt: record.revokedAt,
    signature: record.signature,
    record,
  })
}

async function propagateIncident(record: IncidentRecord) {
  return postToTrustGraph('/v1/incidents', {
    actorDid: record.actor,
    reportedBy: record.reportedBy,
    type: record.type,
    severity: record.severity,
    description: record.description,
    evidenceRefs: record.evidenceRefs,
    trustPenalty: record.impact.trustPenalty,
    reputationPenalty: record.impact.reputationPenalty,
    capabilitiesRevoked: record.impact.capabilitiesRevoked,
    record,
  })
}

function isSignedRevocationRecord(record: RevocationRecord | undefined): record is RevocationRecord {
  return Boolean(
    record &&
    typeof record.id === 'string' &&
    typeof record.did === 'string' &&
    typeof record.reason === 'string' &&
    typeof record.revokedBy === 'string' &&
    typeof record.revokedAt === 'string' &&
    typeof record.signature === 'string' &&
    record.signature.length > 0 &&
    Array.isArray(record.propagatedTo)
  )
}

function isSignedIncidentRecord(record: IncidentRecord | undefined): record is IncidentRecord {
  return Boolean(
    record &&
    typeof record.id === 'string' &&
    typeof record.actor === 'string' &&
    typeof record.reportedBy === 'string' &&
    typeof record.type === 'string' &&
    typeof record.severity === 'string' &&
    typeof record.description === 'string' &&
    typeof record.reportedAt === 'string' &&
    typeof record.signature === 'string' &&
    record.signature.length > 0 &&
    Array.isArray(record.evidenceRefs) &&
    record.impact &&
    typeof record.impact.trustPenalty === 'number' &&
    typeof record.impact.reputationPenalty === 'number' &&
    Array.isArray(record.impact.capabilitiesRevoked)
  )
}

interface PropagationResult {
  attempted: true
  ok: boolean
  status: number
  target: string
  path: string
  body: Record<string, unknown>
  attemptedAt: string
  error?: string
}

async function postToTrustGraph(path: string, body: Record<string, unknown>): Promise<PropagationResult> {
  const attemptedAt = new Date().toISOString()
  try {
    const resp = await fetch(`${TRUST_GRAPH_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': propagationIdempotencyKey(path, body) },
      body: JSON.stringify(body),
    })
    return { attempted: true, ok: resp.ok, status: resp.status, target: TRUST_GRAPH_SERVICE_ID, path, body, attemptedAt }
  } catch (error) {
    return {
      attempted: true,
      ok: false,
      status: 0,
      target: TRUST_GRAPH_SERVICE_ID,
      path,
      body,
      attemptedAt,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

async function retryPendingPropagations(limit = 25) {
  const pending = await authorityStore.listPendingPropagations(new Date().toISOString(), limit)
  const results = []
  for (const record of pending) {
    const result = await postToTrustGraph(record.path, record.body)
    const attemptedAt = result.attemptedAt
    const nextAttemptAt = result.ok ? undefined : nextPropagationAttemptAt(record.attempts + 1, attemptedAt)
    const updated = await authorityStore.updatePropagationAttempt(record.id, {
      ok: result.ok,
      status: result.status,
      error: result.error,
      attemptedAt,
      nextAttemptAt,
    })
    await appendPropagationEvidence(record.actor, record.recordType, record.recordId, result)
    results.push({
      id: record.id,
      ok: result.ok,
      status: result.status,
      attempts: updated?.attempts,
      outboxStatus: updated?.status,
      nextAttemptAt: updated?.nextAttemptAt,
      error: result.error,
    })
  }
  return { attempted: results.length, results }
}

function propagationIdempotencyKey(path: string, body: Record<string, unknown>): string {
  const record = body.record as { id?: string } | undefined
  return `${TRUST_GRAPH_SERVICE_ID}:${path}:${record?.id ?? crypto.randomUUID()}`
}

function propagationStatusForFailure(status: number, attempts: number, maxAttempts: number): AuthorityPropagationStatus {
  if (attempts >= maxAttempts) return 'failed'
  if (status >= 400 && status < 500 && status !== 408 && status !== 409 && status !== 429) return 'failed'
  return 'pending'
}

function nextPropagationAttemptAt(attempts: number, from = new Date().toISOString()): string {
  const delayMs = Math.min(60_000, 1000 * 2 ** Math.max(0, attempts - 1))
  return new Date(new Date(from).getTime() + delayMs).toISOString()
}

function parsePositiveInt(value: unknown, fallback: number): number {
  const parsed = typeof value === 'number' ? value : parseInt(String(value ?? ''), 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

async function verifyOptionalSignature(
  publicKeyInput: unknown,
  verify: (publicKey: Uint8Array) => Promise<boolean>,
  label: string,
  required = false
): Promise<string[]> {
  if (publicKeyInput === undefined || publicKeyInput === null || publicKeyInput === '') {
    return required ? [`${label} public key is required`] : []
  }

  const publicKey = parsePublicKey(publicKeyInput)
  if (!publicKey) return [`${label} public key must be a 32-byte hex string or byte array`]

  const ok = await verify(publicKey)
  return ok ? [] : [`${label} signature verification failed`]
}

function parsePublicKey(input: unknown): Uint8Array | null {
  if (typeof input === 'string') {
    if (!/^[a-fA-F0-9]{64}$/.test(input)) return null
    return Uint8Array.from(Buffer.from(input, 'hex'))
  }

  if (Array.isArray(input) && input.length === 32 && input.every(isByte)) {
    return Uint8Array.from(input)
  }

  return null
}

function isByte(value: unknown): value is number {
  return Number.isInteger(value) && typeof value === 'number' && value >= 0 && value <= 255
}

function authoritySignatureVerificationRequired(): boolean {
  const configured = process.env.AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION
  if (configured === undefined || configured.trim() === '') {
    return process.env.NODE_ENV === 'production'
  }
  return parseBooleanEnv(configured)
}

function requestApprovalGranted(body: { approvalGranted?: unknown }): boolean {
  if (process.env.NODE_ENV === 'production') {
    return false
  }
  return body.approvalGranted === true
}

async function resolveAuthorizationScores(body: {
  agentDid: string
  capabilityId: string
  reputationScore?: unknown
  capabilityScore?: unknown
}): Promise<
  | { ok: true; reputationScore: number; capabilityScore?: number }
  | { ok: false; error: string }
> {
  if (process.env.NODE_ENV !== 'production') {
    return {
      ok: true,
      reputationScore: numericScore(body.reputationScore, 0.9),
      capabilityScore: optionalNumericScore(body.capabilityScore),
    }
  }

  try {
    const [reputation, capability] = await Promise.all([
      fetchTrustScore(`${TRUST_GRAPH_URL}/v1/trust/${encodeURIComponent(body.agentDid)}/score`, 'reputation'),
      fetchTrustScore(
        `${TRUST_GRAPH_URL}/v1/trust/${encodeURIComponent(body.agentDid)}/capability/${encodeURIComponent(body.capabilityId)}`,
        'capability'
      ),
    ])
    return {
      ok: true,
      reputationScore: reputation,
      capabilityScore: capability,
    }
  } catch (error) {
    return {
      ok: false,
      error: `Trust graph score lookup failed: ${error instanceof Error ? error.message : String(error)}`,
    }
  }
}

async function fetchTrustScore(url: string, label: string): Promise<number> {
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`${label} score returned HTTP ${response.status}`)
  }
  const body = await response.json() as { score?: unknown }
  if (typeof body.score !== 'number' || !Number.isFinite(body.score)) {
    throw new Error(`${label} score response is missing numeric score`)
  }
  return clampScore(body.score)
}

function numericScore(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? clampScore(value) : fallback
}

function optionalNumericScore(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? clampScore(value) : undefined
}

function parseBooleanEnv(value: string | undefined): boolean {
  return value === '1' || value?.toLowerCase() === 'true'
}

// ─── Runtime Attestation (local) ──────────────────────────────────
app.post('/v1/attest', async (c) => {
  const body = await c.req.json()
  const did = body.did || body.agentDid
  if (!did) {
    return c.json({ error: 'did or agentDid is required' }, 400)
  }
  const attestation = await teeProvider.attest(did)
  return c.json(attestation, 201)
})

// ─── Kill Switch (local) ──────────────────────────────────────────
app.get('/v1/killswitch/status', (c) => {
  const global = killSwitch.isEngaged({ type: 'global' })
  return c.json({ global })
})

app.post('/v1/killswitch/engage', async (c) => {
  const body = await c.req.json()
  if (body.global) {
    killSwitch.engage({ type: 'global' })
    return c.json({ engaged: true, scope: 'global' })
  }
  if (body.did) {
    killSwitch.engage({ type: 'agent', did: body.did })
    return c.json({ engaged: true, scope: 'agent', did: body.did })
  }
  if (body.capabilityId) {
    killSwitch.engage({ type: 'capability', id: body.capabilityId })
    return c.json({ engaged: true, scope: 'capability', id: body.capabilityId })
  }
  killSwitch.engage({ type: 'global' })
  return c.json({ engaged: true, scope: 'global' })
})

app.post('/v1/killswitch/disengage', async (c) => {
  const body = await c.req.json()
  if (body.global) {
    killSwitch.disengage({ type: 'global' })
    return c.json({ engaged: false, scope: 'global' })
  }
  if (body.did) {
    killSwitch.disengage({ type: 'agent', did: body.did })
    return c.json({ engaged: false, scope: 'agent', did: body.did })
  }
  if (body.capabilityId) {
    killSwitch.disengage({ type: 'capability', id: body.capabilityId })
    return c.json({ engaged: false, scope: 'capability', id: body.capabilityId })
  }
  killSwitch.disengageAll()
  return c.json({ engaged: false, scope: 'all' })
})

export { app }

// Start server only when not imported as module
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.AGENTD_PORT || '7345', 10)

  let inFlightRequests = 0
  let isShuttingDown = false

  const originalFetch = app.fetch
  const wrappedFetch: typeof originalFetch = async (req, ...args) => {
    if (isShuttingDown) {
      return new Response(JSON.stringify({ error: 'Service shutting down' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    inFlightRequests++
    try {
      return await originalFetch.call(app, req, ...args)
    } finally {
      inFlightRequests--
    }
  }

  console.log(`FIDES agentd starting on port ${port}`)

  const server = serve({
    fetch: wrappedFetch,
    port,
  })

  const shutdown = async () => {
    if (isShuttingDown) return
    isShuttingDown = true
    console.log('Shutting down agentd service...')

    const deadline = Date.now() + 10_000
    while (inFlightRequests > 0 && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 100))
    }

    if (inFlightRequests > 0) {
      console.warn(`Force closing with ${inFlightRequests} in-flight requests`)
    }

    server.close()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}
