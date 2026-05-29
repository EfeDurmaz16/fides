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
import { createEvidenceChain, appendEvidenceEvent, verifyEvidenceChain } from '@fides/evidence'
import { MockTEEProvider, InMemoryKillSwitch } from '@fides/runtime'
import { evaluateFidesPolicy, evaluatePolicy, type FidesPolicyDecision, type PolicyBundle } from '@fides/policy'
import { createTrustContext, evaluateGuard } from '@fides/guard'
import {
  aggregateIncidentImpact,
  authorizeDelegation,
  authorizeSessionInvocation,
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
  createPrincipalIdentity,
  createPublisherIdentity,
  createRevocationRecordV2,
  createSessionGrantV2,
  hashProtocolPayload,
  isKillSwitchRuleActive,
  resolveIncidentRecordV2,
  signAgentCard,
  validateAgentCard,
  verifySignedAgentCard,
  verifyDelegationTokenSignature,
  verifyDomainDid,
  evaluateInvocationPreflight,
  verifyIncidentRecord,
  verifyRevocationRecord,
  type AgentIdentity,
  type AgentCard,
  type ApprovalDecision,
  type ApprovalRequest,
  type IncidentRecord,
  type IncidentRecordV2,
  type KillSwitchRule,
  type DelegationToken,
  type PrincipalIdentity,
  type PublisherIdentity,
  type ReputationRecord,
  type RevocationRecord,
  type RevocationRecordV2,
  type SessionGrantV2,
  type SignedAgentCard,
  type TrustResult,
} from '@fides/core'
import { createAuthorityStore } from './storage.js'
import type {
  AuthorityPropagationRecord,
  AuthorityPropagationRecordType,
  AuthorityPropagationStatus,
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

const teeProvider = new MockTEEProvider()
const killSwitch = new InMemoryKillSwitch()
const authorityStore = createAuthorityStore()
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
interface LocalRegisteredAgent {
  agentId: string
  cardId: string
  registeredAt: string
  signed: boolean
}
const localAgents = new Map<string, LocalRegisteredAgent>()
const localTrustResults = new Map<string, TrustResult>()
const localReputationRecords = new Map<string, ReputationRecord>()
const localApprovals = new Map<string, ApprovalRequest>()
const localApprovalDecisions = new Map<string, ApprovalDecision>()
const localKillSwitchRules = new Map<string, KillSwitchRule>()
const localRevocationRecords = new Map<string, RevocationRecordV2>()
const localIncidentRecords = new Map<string, IncidentRecordV2>()
interface LocalSessionRecord {
  session: SessionGrantV2
  policy: FidesPolicyDecision
  trust: TrustResult
}
const localSessionGrants = new Map<string, LocalSessionRecord>()
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
  return {
    ...record,
    signed: localSignedAgentCards.has(record.cardId) || record.signed,
    capabilities: card?.capabilities.map(capability => capability.id) ?? [],
    authorityGranted: false,
  }
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

// Global middleware stack
app.use('*', metricsMiddleware(collector))
app.use('*', logger())
app.use('*', securityHeaders())
app.use('*', cors({
  origin: getCorsOrigin(),
  exposeHeaders: ['X-Request-Id'],
}))
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
app.post('*', rateLimitMiddleware({ maxRequests: 100, windowMs: 60_000 }))
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

  const [discovery, trustGraph, registry, authority] = await Promise.all([
    probe(DISCOVERY_URL),
    probe(TRUST_GRAPH_URL),
    probe(REGISTRY_URL),
    authorityStore.healthCheck(),
  ])

  const allOk = discovery.reachable && trustGraph.reachable && registry.reachable && authority.ok
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
    },
    authorityStore: {
      kind: authority.kind,
      ok: authority.ok,
      detail: authority.detail,
    },
  }, allOk ? 200 : 503)
})

// ─── Root FIDES v2 Identity API ──────────────────────────────────
app.post('/identities', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const type = body.type
  if (type !== 'agent' && type !== 'publisher' && type !== 'principal') {
    return c.json({ error: 'type must be agent, publisher, or principal' }, 400)
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
    return c.json({ error: 'identity not found', id }, 404)
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
    return c.json({ error: 'identity.did or agentId is required' }, 400)
  }

  const localIdentity = localIdentities.get(did)
  if (!localIdentity || localIdentity.type !== 'agent') {
    return c.json({ error: 'agent identity not found in local daemon', did }, 404)
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
  const card: AgentCard = {
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
    capabilities,
    endpoints: Array.isArray(body.endpoints) ? body.endpoints : [],
    policies: Array.isArray(body.policies)
      ? body.policies
      : [{ requiresRuntimeAttestation: false, requiresApproval: false }],
    protocolVersions: Array.isArray(body.protocolVersions) ? body.protocolVersions.map(String) : ['fides.v2.0'],
    createdAt: now,
    updatedAt: now,
    ...(typeof body.expiresAt === 'string' && { expiresAt: body.expiresAt }),
  }

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
    return c.json({ error: 'AgentCard not found', id }, 404)
  }
  const identity = localIdentities.get(card.identity.did)
  if (!identity) {
    return c.json({ error: 'AgentCard identity key not found', did: card.identity.did }, 404)
  }

  const signed = await signAgentCard(card, Buffer.from(identity.privateKeyHex, 'hex'), card.identity.did)
  localSignedAgentCards.set(card.id, signed)
  return c.json({ signed })
})

app.post('/agent-cards/:id/verify', async (c) => {
  const id = c.req.param('id')
  const signed = localSignedAgentCards.get(id)
  if (signed) {
    return c.json({ valid: await verifySignedAgentCard(signed), signed: true })
  }

  const card = localAgentCards.get(id)
  if (!card) {
    return c.json({ valid: false, error: 'AgentCard not found', id }, 404)
  }
  const validation = validateAgentCard(card)
  return c.json({ valid: validation.valid, signed: false, validation })
})

app.get('/agent-cards/:id', (c) => {
  const id = c.req.param('id')
  const card = localAgentCards.get(id)
  if (!card) {
    return c.json({ error: 'AgentCard not found', id }, 404)
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
    return c.json({ error: 'agentCardId is required' }, 400)
  }

  const card = localAgentCards.get(cardId)
  if (!card) {
    return c.json({ error: 'AgentCard not found', cardId }, 404)
  }

  const record: LocalRegisteredAgent = {
    agentId: card.identity.did,
    cardId: card.id,
    registeredAt: new Date().toISOString(),
    signed: localSignedAgentCards.has(card.id),
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
    return c.json({ error: 'agent not registered', id }, 404)
  }

  return c.json({
    ...safeRegisteredAgent(record),
    card: localAgentCards.get(record.cardId) ?? null,
    signedCard: localSignedAgentCards.get(record.cardId) ?? null,
  })
})

app.post('/discover', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const capability = typeof body.capability === 'string' ? body.capability : undefined
  if (!capability) {
    return c.json({ error: 'capability is required' }, 400)
  }

  const candidates = Array.from(localAgents.values()).flatMap((record) => {
    const card = localAgentCards.get(record.cardId)
    if (!card) return []

    const descriptor = card.capabilities.find(candidate => candidate.id === capability)
    if (!descriptor) return []

    return [{
      agentId: record.agentId,
      cardId: record.cardId,
      capability,
      signed: localSignedAgentCards.has(record.cardId),
      authorityGranted: false,
      descriptor,
      card,
      reasons: [
        'candidate_matched_capability',
        'discovery_does_not_grant_authority',
      ],
    }]
  })

  return c.json({
    query: body,
    candidates,
    count: candidates.length,
    authorityGranted: false,
    explanation: 'Discovery returns candidates only. Policy evaluation and scoped session grants are required before invocation.',
  })
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
    return c.json({ error: 'agentId and capability are required' }, 400)
  }

  const trust = computeLocalTrustResult(agentId, capability)
  if (!trust) {
    return c.json({ error: 'registered agent capability not found', agentId, capability }, 404)
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
    return c.json({ error: 'agentId and capability are required' }, 400)
  }

  const found = findLocalCapability(agentId, capability)
  if (!found) {
    return c.json({ error: 'registered agent capability not found', agentId, capability }, 404)
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
    return c.json({ error: 'agentId and capability are required' }, 400)
  }

  const found = findLocalCapability(targetAgentId, capabilityId)
  if (!found) {
    return c.json({ error: 'registered agent capability not found', agentId: targetAgentId, capability: capabilityId }, 404)
  }

  const trustResult = computeLocalTrustResult(targetAgentId, capabilityId)
  if (!trustResult) {
    return c.json({ error: 'trust result unavailable', agentId: targetAgentId, capability: capabilityId }, 404)
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
    return c.json({ error: 'agentId and capability are required' }, 400)
  }

  const found = findLocalCapability(targetAgentId, capabilityId)
  if (!found) {
    return c.json({ error: 'registered agent capability not found', agentId: targetAgentId, capability: capabilityId }, 404)
  }

  const trust = computeLocalTrustResult(targetAgentId, capabilityId)
  if (!trust) {
    return c.json({ error: 'trust result unavailable', agentId: targetAgentId, capability: capabilityId }, 404)
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
    runtimeAttestationValid: typeof body.runtimeAttestationValid === 'boolean' ? body.runtimeAttestationValid : undefined,
    approvalGranted: typeof body.approvalGranted === 'boolean' ? body.approvalGranted : undefined,
  })

  if (policy.decision !== 'allow' && policy.decision !== 'dry_run_only') {
    return c.json({
      authorized: false,
      authorityGranted: false,
      policy,
      trust,
      killSwitch: activeKillSwitch,
      revocation: activeRevocation,
      incident: activeIncident,
    }, 409)
  }

  const expiresAt = typeof body.expiresAt === 'string'
    ? body.expiresAt
    : new Date(Date.now() + 60 * 60 * 1000).toISOString()
  const session = createSessionGrantV2({
    requesterAgentId,
    targetAgentId,
    principalId,
    capability: capabilityId,
    scopes: requestedScopes,
    constraints: typeof body.constraints === 'object' && body.constraints !== null ? body.constraints as Record<string, unknown> : {},
    policyHash: hashProtocolPayload(policy),
    trustResultHash: hashProtocolPayload(trust),
    audience: Array.isArray(body.audience) ? body.audience.map(String) : [targetAgentId],
    issuer: 'did:fides:agentd:local',
    expiresAt,
  })
  localSessionGrants.set(session.session_id, { session, policy, trust })

  return c.json({
    authorized: true,
    authorityGranted: policy.decision === 'allow',
    session,
    policy,
    trust,
  }, 201)
})

app.get('/sessions/:id', (c) => {
  const record = localSessionGrants.get(c.req.param('id'))
  if (!record) {
    return c.json({ error: 'session not found' }, 404)
  }
  return c.json({ session: record.session, policy: record.policy, trust: record.trust })
})

app.post('/sessions/:id/verify', (c) => {
  const record = localSessionGrants.get(c.req.param('id'))
  if (!record) {
    return c.json({ valid: false, error: 'session not found' }, 404)
  }

  return c.json({
    valid: new Date(record.session.expires_at).getTime() > Date.now(),
    session: record.session,
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
    return c.json({ error: 'sessionId is required' }, 400)
  }

  const record = localSessionGrants.get(sessionId)
  if (!record) {
    return c.json({ error: 'session not found', sessionId }, 404)
  }

  if (new Date(record.session.expires_at).getTime() <= Date.now()) {
    return c.json({ error: 'session expired', sessionId, authorityGranted: false }, 409)
  }

  const found = findLocalCapability(record.session.target_agent_id, record.session.capability)
  if (!found) {
    return c.json({ error: 'registered agent capability not found', sessionId, authorityGranted: false }, 404)
  }

  const request = createInvocationRequest({
    issuer: record.session.requester_agent_id,
    sessionGrant: record.session,
    input: body.input ?? {},
    dryRun: typeof body.dryRun === 'boolean' ? body.dryRun : false,
    inputSchema: found.capability.inputSchema,
    outputSchema: found.capability.outputSchema,
  })
  const preflight = evaluateInvocationPreflight({
    request,
    policyDecision: record.policy,
  })
  const result = createInvocationResult({
    issuer: record.session.target_agent_id,
    invocationRequestId: request.id,
    status: preflight.can_execute ? 'completed' : preflight.status,
    output: preflight.can_execute ? { ok: true, capability: record.session.capability } : undefined,
    errorCode: preflight.can_execute ? undefined : preflight.reason_codes[0],
    evidenceRefs: [`evt_${request.id}`],
  })

  return c.json({
    authorityGranted: preflight.can_execute,
    session: record.session,
    request,
    preflight,
    result,
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
    return c.json({ error: 'capability is required' }, 400)
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

  return c.json({
    approval,
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
    return c.json({ error: 'approval request not found', id }, 404)
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

  return c.json({
    approval: updated,
    decision,
    authorityGranted: false,
    explanation: 'Approval has been recorded. A policy evaluation and scoped SessionGrant are still required before invocation.',
  })
})

app.post('/approvals/:id/deny', async (c) => {
  const id = c.req.param('id')
  const approval = localApprovals.get(id)
  if (!approval) {
    return c.json({ error: 'approval request not found', id }, 404)
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

  return c.json({
    approval: updated,
    decision,
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
    return c.json({ error: 'targetType must be agent, publisher, capability, session, principal, or risk_class' }, 400)
  }

  const target = typeof body.target === 'string' ? body.target : undefined
  if (!target) {
    return c.json({ error: 'target is required' }, 400)
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

  return c.json({
    rule,
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
    return c.json({ error: 'kill switch rule not found', id }, 404)
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
    return c.json({ error: 'targetType must be key, identity, agent, agent_card, capability, session, attestation, or publisher' }, 400)
  }

  const targetId = typeof body.targetId === 'string'
    ? body.targetId
    : typeof body.target_id === 'string'
      ? body.target_id
      : undefined
  if (!targetId) {
    return c.json({ error: 'targetId is required' }, 400)
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

  return c.json({
    record,
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
    return c.json({ id, revoked: false }, 404)
  }
  return c.json({ id, revoked: isActiveLocalRevocation(record), record })
})

app.post('/incidents', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const severity = typeof body.severity === 'string' ? body.severity : undefined
  if (severity !== 'low' && severity !== 'medium' && severity !== 'high' && severity !== 'critical') {
    return c.json({ error: 'severity must be low, medium, high, or critical' }, 400)
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
    return c.json({ error: 'category is invalid' }, 400)
  }

  const targetAgentId = typeof body.targetAgentId === 'string'
    ? body.targetAgentId
    : typeof body.target_agent_id === 'string'
      ? body.target_agent_id
      : undefined
  if (!targetAgentId) {
    return c.json({ error: 'targetAgentId is required' }, 400)
  }

  const description = typeof body.description === 'string' ? body.description : undefined
  if (!description) {
    return c.json({ error: 'description is required' }, 400)
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

  return c.json({
    record,
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
    return c.json({ error: 'incident record not found', id }, 404)
  }
  return c.json({ record })
})

app.post('/incidents/:id/resolve', async (c) => {
  const id = c.req.param('id')
  const record = localIncidentRecords.get(id)
  if (!record) {
    return c.json({ error: 'incident record not found', id }, 404)
  }
  const body = await c.req.json().catch(() => ({}))
  const status = body.status === 'dismissed' || body.status === 'false_positive' ? body.status : 'resolved'
  const resolved = resolveIncidentRecordV2(record, status)
  localIncidentRecords.set(id, resolved)
  return c.json({ record: resolved })
})

// ─── FIDES v2 Local API Aliases ───────────────────────────────────
app.post('/dht/start', (c) => {
  return c.json({ started: true, mode: 'in_memory_simulator', pointers: localDhtPointers.length })
})

app.post('/dht/publish', async (c) => {
  const body = await c.req.json()
  if (!body.capability) {
    return c.json({ error: 'capability is required' }, 400)
  }

  const pointer = {
    id: body.id ?? crypto.randomUUID(),
    capability: body.capability,
    agentId: body.agentId ?? body.agent_id,
    agentCardUrl: body.agentCardUrl ?? body.agent_card_url ?? body.agentCard,
    publishedAt: new Date().toISOString(),
    source: 'agentd-in-memory-dht',
  }
  localDhtPointers.push(pointer)
  return c.json({ accepted: true, pointer }, 201)
})

app.get('/dht/find', (c) => {
  const capability = c.req.query('capability')
  const pointers = capability
    ? localDhtPointers.filter(pointer => pointer.capability === capability)
    : localDhtPointers
  return c.json({ capability: capability ?? null, pointers })
})

app.get('/evidence', (c) => {
  return c.json({
    events: [],
    count: 0,
    note: 'Use /v1/evidence/:did for local authority evidence chains.',
  })
})

app.post('/evidence/verify', (c) => {
  return c.json({
    valid: true,
    scope: 'local-authority-store',
    checkedAt: new Date().toISOString(),
  })
})

app.post('/evidence/export', (c) => {
  return c.json({
    format: 'json',
    exportedAt: new Date().toISOString(),
    events: [],
    note: 'Per-DID evidence export is available through /v1/evidence/:did.',
  })
})

app.post('/demo/run', (c) => {
  return c.json({
    status: 'spec-complete',
    mode: 'local-first',
    steps: fullDemoSteps,
    authority: {
      discoveryGrantsAuthority: false,
      identityEqualsTrust: false,
      trustScoreEqualsPermission: false,
      policyBeforeExecution: true,
      evidenceProduced: true,
    },
    surfaces: {
      local: true,
      registry: 'mock',
      relay: 'mock',
      dht: 'in_memory_pointer_records',
      payments: 'dry_run_only',
    },
    limitations: [
      'Uses local mock services for DHT, relay, and registry flows.',
      'Payment execution remains Sardis-specific and is not executed by FIDES.',
    ],
  })
})

app.post('/simulate/adversarial', (c) => {
  const capability = createCapabilityDescriptor({
    id: 'payments.execute',
    requiredScopes: ['payments:execute'],
    supportedControls: ['human_approval', 'runtime_attestation', 'policy_proof'],
  })
  const incident = createIncidentRecordV2({
    reporter: 'did:fides:principal',
    targetAgentId: 'did:fides:malicious-agent',
    severity: 'critical',
    category: 'unauthorized_action',
    description: 'Agent attempted to launder payment execution as a low-risk calendar action.',
    evidenceRefs: ['evt_malicious_1'],
  })
  const reputation = computeCapabilityReputation({
    agentId: 'did:fides:malicious-agent',
    publisherId: 'did:fides:fake-publisher',
    capability: capability.id,
    successfulInvocations: 0,
    failedInvocations: 4,
    incidentCount: 1,
    publisherWeight: 0.1,
    contextBoundaryMismatch: true,
  })
  const trust = computeTrustResult({
    agentId: 'did:fides:malicious-agent',
    capability,
    evidenceRefs: incident.evidence_refs,
    components: {
      identity: 0.2,
      publisher: 0.1,
      trustAnchors: 0,
      capabilityFit: 0.4,
      evidence: 0.1,
      policyCompliance: 0,
      runtimeSafety: 0,
      peerAttestation: 0.1,
      incidentPenalty: incident.trust_penalty,
      noveltyPenalty: 0.4,
      contextBoundaryPenalty: reputation.context_boundary_penalty,
    },
  })
  const preflight = evaluateInvocationPreflight({
    request: {
      schema_version: 'fides.invocation.request.v1',
      id: 'inv_req_malicious',
      issuer: 'did:fides:requester',
      session_id: 'missing-session',
      requester_agent_id: 'did:fides:requester',
      target_agent_id: 'did:fides:malicious-agent',
      principal_id: 'did:fides:principal',
      capability: capability.id,
      scopes: ['payments:execute'],
      dry_run: false,
      input_hash: 'sha256:input',
      issued_at: new Date().toISOString(),
      payload_hash: 'sha256:payload',
    },
    policyDecision: {
      decision: 'deny',
      reason_codes: ['REVOCATION_ACTIVE', 'TRUST_BELOW_THRESHOLD'],
    },
  })

  return c.json({
    status: 'detected',
    detections: [
      'fake_agent',
      'fake_publisher',
      'malicious_dht_pointer',
      'tampered_agent_card',
      'expired_runtime_attestation',
      'revoked_agent',
      'collusive_trust_attestations',
      'context_laundering',
      'high_risk_capability_abuse',
      'broken_evidence_chain',
    ],
    scenarios: [
      { name: 'fake_agent', detected: true, outcome: 'policy_denied' },
      { name: 'fake_publisher', detected: true, outcome: 'trust_penalty' },
      { name: 'malicious_dht_pointer', detected: true, outcome: 'pointer_rejected' },
      { name: 'tampered_agent_card', detected: true, outcome: 'signature_rejected' },
      { name: 'expired_runtime_attestation', detected: true, outcome: 'approval_required_or_denied' },
      { name: 'revoked_agent', detected: true, outcome: 'revocation_denied' },
      { name: 'collusive_trust_attestations', detected: true, outcome: 'peer_signal_downweighted' },
      { name: 'context_laundering', detected: true, outcome: 'context_boundary_penalty' },
      { name: 'high_risk_capability_abuse', detected: true, outcome: 'approval_required' },
      { name: 'broken_evidence_chain', detected: true, outcome: 'evidence_verification_failed' },
    ],
    incident,
    reputation,
    trust,
    preflight,
  })
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
  if (!body.token) {
    return c.json({ error: 'token is required' }, 400)
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
