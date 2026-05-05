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
import { rateLimitMiddleware, MetricsCollector, metricsMiddleware } from '@fides/sdk'
import { createEvidenceChain, appendEvidenceEvent, verifyEvidenceChain } from '@fides/evidence'
import { MockTEEProvider, InMemoryKillSwitch } from '@fides/runtime'
import { evaluatePolicy, type PolicyBundle } from '@fides/policy'
import { createTrustContext, evaluateGuard } from '@fides/guard'
import {
  aggregateIncidentImpact,
  authorizeDelegation,
  authorizeSessionInvocation,
  createIncidentRecord,
  createRevocationRecord,
  type DelegationToken,
} from '@fides/core'
import { createAuthorityStore } from './storage.js'
import { logger } from './middleware/logger.js'
import { securityHeaders } from './middleware/security.js'
import { errorHandler } from './middleware/error-handler.js'
import { apiKeyAuth } from './middleware/auth.js'

const app = new Hono()
const collector = new MetricsCollector()

const DISCOVERY_URL = process.env.DISCOVERY_URL || 'http://localhost:3100'
const TRUST_GRAPH_URL = process.env.TRUST_GRAPH_URL || 'http://localhost:3200'
const REGISTRY_URL = process.env.REGISTRY_URL || 'http://localhost:7346'

const teeProvider = new MockTEEProvider()
const killSwitch = new InMemoryKillSwitch()
const authorityStore = createAuthorityStore()

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
  const auth = apiKeyAuth()
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

  const [discovery, trustGraph, registry] = await Promise.all([
    probe(DISCOVERY_URL),
    probe(TRUST_GRAPH_URL),
    probe(REGISTRY_URL),
  ])

  const allOk = discovery.reachable && trustGraph.reachable && registry.reachable
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
    },
  }, allOk ? 200 : 503)
})

// ─── Identity Resolution (proxy to discovery) ─────────────────────
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
    return c.json({ did, card: null, error: 'not found' }, 404)
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
  if (!body.did || !body.reason || !body.revokedBy) {
    return c.json({ error: 'did, reason, and revokedBy are required' }, 400)
  }

  const record = {
    ...createRevocationRecord({
      did: body.did,
      reason: body.reason,
      revokedBy: body.revokedBy,
    }),
    signature: body.signature ?? 'local-agentd',
  }
  await authorityStore.putRevocation(record)

  return c.json({ revoked: true, record }, 201)
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
  if (!body.type || !body.severity || !body.actor || !body.description) {
    return c.json({ error: 'type, severity, actor, and description are required' }, 400)
  }

  const record = {
    ...createIncidentRecord(body),
    signature: body.signature ?? 'local-agentd',
  }
  await authorityStore.putIncident(record)
  const incidents = await authorityStore.listIncidents(record.actor)

  return c.json({ recorded: true, record, impact: aggregateIncidentImpact(incidents) }, 201)
})

app.get('/v1/incidents/:did', async (c) => {
  const did = c.req.param('did')
  const incidents = await authorityStore.listIncidents(did)
  return c.json({ did, incidents, impact: aggregateIncidentImpact(incidents) })
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

  const trust = createTrustContext({
    reputationScore: clampScore((body.reputationScore ?? 0.9) - impact.totalReputationPenalty),
    capabilityScore: body.capabilityScore,
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
    approvalGranted: body.approvalGranted ?? false,
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

function redactSessionKey<T extends { sessionKey: string }>(session: T): Omit<T, 'sessionKey'> & { sessionKey: string } {
  return { ...session, sessionKey: 'redacted' }
}

function clampScore(score: number): number {
  return Math.max(0, Math.min(1, score))
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
  killSwitch.disengage({ type: 'global' })
  killSwitch.disengage({ type: 'agent' })
  killSwitch.disengage({ type: 'capability' })
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
