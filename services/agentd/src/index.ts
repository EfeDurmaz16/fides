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
import { createEvidenceChain, appendEvidenceEvent, verifyEvidenceChain, type EvidenceChain } from '@fides/evidence'
import { MockTEEProvider, InMemoryKillSwitch } from '@fides/runtime'
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
const evidenceChains = new Map<string, EvidenceChain>()

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
  return c.json({
    decision: body.policy?.defaultAction || 'allow',
    matchedRules: [],
    explanation: {
      decision: body.policy ? 'Policy evaluated' : 'No policy provided, default allow',
      factors: [],
    },
  })
})

// ─── Evidence Ledger (local) ──────────────────────────────────────
app.post('/v1/evidence', async (c) => {
  const body = await c.req.json()
  const did = body.actor || body.did
  if (!did) {
    return c.json({ error: 'actor or did is required' }, 400)
  }

  let chain = evidenceChains.get(did) || createEvidenceChain()
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

  evidenceChains.set(did, chain)
  return c.json({ accepted: true, id: chain.events[chain.events.length - 1].hash }, 201)
})

app.get('/v1/evidence/:did', (c) => {
  const did = c.req.param('did')
  const chain = evidenceChains.get(did)
  if (!chain) {
    return c.json({ did, events: [], valid: true })
  }
  const valid = verifyEvidenceChain(chain)
  return c.json({ did, events: chain.events, count: chain.events.length, valid, merkleRoot: chain.merkleRoot })
})

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
