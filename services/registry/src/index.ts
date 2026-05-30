/**
 * FIDES v2 Registry Service
 *
 * Hosted registry for AgentCards with file-based persistence,
 * public/private mode, and search.
 */

import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { cors } from 'hono/cors'
import { bodyLimit } from 'hono/body-limit'
import { rateLimitMiddleware, MetricsCollector, metricsMiddleware } from '@fides/sdk'
import { verifySignedAgentCardIdentity, type SignedAgentCard } from '@fides/core'
import { logger } from './middleware/logger.js'
import { securityHeaders } from './middleware/security.js'
import { errorHandler } from './middleware/error-handler.js'
import { apiKeyAuth, registryScopeForRequest } from './middleware/auth.js'
import { createRegistryStore } from './storage.js'

const app = new Hono()
const collector = new MetricsCollector()
const registry = createRegistryStore()

type PublisherClaim = {
  did?: unknown
  domain?: unknown
  verified?: unknown
  verificationMethod?: unknown
  organization?: unknown
}

type OrganizationPublisherClaim = {
  did?: unknown
  domain?: unknown
  verified?: unknown
  verificationMethod?: unknown
}

type DiscoveryIdentityResponse = {
  did?: unknown
  domain?: unknown
  domainVerified?: unknown
  verificationMethod?: unknown
  organizationDomain?: unknown
  organizationDomainVerified?: unknown
  organizationVerificationMethod?: unknown
}

function isSignedAgentCard(value: unknown): value is SignedAgentCard {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const candidate = value as Partial<SignedAgentCard>
  return Boolean(candidate.payload && candidate.proof)
}

function reviveByteArray(value: unknown): Uint8Array | unknown {
  if (value instanceof Uint8Array) return value
  if (Array.isArray(value) && value.length === 32 && value.every(isByte)) {
    return Uint8Array.from(value)
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const entries = Object.entries(value as Record<string, unknown>)
    if (
      entries.length === 32 &&
      entries.every(([key, entry]) => /^\d+$/.test(key) && isByte(entry))
    ) {
      return Uint8Array.from(entries
        .sort(([a], [b]) => Number(a) - Number(b))
        .map(([, entry]) => entry as number))
    }
  }
  return value
}

function signedAgentCardForVerification(card: SignedAgentCard): SignedAgentCard {
  return {
    ...card,
    payload: {
      ...card.payload,
      identity: {
        ...card.payload.identity,
        publicKey: reviveByteArray(card.payload.identity.publicKey) as Uint8Array,
      },
    },
  }
}

function isByte(value: unknown): value is number {
  return Number.isInteger(value) && typeof value === 'number' && value >= 0 && value <= 255
}

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

function getDiscoveryUrl(): string {
  return (process.env.DISCOVERY_URL || 'http://localhost:7347').replace(/\/+$/, '')
}

function extractPublisherClaim(card: Record<string, unknown>): PublisherClaim | null {
  const payload = card.payload as Record<string, unknown> | undefined
  const publisher = card.publisher ?? payload?.publisher
  if (!publisher || typeof publisher !== 'object' || Array.isArray(publisher)) {
    return null
  }
  return publisher as PublisherClaim
}

function extractOrganizationPublisherClaim(publisher: PublisherClaim): OrganizationPublisherClaim | null {
  if (!publisher.organization || typeof publisher.organization !== 'object' || Array.isArray(publisher.organization)) {
    return null
  }
  return publisher.organization as OrganizationPublisherClaim
}

async function verifyPublisherClaim(card: Record<string, unknown>): Promise<{ ok: true } | { ok: false; status: 422; error: string }> {
  const publisher = extractPublisherClaim(card)
  if (!publisher) {
    return { ok: true }
  }

  if (publisher.verified === true) {
    if (publisher.verificationMethod !== 'dns') {
      return { ok: false, status: 422, error: 'verified publisher claims must use dns verification' }
    }
    if (typeof publisher.did !== 'string' || !publisher.did) {
      return { ok: false, status: 422, error: 'verified publisher claims require publisher.did' }
    }
    if (typeof publisher.domain !== 'string' || !publisher.domain) {
      return { ok: false, status: 422, error: 'verified publisher claims require publisher.domain' }
    }

    let response: Response
    try {
      response = await fetch(`${getDiscoveryUrl()}/identities/${encodeURIComponent(publisher.did)}`)
    } catch {
      return { ok: false, status: 422, error: 'publisher identity is not registered or not reachable in discovery' }
    }
    if (!response.ok) {
      return { ok: false, status: 422, error: 'publisher identity is not registered or not reachable in discovery' }
    }

    const identity = await response.json() as DiscoveryIdentityResponse
    if (
      identity.did !== publisher.did ||
      identity.domain !== publisher.domain ||
      identity.domainVerified !== true ||
      identity.verificationMethod !== 'dns'
    ) {
      return { ok: false, status: 422, error: 'publisher domain verification claim does not match discovery state' }
    }
  }

  const organization = extractOrganizationPublisherClaim(publisher)
  if (!organization || organization.verified !== true) {
    return { ok: true }
  }

  if (organization.verificationMethod !== 'dns') {
    return { ok: false, status: 422, error: 'verified publisher organization claims must use dns verification' }
  }
  if (typeof organization.did !== 'string' || !organization.did) {
    return { ok: false, status: 422, error: 'verified publisher organization claims require organization.did' }
  }
  if (typeof organization.domain !== 'string' || !organization.domain) {
    return { ok: false, status: 422, error: 'verified publisher organization claims require organization.domain' }
  }

  let response: Response
  try {
    response = await fetch(`${getDiscoveryUrl()}/identities/${encodeURIComponent(organization.did)}`)
  } catch {
    return { ok: false, status: 422, error: 'publisher organization identity is not registered or not reachable in discovery' }
  }
  if (!response.ok) {
    return { ok: false, status: 422, error: 'publisher organization identity is not registered or not reachable in discovery' }
  }

  const identity = await response.json() as DiscoveryIdentityResponse
  if (
    identity.did !== organization.did ||
    identity.organizationDomain !== organization.domain ||
    identity.organizationDomainVerified !== true ||
    identity.organizationVerificationMethod !== 'dns'
  ) {
    return { ok: false, status: 422, error: 'publisher organization verification claim does not match discovery state' }
  }

  return { ok: true }
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
  const auth = apiKeyAuth(registryScopeForRequest(c.req.method, new URL(c.req.url).pathname))
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
  const persistence = await registry.healthCheck()
  const stats = persistence.ok ? await registry.stats() : { total: 0, public: 0, private: 0 }

  const status = persistence.ok ? 'healthy' : 'degraded'
  return c.json({
    status,
    service: 'registry',
    count: stats.total,
    timestamp: new Date().toISOString(),
    checks: {
      persistence: persistence.ok ? 'ok' : 'fail',
      store: persistence,
    },
  }, persistence.ok ? 200 : 503)
})

/**
 * Register an AgentCard.
 */
app.post('/v1/cards', async (c) => {
  const body = await c.req.json()
  const did = body.id || body.payload?.id
  if (!did) {
    return c.json({ error: 'id is required' }, 400)
  }

  if (isSignedAgentCard(body) && !await verifySignedAgentCardIdentity(signedAgentCardForVerification(body))) {
    return c.json({ error: 'signed AgentCard proof must verify and match payload.identity.did' }, 422)
  }

  const publisherVerification = await verifyPublisherClaim(body)
  if (!publisherVerification.ok) {
    return c.json({ error: publisherVerification.error }, publisherVerification.status)
  }

  const now = new Date().toISOString()
  await registry.put(did, {
    card: body,
    mode: 'public',
    registeredAt: now,
    updatedAt: now,
    metadata: {},
  })

  return c.json({ success: true, did, registeredAt: now }, 201)
})

/**
 * Get an AgentCard by DID.
 */
app.get('/v1/cards/:did', async (c) => {
  const did = c.req.param('did')
  const entry = await registry.get(did)
  if (!entry) {
    return c.json({ error: 'Not found' }, 404)
  }
  if (entry.mode === 'private') {
    return c.json({ error: 'Private card — access denied' }, 403)
  }
  return c.json(entry.card)
})

/**
 * Search AgentCards.
 */
app.get('/v1/search', async (c) => {
  const query = c.req.query('q')?.toLowerCase() || ''
  const results: Array<{ did: string; name?: string; capabilities?: string[] }> = []

  for (const [did, entry] of await registry.list()) {
    if (entry.mode === 'private') continue

    const card = entry.card as Record<string, unknown>
    const payload = card.payload as Record<string, unknown> | undefined
    const name = ((card.name as string) || (payload?.name as string) || '') as string
    const capsRaw = (card.capabilities || payload?.capabilities || []) as unknown[]

    if (!query || name.toLowerCase().includes(query) || did.toLowerCase().includes(query)) {
      const capabilities: string[] = Array.isArray(capsRaw)
        ? capsRaw.map(c => typeof c === 'string' ? c : (c as Record<string, unknown>).id as string)
        : []
      results.push({ did, name, capabilities })
    }
  }

  return c.json({ results, count: results.length, query })
})

/**
 * Delete an AgentCard.
 */
app.delete('/v1/cards/:did', async (c) => {
  const did = c.req.param('did')
  const deleted = await registry.delete(did)
  if (!deleted) {
    return c.json({ error: 'Not found' }, 404)
  }
  return c.json({ success: true })
})

/**
 * Update visibility mode.
 */
app.post('/v1/cards/:did/mode', async (c) => {
  const did = c.req.param('did')
  const entry = await registry.get(did)
  if (!entry) return c.json({ error: 'Not found' }, 404)

  const { mode } = await c.req.json<{ mode: 'public' | 'private' }>()
  if (mode !== 'public' && mode !== 'private') {
    return c.json({ error: 'mode must be public or private' }, 400)
  }

  entry.mode = mode
  entry.updatedAt = new Date().toISOString()
  await registry.put(did, entry)

  return c.json({ success: true, mode })
})

/**
 * Update metadata.
 */
app.patch('/v1/cards/:did/metadata', async (c) => {
  const did = c.req.param('did')
  const entry = await registry.get(did)
  if (!entry) return c.json({ error: 'Not found' }, 404)

  const metadata = await c.req.json()
  entry.metadata = { ...entry.metadata, ...metadata }
  entry.updatedAt = new Date().toISOString()
  await registry.put(did, entry)

  return c.json({ success: true })
})

/**
 * Get registry stats.
 */
app.get('/v1/stats', async (c) => {
  return c.json(await registry.stats())
})

export { app }

// Start server only when not imported as module
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.REGISTRY_PORT || '7346', 10)

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

  console.log(`FIDES Registry starting on port ${port}`)

  const server = serve({
    fetch: wrappedFetch,
    port,
  })

  const shutdown = async () => {
    if (isShuttingDown) return
    isShuttingDown = true
    console.log('Shutting down registry service...')

    const deadline = Date.now() + 10_000
    while (inFlightRequests > 0 && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 100))
    }

    if (inFlightRequests > 0) {
      console.warn(`Force closing with ${inFlightRequests} in-flight requests`)
    }

    server.close()
    await registry.close?.()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}
