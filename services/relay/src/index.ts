/**
 * FIDES v2 Relay Service
 *
 * Message relay for agents behind NAT/firewalls or with dynamic addresses.
 * Supports message queueing with TTL, delivery tracking, and status queries.
 */

import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { cors } from 'hono/cors'
import { bodyLimit } from 'hono/body-limit'
import { rateLimitMiddleware, MetricsCollector, metricsMiddleware } from '@fides/sdk'
import { logger } from './middleware/logger.js'
import { securityHeaders } from './middleware/security.js'
import { errorHandler } from './middleware/error-handler.js'
import { apiKeyAuth, relayScopeForRequest } from './middleware/auth.js'
import { createRelayStore, type RelayMessage } from './storage.js'

const app = new Hono()
const collector = new MetricsCollector()

const relayStore = createRelayStore()
const DEFAULT_TTL_MS = 5 * 60 * 1000

const startTime = Date.now()

setInterval(() => {
  void relayStore.expirePending(Date.now())
}, 60000)

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
  const auth = apiKeyAuth(relayScopeForRequest(c.req.method, new URL(c.req.url).pathname))
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
  const stats = await relayStore.stats()
  return c.json({
    status: 'healthy',
    service: 'relay',
    store: relayStore.kind,
    uptime: Math.floor((Date.now() - startTime) / 1000),
    timestamp: new Date().toISOString(),
    queues: {
      total: stats.total,
      pending: stats.pending,
      delivered: stats.delivered,
      expired: stats.expired,
      activeQueues: stats.queues,
    },
  })
})

/**
 * Submit a message for relay.
 */
app.post('/v1/relay', async (c) => {
  const body = await c.req.json<{ to: string; from: string; payload: unknown; ttlMs?: number }>()
  if (!body.to || !body.payload) {
    return c.json({ error: 'to and payload are required' }, 400)
  }

  const id = crypto.randomUUID()
  const ttl = body.ttlMs ?? DEFAULT_TTL_MS
  const now = new Date()

  const message: RelayMessage = {
    id,
    to: body.to,
    from: body.from || 'anonymous',
    payload: body.payload,
    status: 'pending',
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttl).toISOString(),
  }

  await relayStore.put(message)

  return c.json({ accepted: true, relayId: id, expiresAt: message.expiresAt }, 201)
})

/**
 * Get queue stats (must be before :param routes to avoid being captured).
 */
app.get('/v1/relay/stats', async (c) => {
  return c.json(await relayStore.stats())
})

/**
 * Poll for pending messages.
 */
app.get('/v1/relay/:did/messages', async (c) => {
  const did = c.req.param('did')
  const pending = await relayStore.pollPending(did, new Date().toISOString())

  return c.json({ messages: pending, count: pending.length })
})

/**
 * Get status of a specific relay message.
 */
app.get('/v1/relay/:id', async (c) => {
  const id = c.req.param('id')
  const msg = await relayStore.get(id)
  if (!msg) {
    return c.json({ error: 'Not found' }, 404)
  }
  return c.json(msg)
})

/**
 * Delete a relay message.
 */
app.delete('/v1/relay/:id', async (c) => {
  const id = c.req.param('id')
  const deleted = await relayStore.delete(id)
  if (!deleted) {
    return c.json({ error: 'Not found' }, 404)
  }
  return c.json({ deleted: true })
})

export { app }

// Start server only when not imported as module
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.RELAY_PORT || '7347', 10)

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

  console.log(`FIDES Relay starting on port ${port} with ${relayStore.kind} store`)

  const server = serve({
    fetch: wrappedFetch,
    port,
  })

  const shutdown = async () => {
    if (isShuttingDown) return
    isShuttingDown = true
    console.log('Shutting down relay service...')

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
