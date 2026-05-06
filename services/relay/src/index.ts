/**
 * FIDES v2 Relay Service
 *
 * Message relay for agents behind NAT/firewalls or with dynamic addresses.
 * Supports in-memory message queue with TTL, delivery tracking, and status queries.
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

const app = new Hono()
const collector = new MetricsCollector()

interface RelayMessage {
  id: string
  to: string
  from: string
  payload: unknown
  status: 'pending' | 'delivered' | 'expired'
  createdAt: string
  expiresAt: string
  deliveredAt?: string
}

const messages = new Map<string, RelayMessage>()
const queues = new Map<string, string[]>()
const DEFAULT_TTL_MS = 5 * 60 * 1000

const startTime = Date.now()

setInterval(() => {
  const now = Date.now()
  for (const [id, msg] of messages) {
    if (msg.status === 'pending' && new Date(msg.expiresAt).getTime() < now) {
      msg.status = 'expired'
    }
  }
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
app.get('/health', (c) => {
  let pending = 0
  let delivered = 0
  let expired = 0
  for (const msg of messages.values()) {
    if (msg.status === 'pending') pending++
    else if (msg.status === 'delivered') delivered++
    else if (msg.status === 'expired') expired++
  }

  return c.json({
    status: 'healthy',
    service: 'relay',
    uptime: Math.floor((Date.now() - startTime) / 1000),
    timestamp: new Date().toISOString(),
    queues: {
      total: messages.size,
      pending,
      delivered,
      expired,
      activeQueues: queues.size,
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

  messages.set(id, message)

  const queue = queues.get(body.to) || []
  queue.push(id)
  queues.set(body.to, queue)

  return c.json({ accepted: true, relayId: id, expiresAt: message.expiresAt }, 201)
})

/**
 * Get queue stats (must be before :param routes to avoid being captured).
 */
app.get('/v1/relay/stats', (c) => {
  let pending = 0
  let delivered = 0
  let expired = 0
  for (const msg of messages.values()) {
    if (msg.status === 'pending') pending++
    else if (msg.status === 'delivered') delivered++
    else if (msg.status === 'expired') expired++
  }
  return c.json({ total: messages.size, pending, delivered, expired, queues: queues.size })
})

/**
 * Poll for pending messages.
 */
app.get('/v1/relay/:did/messages', (c) => {
  const did = c.req.param('did')
  const queue = queues.get(did) || []
  const pending: RelayMessage[] = []

  for (const id of queue) {
    const msg = messages.get(id)
    if (msg && msg.status === 'pending') {
      msg.status = 'delivered'
      msg.deliveredAt = new Date().toISOString()
      pending.push(msg)
    }
  }

  queues.set(did, queue.filter(id => {
    const msg = messages.get(id)
    return msg && msg.status === 'pending'
  }))

  return c.json({ messages: pending, count: pending.length })
})

/**
 * Get status of a specific relay message.
 */
app.get('/v1/relay/:id', (c) => {
  const id = c.req.param('id')
  const msg = messages.get(id)
  if (!msg) {
    return c.json({ error: 'Not found' }, 404)
  }
  return c.json(msg)
})

/**
 * Delete a relay message.
 */
app.delete('/v1/relay/:id', (c) => {
  const id = c.req.param('id')
  const msg = messages.get(id)
  if (!msg) {
    return c.json({ error: 'Not found' }, 404)
  }
  messages.delete(id)
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

  console.log(`FIDES Relay starting on port ${port}`)

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
