/**
 * FIDES v2 Relay Service
 *
 * Message relay for agents behind NAT/firewalls or with dynamic addresses.
 * Supports in-memory message queue with TTL, delivery tracking, and status queries.
 */

import { Hono } from 'hono'
import { serve } from '@hono/node-server'

const app = new Hono()

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

// In-memory message store with TTL
const messages = new Map<string, RelayMessage>()
// Per-DID message queues
const queues = new Map<string, string[]>()
// Default TTL: 5 minutes
const DEFAULT_TTL_MS = 5 * 60 * 1000

// Cleanup expired messages every minute
setInterval(() => {
  const now = Date.now()
  for (const [id, msg] of messages) {
    if (msg.status === 'pending' && new Date(msg.expiresAt).getTime() < now) {
      msg.status = 'expired'
    }
  }
}, 60000)

app.get('/health', (c) => c.json({ status: 'ok', service: 'relay', queueSize: messages.size }))

/**
 * Submit a message for relay.
 * The message is stored and the recipient can poll for it.
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

  // Add to recipient's queue
  const queue = queues.get(body.to) || []
  queue.push(id)
  queues.set(body.to, queue)

  return c.json({ accepted: true, relayId: id, expiresAt: message.expiresAt }, 201)
})

/**
 * Poll for pending messages for a given DID.
 * Returns all pending messages and marks them as delivered.
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

  // Clear delivered from queue
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

/**
 * Get queue stats.
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

const port = Number(process.env.RELAY_PORT) || 7347
serve({ fetch: app.fetch, port })
console.log(`FIDES Relay running on port ${port}`)
