/**
 * FIDES v2 Relay Service
 *
 * Mock relay server for agent discovery message routing.
 */

import { Hono } from 'hono'
import { serve } from '@hono/node-server'

const app = new Hono()

app.get('/health', (c) => c.json({ status: 'ok', service: 'relay' }))

app.post('/v1/relay', async (c) => {
  const body = await c.req.json<{ to: string; payload: unknown }>()
  // Stub: accept message, log it, return acceptance
  console.log(`Relay message to ${body.to}:`, body.payload)
  return c.json({ accepted: true, relayId: crypto.randomUUID() })
})

const port = Number(process.env.RELAY_PORT) || 7347
serve({ fetch: app.fetch, port })
console.log(`FIDES Relay running on port ${port}`)
