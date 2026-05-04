/**
 * FIDES v2 Registry Service
 *
 * Hosted registry for AgentCards with public/private mode
 * and federation peering stubs.
 */

import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import type { AgentCard, SignedAgentCard } from '@fides/core'

const app = new Hono()

// In-memory store for demonstration
const registry = new Map<string, { card: SignedAgentCard; mode: 'public' | 'private'; peers: string[] }>()

app.get('/health', (c) => c.json({ status: 'ok', service: 'registry' }))

app.post('/v1/cards', async (c) => {
  const body = await c.req.json<SignedAgentCard>()
  const did = body.payload.id
  registry.set(did, { card: body, mode: 'public', peers: [] })
  return c.json({ success: true, did }, 201)
})

app.get('/v1/cards/:did', (c) => {
  const did = c.req.param('did')
  const entry = registry.get(did)
  if (!entry || entry.mode === 'private') {
    return c.json({ error: 'Not found' }, 404)
  }
  return c.json(entry.card.payload)
})

app.delete('/v1/cards/:did', (c) => {
  const did = c.req.param('did')
  registry.delete(did)
  return c.json({ success: true })
})

app.post('/v1/cards/:did/mode', async (c) => {
  const did = c.req.param('did')
  const { mode } = await c.req.json<{ mode: 'public' | 'private' }>()
  const entry = registry.get(did)
  if (!entry) return c.json({ error: 'Not found' }, 404)
  entry.mode = mode
  return c.json({ success: true, mode })
})

const port = Number(process.env.REGISTRY_PORT) || 7346
serve({ fetch: app.fetch, port })
console.log(`FIDES Registry running on port ${port}`)
