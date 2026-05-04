/**
 * FIDES v2 Local Daemon (agentd)
 *
 * Provides a local HTTP API for the FIDES trust fabric.
 */

import { Hono } from 'hono'
import { serve } from '@hono/node-server'

const app = new Hono()

app.get('/health', (c) => c.json({ status: 'ok', service: 'agentd' }))

app.get('/v1/identities/:did', (c) => {
  const did = c.req.param('did')
  return c.json({ did, status: 'resolved' })
})

app.get('/v1/cards/:did', (c) => {
  const did = c.req.param('did')
  return c.json({ did, card: null })
})

app.get('/v1/trust/:did/score', (c) => {
  const did = c.req.param('did')
  return c.json({ did, score: 0.5, directTrusters: 0, transitiveTrusters: 0 })
})

app.post('/v1/policy/evaluate', async (c) => {
  const body = await c.req.json()
  return c.json({ decision: 'allow', matchedRules: [], explanation: { decision: 'default allow', factors: [] } })
})

app.post('/v1/evidence', async (c) => {
  const body = await c.req.json()
  return c.json({ accepted: true, id: crypto.randomUUID() })
})

app.get('/v1/evidence/:did', (c) => {
  return c.json({ events: [] })
})

app.get('/v1/killswitch/status', (c) => {
  return c.json({ engaged: false })
})

app.post('/v1/killswitch/engage', (c) => {
  return c.json({ engaged: true })
})

app.post('/v1/killswitch/disengage', (c) => {
  return c.json({ engaged: false })
})

const port = Number(process.env.AGENTD_PORT) || 7345
serve({ fetch: app.fetch, port })
console.log(`FIDES agentd running on port ${port}`)
