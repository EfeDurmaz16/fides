/**
 * FIDES v2 Local Daemon (agentd)
 *
 * Provides a local HTTP API proxying to the FIDES trust fabric services.
 * Connects to discovery, trust-graph, and registry services.
 */

import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { createEvidenceChain, appendEvidenceEvent, verifyEvidenceChain, type EvidenceChain } from '@fides/evidence'
import { MockTEEProvider, InMemoryKillSwitch } from '@fides/runtime'

const app = new Hono()

// Service URLs
const DISCOVERY_URL = process.env.DISCOVERY_URL || 'http://localhost:3100'
const TRUST_GRAPH_URL = process.env.TRUST_GRAPH_URL || 'http://localhost:3101'
const REGISTRY_URL = process.env.REGISTRY_URL || 'http://localhost:7346'

// Local state
const teeProvider = new MockTEEProvider()
const killSwitch = new InMemoryKillSwitch()
const evidenceChains = new Map<string, EvidenceChain>()

// ─── Health ───────────────────────────────────────────────────────
app.get('/health', (c) => c.json({
  status: 'ok',
  service: 'agentd',
  discovery: DISCOVERY_URL,
  trustGraph: TRUST_GRAPH_URL,
  registry: REGISTRY_URL,
}))

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
  // For now, return a structured response. Real evaluation requires
  // @fides/policy which is available in the SDK layer.
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

const port = Number(process.env.AGENTD_PORT) || 7345
serve({ fetch: app.fetch, port })
console.log(`FIDES agentd running on port ${port}`)
