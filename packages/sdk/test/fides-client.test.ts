import { afterEach, describe, expect, it, vi } from 'vitest'
import { FidesClient } from '../src/fides-client.js'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('FidesClient', () => {
  it('exposes promise-based identity, card, discovery, trust, session, and invocation namespaces', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init })
      return new Response(JSON.stringify({ ok: true, id: 'obj_1', agentId: 'did:fides:agent' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:4817' })

    await client.identity.createAgent()
    await client.cards.create({ name: 'Invoice Agent', capabilities: [] })
    await client.cards.sign({ id: 'card_1' })
    await client.agents.register({ id: 'card_1' })
    await client.discovery.find({ capability: 'invoice.reconcile' })
    await client.trust.evaluate({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    await client.sessions.request({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    await client.invoke({ sessionId: 'sess_1', input: { invoiceId: 'inv_123' } })

    expect(calls.map(call => call.url)).toEqual([
      'http://localhost:4817/identities',
      'http://localhost:4817/agent-cards',
      'http://localhost:4817/agent-cards/card_1/sign',
      'http://localhost:4817/agents/register',
      'http://localhost:4817/discover',
      'http://localhost:4817/trust/evaluate',
      'http://localhost:4817/sessions',
      'http://localhost:4817/invoke',
    ])
    expect(calls.every(call => call.init?.method === 'POST')).toBe(true)
  })
})
