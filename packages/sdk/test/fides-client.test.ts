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

  it('uses the root identity API served by local agentd', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init })
      if (String(url).endsWith('/identities') && init?.method === 'GET') {
        return new Response(JSON.stringify({ identities: [{ did: 'did:fides:agent', type: 'agent' }] }), { status: 200 })
      }
      if (String(url).endsWith('/identities/did%3Afides%3Aagent')) {
        return new Response(JSON.stringify({ identity: { did: 'did:fides:agent' } }), { status: 200 })
      }
      return new Response(JSON.stringify({ identity: { did: 'did:fides:agent' } }), { status: 201 })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345', apiKey: 'sdk-key' })

    await expect(client.identity.createAgent({ name: 'Calendar Agent' })).resolves.toMatchObject({
      identity: { did: 'did:fides:agent' },
    })
    await expect(client.identity.list()).resolves.toMatchObject({
      identities: [{ did: 'did:fides:agent', type: 'agent' }],
    })
    await expect(client.identity.show('did:fides:agent')).resolves.toMatchObject({
      identity: { did: 'did:fides:agent' },
    })

    expect(calls.map(call => call.url)).toEqual([
      'http://localhost:7345/identities',
      'http://localhost:7345/identities',
      'http://localhost:7345/identities/did%3Afides%3Aagent',
    ])
    expect((calls[0].init?.headers as Headers).get('X-API-Key')).toBe('sdk-key')
  })

  it('uses the root AgentCard API served by local agentd', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init })
      if (String(url).endsWith('/agent-cards/card_1/sign')) {
        return new Response(JSON.stringify({ signed: { payload: { id: 'card_1' }, proof: {} } }), { status: 200 })
      }
      if (String(url).endsWith('/agent-cards/card_1/verify')) {
        return new Response(JSON.stringify({ valid: true }), { status: 200 })
      }
      if (String(url).endsWith('/agent-cards/card_1')) {
        return new Response(JSON.stringify({ card: { id: 'card_1' } }), { status: 200 })
      }
      return new Response(JSON.stringify({ card: { id: 'card_1' }, validation: { valid: true } }), { status: 201 })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })

    await expect(client.cards.create({ identity: { did: 'did:fides:agent' }, capabilities: [] })).resolves.toMatchObject({
      card: { id: 'card_1' },
    })
    await expect(client.cards.sign({ id: 'card_1' })).resolves.toMatchObject({
      signed: { payload: { id: 'card_1' } },
    })
    await expect(client.cards.verify('card_1')).resolves.toMatchObject({ valid: true })
    await expect(client.cards.get('card_1')).resolves.toMatchObject({ card: { id: 'card_1' } })

    expect(calls.map(call => call.url)).toEqual([
      'http://localhost:7345/agent-cards',
      'http://localhost:7345/agent-cards/card_1/sign',
      'http://localhost:7345/agent-cards/card_1/verify',
      'http://localhost:7345/agent-cards/card_1',
    ])
  })
})
