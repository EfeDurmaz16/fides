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
    await client.reputation.update({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    await client.policy.evaluate({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    await client.approvals.create({ agentId: 'did:fides:agent', capability: 'payments.prepare' })
    await client.approvals.list()
    await client.approvals.approve('approval_1', { approverId: 'did:fides:approver' })
    await client.approvals.deny('approval_1', { approverId: 'did:fides:approver' })
    await client.killSwitch.enable({ targetType: 'capability', target: 'deploy.preview' })
    await client.killSwitch.list()
    await client.killSwitch.disable('rule_1')
    await client.revocations.create({ targetType: 'agent', targetId: 'did:fides:agent' })
    await client.revocations.list()
    await client.revocations.get('rev_1')
    await client.incidents.report({ targetAgentId: 'did:fides:agent', severity: 'high', category: 'unauthorized_action', description: 'test' })
    await client.incidents.list()
    await client.incidents.get('inc_1')
    await client.incidents.resolve('inc_1', { status: 'resolved' })
    await client.sessions.request({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    await client.sessions.get('sess_1')
    await client.sessions.verify('sess_1')
    await client.invoke({ sessionId: 'sess_1', input: { invoiceId: 'inv_123' } })

    expect(calls.map(call => call.url)).toEqual([
      'http://localhost:4817/identities',
      'http://localhost:4817/agent-cards',
      'http://localhost:4817/agent-cards/card_1/sign',
      'http://localhost:4817/agents/register',
      'http://localhost:4817/discover',
      'http://localhost:4817/trust/evaluate',
      'http://localhost:4817/reputation/update',
      'http://localhost:4817/policy/evaluate',
      'http://localhost:4817/approvals',
      'http://localhost:4817/approvals',
      'http://localhost:4817/approvals/approval_1/approve',
      'http://localhost:4817/approvals/approval_1/deny',
      'http://localhost:4817/killswitch',
      'http://localhost:4817/killswitch',
      'http://localhost:4817/killswitch/rule_1',
      'http://localhost:4817/revocations',
      'http://localhost:4817/revocations',
      'http://localhost:4817/revocations/rev_1',
      'http://localhost:4817/incidents',
      'http://localhost:4817/incidents',
      'http://localhost:4817/incidents/inc_1',
      'http://localhost:4817/incidents/inc_1/resolve',
      'http://localhost:4817/sessions',
      'http://localhost:4817/sessions/sess_1',
      'http://localhost:4817/sessions/sess_1/verify',
      'http://localhost:4817/invoke',
    ])
    expect(calls.map(call => call.init?.method)).toEqual([
      'POST',
      'POST',
      'POST',
      'POST',
      'POST',
      'POST',
      'POST',
      'POST',
      'POST',
      'GET',
      'POST',
      'POST',
      'POST',
      'GET',
      'DELETE',
      'POST',
      'GET',
      'GET',
      'POST',
      'GET',
      'GET',
      'POST',
      'POST',
      'GET',
      'POST',
      'POST',
    ])
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

  it('uses root agent registration and discovery APIs served by local agentd', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init })
      if (String(url).endsWith('/agents/register')) {
        return new Response(JSON.stringify({ registered: true, agentId: 'did:fides:agent', authorityGranted: false }), { status: 201 })
      }
      if (String(url).endsWith('/agents/did%3Afides%3Aagent')) {
        return new Response(JSON.stringify({ agentId: 'did:fides:agent', card: {} }), { status: 200 })
      }
      if (String(url).endsWith('/agents')) {
        return new Response(JSON.stringify({ agents: [{ agentId: 'did:fides:agent' }] }), { status: 200 })
      }
      return new Response(JSON.stringify({ authorityGranted: false, candidates: [{ agentId: 'did:fides:agent' }] }), { status: 200 })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })

    await expect(client.agents.register({ agentCardId: 'did:fides:agent' })).resolves.toMatchObject({
      registered: true,
      authorityGranted: false,
    })
    await expect(client.agents.list()).resolves.toMatchObject({ agents: [{ agentId: 'did:fides:agent' }] })
    await expect(client.agents.inspect('did:fides:agent')).resolves.toMatchObject({ agentId: 'did:fides:agent' })
    await expect(client.discovery.find({ capability: 'invoice.reconcile' })).resolves.toMatchObject({
      authorityGranted: false,
      candidates: [{ agentId: 'did:fides:agent' }],
    })

    expect(calls.map(call => call.url)).toEqual([
      'http://localhost:7345/agents/register',
      'http://localhost:7345/agents',
      'http://localhost:7345/agents/did%3Afides%3Aagent',
      'http://localhost:7345/discover',
    ])
  })
})
