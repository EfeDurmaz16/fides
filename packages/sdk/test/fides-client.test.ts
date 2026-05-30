import { afterEach, describe, expect, it, vi } from 'vitest'
import { createAgentIdentity, verifySignedInvocationRequest, type SessionGrantV2 } from '@fides/core'
import { FidesClient, FidesClientError } from '../src/fides-client.js'

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
    await client.discovery.local({ capability: 'invoice.reconcile' })
    await client.discovery.wellKnown({ capability: 'invoice.reconcile' })
    await client.discovery.registry({
      capability: 'invoice.reconcile',
      supported_versions: ['fides.v2.0'],
      required_versions: ['fides.v2.0'],
    })
    await client.discovery.relay({
      capability: 'invoice.reconcile',
      supported_versions: ['fides.v2.0'],
    })
    await client.discovery.dht({ capability: 'invoice.reconcile' })
    await client.discovery.federation({ capability: 'invoice.reconcile' })
    await client.trust.evaluate({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    await client.reputation.update({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    await client.policy.evaluate({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    await client.delegations.create({
      delegator: 'did:fides:principal',
      delegatee: 'did:fides:requester',
      capabilities: ['invoice.reconcile'],
    })
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
    await client.attestations.create({ agentId: 'did:fides:agent', codeHash: 'sha256:test' })
    await client.attestations.get('att_1')
    await client.attestations.verify('att_1')
    await client.sessions.request({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    await client.sessions.get('sess_1')
    await client.sessions.verify('sess_1')
    await client.registry.start()
    await client.registry.publish({ agentCardId: 'did:fides:agent' })
    await client.registry.search({
      capability: 'invoice.reconcile',
      supported_versions: ['fides.v2.0'],
      required_versions: ['fides.v2.0'],
    })
    await client.registry.index()
    await client.relay.start()
    await client.relay.register({ agentId: 'did:fides:agent' })
    await client.relay.discover({
      capability: 'invoice.reconcile',
      supported_versions: ['fides.v2.0'],
    })
    await client.dht.start()
    await client.dht.publish({ capability: 'invoice.reconcile', agentId: 'did:fides:agent' })
    await client.dht.find({ capability: 'invoice.reconcile' })
    await client.wellKnown.fides()
    await client.wellKnown.agents()
    await client.wellKnown.agent('did:fides:agent')
    await client.evidence.append({ type: 'capability.invoked', actor: 'did:fides:agent' })
    await client.evidence.list()
    await client.evidence.inspect('evt_1')
    await client.evidence.verify()
    await client.evidence.export()
    await client.demo.run()
    await client.simulate.adversarial()
    await client.invoke({ sessionId: 'sess_1', input: { invoiceId: 'inv_123' } })

    expect(calls.map(call => call.url)).toEqual([
      'http://localhost:4817/identities',
      'http://localhost:4817/agent-cards',
      'http://localhost:4817/agent-cards/card_1/sign',
      'http://localhost:4817/agents/register',
      'http://localhost:4817/discover',
      'http://localhost:4817/discover/local',
      'http://localhost:4817/discover/well-known',
      'http://localhost:4817/discover/registry',
      'http://localhost:4817/discover/relay',
      'http://localhost:4817/discover/dht',
      'http://localhost:4817/discover/federation',
      'http://localhost:4817/trust/evaluate',
      'http://localhost:4817/reputation/update',
      'http://localhost:4817/policy/evaluate',
      'http://localhost:4817/delegations',
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
      'http://localhost:4817/attestations',
      'http://localhost:4817/attestations/att_1',
      'http://localhost:4817/attestations/att_1/verify',
      'http://localhost:4817/sessions',
      'http://localhost:4817/sessions/sess_1',
      'http://localhost:4817/sessions/sess_1/verify',
      'http://localhost:4817/registry/start',
      'http://localhost:4817/registry/publish',
      'http://localhost:4817/registry/search',
      'http://localhost:4817/registry/index',
      'http://localhost:4817/relay/start',
      'http://localhost:4817/relay/register',
      'http://localhost:4817/relay/discover',
      'http://localhost:4817/dht/start',
      'http://localhost:4817/dht/publish',
      'http://localhost:4817/dht/find',
      'http://localhost:4817/.well-known/fides.json',
      'http://localhost:4817/.well-known/agents.json',
      'http://localhost:4817/.well-known/agents/did%3Afides%3Aagent.json',
      'http://localhost:4817/evidence',
      'http://localhost:4817/evidence',
      'http://localhost:4817/evidence/evt_1',
      'http://localhost:4817/evidence/verify',
      'http://localhost:4817/evidence/export',
      'http://localhost:4817/demo/run',
      'http://localhost:4817/simulate/adversarial',
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
      'GET',
      'POST',
      'POST',
      'POST',
      'POST',
      'GET',
      'POST',
      'POST',
      'POST',
      'POST',
      'POST',
      'POST',
      'GET',
      'GET',
      'GET',
      'POST',
      'GET',
      'GET',
      'POST',
      'POST',
      'POST',
      'POST',
      'POST',
    ])
    expect(JSON.parse(calls[7].init?.body as string)).toEqual({
      capability: 'invoice.reconcile',
      supported_versions: ['fides.v2.0'],
      required_versions: ['fides.v2.0'],
    })
    expect(JSON.parse(calls[37].init?.body as string)).toEqual({
      capability: 'invoice.reconcile',
      supported_versions: ['fides.v2.0'],
      required_versions: ['fides.v2.0'],
    })
    expect(JSON.parse(calls[43].init?.body as string)).toEqual({
      capability: 'invoice.reconcile',
      agentId: 'did:fides:agent',
    })
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

  it('throws typed client errors when agentd returns an ErrorEnvelope', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      return new Response(JSON.stringify({
        error: {
          code: 'APPROVAL_REQUIRED',
          category: 'approval',
          severity: 'warning',
          retryable: true,
          message: 'Human approval is required before execution',
          details: { reason_codes: ['HIGH_RISK_REQUIRES_ATTESTATION_OR_APPROVAL'] },
        },
      }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' },
      })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })

    await expect(client.sessions.request({
      agentId: 'did:fides:agent',
      capability: 'payments.prepare',
    })).rejects.toMatchObject({
      name: 'FidesClientError',
      status: 409,
      error: {
        code: 'APPROVAL_REQUIRED',
        retryable: true,
      },
    })

    try {
      await client.sessions.request({ agentId: 'did:fides:agent', capability: 'payments.prepare' })
    } catch (error) {
      expect(error).toBeInstanceOf(FidesClientError)
      expect((error as FidesClientError).message).toBe('Human approval is required before execution')
      expect((error as FidesClientError).error?.details).toEqual({
        reason_codes: ['HIGH_RISK_REQUIRES_ATTESTATION_OR_APPROVAL'],
      })
    }
  })

  it('creates and submits signed invocation requests from a session grant', async () => {
    const requester = await createAgentIdentity()
    const sessionGrant: SessionGrantV2 = {
      schema_version: 'fides.session_grant.v1',
      session_id: 'sess_signed',
      requester_agent_id: requester.identity.did,
      target_agent_id: 'did:fides:target',
      principal_id: 'did:fides:principal',
      capability: 'invoice.reconcile',
      scopes: ['read:invoices'],
      constraints: { invoiceId: 'inv_123' },
      policy_hash: 'sha256:policy',
      trust_result_hash: 'sha256:trust',
      issued_at: '2026-05-30T00:00:00.000Z',
      expires_at: '2026-05-30T01:00:00.000Z',
      nonce: 'nonce_signed',
      audience: ['did:fides:target'],
      issuer: requester.identity.did,
      payload_hash: 'sha256:session',
    }
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init })
      return new Response(JSON.stringify({
        authorityGranted: true,
        session: sessionGrant,
        request: { id: 'inv_req_1' },
        signedRequestVerified: true,
        preflight: { status: 'allowed' },
        result: { status: 'completed' },
        signedResultVerified: true,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    await expect(client.invokeSigned({
      sessionGrant,
      input: { invoiceId: 'inv_123' },
      privateKey: requester.privateKey,
      inputSchema: {
        type: 'object',
        required: ['invoiceId'],
        properties: { invoiceId: { type: 'string' } },
      },
    })).resolves.toMatchObject({
      authorityGranted: true,
      signedRequestVerified: true,
    })

    expect(calls).toHaveLength(1)
    expect(calls[0].url).toBe('http://localhost:7345/invoke')
    const body = JSON.parse(calls[0].init?.body as string)
    expect(body).toMatchObject({
      sessionId: 'sess_signed',
      input: { invoiceId: 'inv_123' },
      signedRequest: {
        payload: {
          schema_version: 'fides.invocation.request.v1',
          issuer: requester.identity.did,
          session_id: 'sess_signed',
          requester_agent_id: requester.identity.did,
          target_agent_id: 'did:fides:target',
          principal_id: 'did:fides:principal',
          capability: 'invoice.reconcile',
          scopes: ['read:invoices'],
          dry_run: false,
        },
        proof: {
          verificationMethod: requester.identity.did,
          proofPurpose: 'capabilityInvocation',
        },
      },
    })
    await expect(verifySignedInvocationRequest(body.signedRequest)).resolves.toBe(true)
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
      return new Response(JSON.stringify({
        authorityGranted: false,
        candidates: [{
          agentId: 'did:fides:agent',
          authority: 'candidate_only',
          evidence_refs: ['evt_discovery'],
        }],
      }), { status: 200 })
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
      candidates: [{
        agentId: 'did:fides:agent',
        authority: 'candidate_only',
        evidence_refs: ['evt_discovery'],
      }],
    })

    expect(calls.map(call => call.url)).toEqual([
      'http://localhost:7345/agents/register',
      'http://localhost:7345/agents',
      'http://localhost:7345/agents/did%3Afides%3Aagent',
      'http://localhost:7345/discover',
    ])
  })
})
