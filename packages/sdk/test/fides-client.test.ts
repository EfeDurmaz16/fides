import { afterEach, describe, expect, it, vi } from 'vitest'
import { createAgentIdentity, verifySignedInvocationRequest, type SessionGrantV2 } from '@fides/core'
import { FidesClient, FidesClientError } from '../src/fides-client.js'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('FidesClient', () => {
  it('types root policy evaluation responses with v2 decisions', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      policy: {
        schema_version: 'fides.policy.decision.v1',
        id: 'poldec_1',
        issuer: 'did:fides:agentd:local',
        subject: 'did:fides:agent',
        decision: 'require_approval',
        principal_id: 'did:fides:principal',
        requester_agent_id: 'did:fides:requester',
        target_agent_id: 'did:fides:agent',
        capability: 'payments.prepare',
        reason_codes: ['HIGH_RISK_REQUIRES_APPROVAL'],
        machine_reasons: [],
        human_reasons: ['High-risk capability requires approval'],
        required_controls: ['human_approval'],
        evidence_refs: [],
        issued_at: '2026-01-01T00:00:00.000Z',
        evaluated_at: '2026-01-01T00:00:00.000Z',
        payload_hash: 'sha256:test',
      },
      trust: { score: 0.7, band: 'medium' },
      authorityGranted: false,
      requiresSessionGrant: false,
      explanation: 'Policy decisions do not execute capabilities.',
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))

    const client = new FidesClient({ daemonUrl: 'http://localhost:4817' })
    const result = await client.policy.evaluate({ agentId: 'did:fides:agent', capability: 'payments.prepare' })

    expect(result.policy.decision).toBe('require_approval')
    expect(result.authorityGranted).toBe(false)
    expect(result.requiresSessionGrant).toBe(false)
  })

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
    await client.discovery.allProviders({ capability: 'invoice.reconcile' })
    await client.trust.evaluate({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    await client.trust.get('did:fides:agent')
    await client.reputation.update({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    await client.reputation.get('did:fides:agent')
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
    await client.evidence.export({ privacy_mode: 'hash_only', include_metadata: false })
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
      'http://localhost:4817/discover/local',
      'http://localhost:4817/discover/well-known',
      'http://localhost:4817/discover/registry',
      'http://localhost:4817/discover/relay',
      'http://localhost:4817/discover/dht',
      'http://localhost:4817/discover/federation',
      'http://localhost:4817/trust/evaluate',
      'http://localhost:4817/trust/did%3Afides%3Aagent',
      'http://localhost:4817/reputation/update',
      'http://localhost:4817/reputation/did%3Afides%3Aagent',
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
      'POST',
      'POST',
      'GET',
      'POST',
      'GET',
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
    expect(JSON.parse(calls[45].init?.body as string)).toEqual({
      capability: 'invoice.reconcile',
      supported_versions: ['fides.v2.0'],
      required_versions: ['fides.v2.0'],
    })
    expect(JSON.parse(calls[51].init?.body as string)).toEqual({
      capability: 'invoice.reconcile',
      agentId: 'did:fides:agent',
    })
    expect(JSON.parse(calls[60].init?.body as string)).toEqual({
      privacy_mode: 'hash_only',
      include_metadata: false,
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

    const created = await client.identity.createAgent({ name: 'Calendar Agent' })
    expect(created).toMatchObject({
      identity: { did: 'did:fides:agent' },
    })
    expect(created.identity.did).toBe('did:fides:agent')
    expect(created.publicKeyHex).toBeUndefined()

    const listed = await client.identity.list()
    expect(listed).toMatchObject({
      identities: [{ did: 'did:fides:agent', type: 'agent' }],
    })
    expect(listed.identities[0]?.did).toBe('did:fides:agent')

    const shown = await client.identity.show('did:fides:agent')
    expect(shown).toMatchObject({
      identity: { did: 'did:fides:agent' },
    })
    expect(shown.identity.did).toBe('did:fides:agent')

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

  it('types root session responses with authority mode and allowed actions', async () => {
    const session: SessionGrantV2 = {
      schema_version: 'fides.session_grant.v1',
      id: 'sess_1',
      session_id: 'sess_1',
      issuer: 'did:fides:agentd',
      subject: 'did:fides:agent',
      requester_agent_id: 'did:fides:requester',
      target_agent_id: 'did:fides:agent',
      principal_id: 'did:fides:principal',
      capability: 'payments.prepare',
      scopes: ['payments:prepare'],
      constraints: { dryRunOnly: true },
      policy_hash: 'sha256:policy',
      trust_result_hash: 'sha256:trust',
      issued_at: '2026-05-30T00:00:00.000Z',
      expires_at: '2026-05-30T01:00:00.000Z',
      audience: ['did:fides:agent'],
      nonce: 'nonce_1',
      payload_hash: 'sha256:payload',
    }

    vi.stubGlobal('fetch', vi.fn(async () => {
      return new Response(JSON.stringify({
        authorized: true,
        authorityGranted: false,
        authorityMode: 'dry_run_only',
        allowedActions: ['dry_run'],
        session,
        signedSessionVerified: true,
        evidenceRefs: ['evt_session'],
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const result = await client.sessions.request({
      agentId: 'did:fides:agent',
      capability: 'payments.prepare',
    })

    expect(result.authorized).toBe(true)
    expect(result.authorityGranted).toBe(false)
    expect(result.authorityMode).toBe('dry_run_only')
    expect(result.allowedActions).toEqual(['dry_run'])
    expect(result.session.constraints).toEqual({ dryRunOnly: true })
  })

  it('adds identity trust-anchor attestations through promise helpers', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init })
      return new Response(JSON.stringify({
        attestation: { id: 'att_identity_1' },
        evidenceRefs: ['evt_1'],
        authorityGranted: false,
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })

    await client.attestations.github({ identity: 'did:fides:publisher', handle: 'fides-dev' })
    await client.attestations.email({ identity: 'did:fides:publisher', email: 'dev@example.com' })
    await client.attestations.domain({ identity: 'did:fides:publisher', domain: 'example.com' })
    await client.attestations.package({
      identity: 'did:fides:publisher',
      registry: 'npm',
      package: '@fides/example-agent',
    })
    await client.attestations.wallet({ identity: 'did:fides:publisher', address: '0xabc' })

    expect(calls.map(call => call.url)).toEqual([
      'http://localhost:7345/attestations',
      'http://localhost:7345/attestations',
      'http://localhost:7345/attestations',
      'http://localhost:7345/attestations',
      'http://localhost:7345/attestations',
    ])
    expect(calls.map(call => JSON.parse(call.init?.body as string))).toEqual([
      { type: 'github', identity: 'did:fides:publisher', handle: 'fides-dev' },
      { type: 'email', identity: 'did:fides:publisher', email: 'dev@example.com' },
      { type: 'domain', identity: 'did:fides:publisher', domain: 'example.com' },
      {
        type: 'package',
        identity: 'did:fides:publisher',
        registry: 'npm',
        package: '@fides/example-agent',
      },
      { type: 'wallet', identity: 'did:fides:publisher', address: '0xabc' },
    ])
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
        return new Response(JSON.stringify({
          registered: true,
          agentId: 'did:fides:agent',
          cardId: 'card_1',
          registeredAt: '2026-05-30T00:00:00.000Z',
          signed: true,
          verified: true,
          authority: 'candidate_only',
          capabilities: ['invoice.reconcile'],
          authorityGranted: false,
          reasons: [
            'identity_bound_signed_agent_card_verified',
            'local_registration_candidate_only',
            'discovery_does_not_grant_authority',
          ],
        }), { status: 201 })
      }
      if (String(url).endsWith('/agents/did%3Afides%3Aagent')) {
        return new Response(JSON.stringify({
          agentId: 'did:fides:agent',
          cardId: 'card_1',
          registeredAt: '2026-05-30T00:00:00.000Z',
          signed: true,
          verified: true,
          authority: 'candidate_only',
          capabilities: ['invoice.reconcile'],
          authorityGranted: false,
          reasons: ['local_registration_candidate_only', 'discovery_does_not_grant_authority'],
          card: {},
          signedCard: {},
        }), { status: 200 })
      }
      if (String(url).endsWith('/agents')) {
        return new Response(JSON.stringify({
          agents: [{
            agentId: 'did:fides:agent',
            cardId: 'card_1',
            registeredAt: '2026-05-30T00:00:00.000Z',
            signed: true,
            verified: true,
            authority: 'candidate_only',
            capabilities: ['invoice.reconcile'],
            authorityGranted: false,
            reasons: ['identity_bound_signed_agent_card_verified', 'discovery_does_not_grant_authority'],
          }],
          authorityGranted: false,
        }), { status: 200 })
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
      authority: 'candidate_only',
      verified: true,
      authorityGranted: false,
      reasons: expect.arrayContaining(['discovery_does_not_grant_authority']),
    })
    await expect(client.agents.list()).resolves.toMatchObject({
      agents: [{
        agentId: 'did:fides:agent',
        authority: 'candidate_only',
        authorityGranted: false,
      }],
      authorityGranted: false,
    })
    await expect(client.agents.inspect('did:fides:agent')).resolves.toMatchObject({
      agentId: 'did:fides:agent',
      authority: 'candidate_only',
      authorityGranted: false,
    })
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

  it('keeps SDK all-provider discovery results when one provider fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request) => {
      if (String(url).endsWith('/discover/relay')) {
        return new Response(JSON.stringify({
          error: {
            code: 'VERSION_INCOMPATIBLE',
            category: 'version',
            severity: 'error',
            retryable: false,
            message: 'Relay candidate protocol version is incompatible',
            details: { provider: 'relay' },
          },
        }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        })
      }

      return new Response(JSON.stringify({
        provider: String(url).split('/').at(-1),
        authorityGranted: false,
        candidates: [{ agentId: 'did:fides:agent', authorityGranted: false }],
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const result = await client.discovery.allProviders({ capability: 'invoice.reconcile' })

    expect(result.authorityGranted).toBe(false)
    expect(result.results).toHaveLength(6)
    expect(result.results).toEqual(expect.arrayContaining([
      expect.objectContaining({
        provider: 'local',
        ok: true,
        result: expect.objectContaining({ authorityGranted: false }),
      }),
      expect.objectContaining({
        provider: 'relay',
        ok: false,
        authorityGranted: false,
        error: expect.objectContaining({
          status: 503,
          code: 'VERSION_INCOMPATIBLE',
          message: 'Relay candidate protocol version is incompatible',
        }),
      }),
    ]))
  })
})
