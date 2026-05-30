import { afterEach, describe, expect, it, vi } from 'vitest'
import { createAgentIdentity, verifySignedInvocationRequest, type SessionGrantV2 } from '@fides/core'
import { FidesClient, FidesClientError } from '../src/fides-client.js'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('FidesClient', () => {
  it('reads root daemon health from the public v2 facade', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      status: 'degraded',
      service: 'agentd',
      authorityStore: { kind: 'file', ok: true },
      localStateStore: { kind: 'sqlite', ok: true, path: '/tmp/fides.sqlite' },
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const health = await client.health()

    expect(health.status).toBe('degraded')
    expect(health.service).toBe('agentd')
    expect(health.authorityStore?.kind).toBe('file')
    expect(health.localStateStore?.kind).toBe('sqlite')
    expect(fetch).toHaveBeenCalledWith('http://localhost:7345/health', {
      method: 'GET',
      headers: new Headers(),
    })
  })

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

  it('types root approval responses without granting authority', async () => {
    const approval = {
      schema_version: 'fides.approval.request.v1',
      id: 'appr_1',
      issuer: 'did:fides:requester',
      subject: 'did:fides:target',
      requester_agent_id: 'did:fides:requester',
      target_agent_id: 'did:fides:target',
      principal_id: 'did:fides:principal',
      capability: 'payments.prepare',
      requested_scopes: ['payments:prepare'],
      risk_level: 'high',
      evidence_refs: [],
      status: 'pending',
      created_at: '2026-05-30T00:00:00.000Z',
      payload_hash: 'sha256:approval',
    }
    const decision = {
      schema_version: 'fides.approval.decision.v1',
      id: 'apprd_1',
      issuer: 'did:fides:approver',
      subject: 'appr_1',
      approval_request_id: 'appr_1',
      approver_id: 'did:fides:approver',
      decision: 'approved',
      reason: 'human approved',
      constraints: {},
      evidence_refs: [],
      decided_at: '2026-05-30T00:01:00.000Z',
      payload_hash: 'sha256:decision',
    }

    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).endsWith('/approvals/appr_1/approve')) {
        return new Response(JSON.stringify({
          approval: { ...approval, status: 'approved' },
          decision,
          evidenceRefs: ['evt_approval_decision'],
          authorityGranted: false,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/approvals') && init?.method === 'GET') {
        return new Response(JSON.stringify({
          approvals: [approval],
          decisions: [],
          authorityGranted: false,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({
        approval,
        evidenceRefs: ['evt_approval_requested'],
        authorityGranted: false,
      }), { status: 201, headers: { 'Content-Type': 'application/json' } })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const created = await client.approvals.create({ agentId: 'did:fides:target', capability: 'payments.prepare' })
    expect(created.approval.status).toBe('pending')
    expect(created.authorityGranted).toBe(false)

    const listed = await client.approvals.list()
    expect(listed.approvals[0]?.capability).toBe('payments.prepare')
    expect(listed.authorityGranted).toBe(false)

    const approved = await client.approvals.approve('appr_1', { approverId: 'did:fides:approver' })
    expect(approved.approval.status).toBe('approved')
    expect(approved.decision.decision).toBe('approved')
    expect(approved.authorityGranted).toBe(false)
  })

  it('types root kill switch responses as policy overrides', async () => {
    const rule = {
      schema_version: 'fides.kill_switch.rule.v1',
      id: 'ks_1',
      issuer: 'did:fides:operator',
      target_type: 'capability',
      target: 'payments.prepare',
      reason: 'incident response',
      enabled: true,
      created_at: '2026-05-30T00:00:00.000Z',
      payload_hash: 'sha256:killswitch',
    }

    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).endsWith('/killswitch/ks_1') && init?.method === 'DELETE') {
        return new Response(JSON.stringify({
          rule: { ...rule, enabled: false },
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/killswitch') && init?.method === 'GET') {
        return new Response(JSON.stringify({
          rules: [rule],
          active: [rule],
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({
        rule,
        evidenceRefs: ['evt_kill_switch'],
        authorityOverride: true,
        explanation: 'Kill switch rules override normal trust and policy evaluation while active.',
      }), { status: 201, headers: { 'Content-Type': 'application/json' } })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const enabled = await client.killSwitch.enable({
      targetType: 'capability',
      target: 'payments.prepare',
      reason: 'incident response',
    })
    expect(enabled.rule.enabled).toBe(true)
    expect(enabled.authorityOverride).toBe(true)

    const listed = await client.killSwitch.list()
    expect(listed.active[0]?.target).toBe('payments.prepare')

    const disabled = await client.killSwitch.disable('ks_1')
    expect(disabled.rule.enabled).toBe(false)
  })

  it('serializes typed governance and evidence request contracts', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init })
      return new Response(JSON.stringify({
        policy: { decision: 'allow' },
        token: { id: 'del_1' },
        approval: { id: 'appr_1' },
        decision: { id: 'apprd_1' },
        rule: { id: 'ks_1' },
        record: { id: 'rec_1' },
        event: { event_id: 'evt_1' },
        authorityGranted: false,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    await client.policy.evaluate({
      principalId: 'did:fides:principal',
      requesterAgentId: 'did:fides:requester',
      agentId: 'did:fides:target',
      capability: 'payments.prepare',
      requestedScopes: ['payments:prepare'],
      runtimeAttestationValid: false,
      approvalGranted: true,
      evidenceRefs: ['evt_policy_input'],
    })
    await client.delegations.create({
      delegator: 'did:fides:principal',
      delegatee: 'did:fides:requester',
      capabilities: ['payments.prepare'],
      constraints: { dryRunOnly: true },
      audience: ['did:fides:target'],
      nonce: 'nonce_1',
    })
    await client.approvals.create({
      targetAgentId: 'did:fides:target',
      capability: 'payments.prepare',
      requesterAgentId: 'did:fides:requester',
      principalId: 'did:fides:principal',
      requestedScopes: ['payments:prepare'],
      riskLevel: 'high',
      policyDecisionHash: 'sha256:policy',
    })
    await client.approvals.approve('appr_1', {
      approverId: 'did:fides:approver',
      reason: 'approved for dry run',
      constraints: { dryRunOnly: true },
      evidenceRefs: ['evt_approval'],
    })
    await client.killSwitch.enable({
      targetType: 'risk_class',
      target: 'critical',
      issuer: 'did:fides:operator',
      reason: 'incident response',
    })
    await client.revocations.create({
      targetType: 'attestation',
      targetId: 'att_1',
      issuer: 'did:fides:operator',
      reason: 'expired attestation',
      evidenceRefs: ['evt_revocation'],
    })
    await client.incidents.report({
      targetAgentId: 'did:fides:target',
      reporter: 'did:fides:principal',
      severity: 'critical',
      category: 'sandbox_escape',
      description: 'escaped policy sandbox',
      trustPenalty: 0.5,
      reputationPenalty: 0.4,
      evidenceRefs: ['evt_incident'],
    })
    await client.incidents.resolve('inc_1', {
      status: 'resolved',
      reason: 'patched',
      resolver: 'did:fides:operator',
      evidenceRefs: ['evt_resolution'],
    })
    await client.evidence.append({
      type: 'policy.evaluated',
      actor: 'did:fides:agentd',
      subject: 'did:fides:target',
      principal: 'did:fides:principal',
      capability: 'payments.prepare',
      input: { amount: 100 },
      output: { decision: 'require_approval' },
      policy: { decision: 'require_approval' },
      decision: 'require_approval',
      riskLevel: 'high',
      privacyMode: 'hash_only',
      metadata: { source: 'sdk-test' },
    })

    expect(calls.map(call => call.url)).toEqual([
      'http://localhost:7345/policy/evaluate',
      'http://localhost:7345/delegations',
      'http://localhost:7345/approvals',
      'http://localhost:7345/approvals/appr_1/approve',
      'http://localhost:7345/killswitch',
      'http://localhost:7345/revocations',
      'http://localhost:7345/incidents',
      'http://localhost:7345/incidents/inc_1/resolve',
      'http://localhost:7345/evidence',
    ])
    expect(calls.map(call => JSON.parse(call.init?.body as string))).toEqual([
      {
        principalId: 'did:fides:principal',
        requesterAgentId: 'did:fides:requester',
        agentId: 'did:fides:target',
        capability: 'payments.prepare',
        requestedScopes: ['payments:prepare'],
        runtimeAttestationValid: false,
        approvalGranted: true,
        evidenceRefs: ['evt_policy_input'],
      },
      {
        delegator: 'did:fides:principal',
        delegatee: 'did:fides:requester',
        capabilities: ['payments.prepare'],
        constraints: { dryRunOnly: true },
        audience: ['did:fides:target'],
        nonce: 'nonce_1',
      },
      {
        targetAgentId: 'did:fides:target',
        capability: 'payments.prepare',
        requesterAgentId: 'did:fides:requester',
        principalId: 'did:fides:principal',
        requestedScopes: ['payments:prepare'],
        riskLevel: 'high',
        policyDecisionHash: 'sha256:policy',
      },
      {
        approverId: 'did:fides:approver',
        reason: 'approved for dry run',
        constraints: { dryRunOnly: true },
        evidenceRefs: ['evt_approval'],
      },
      {
        targetType: 'risk_class',
        target: 'critical',
        issuer: 'did:fides:operator',
        reason: 'incident response',
      },
      {
        targetType: 'attestation',
        targetId: 'att_1',
        issuer: 'did:fides:operator',
        reason: 'expired attestation',
        evidenceRefs: ['evt_revocation'],
      },
      {
        targetAgentId: 'did:fides:target',
        reporter: 'did:fides:principal',
        severity: 'critical',
        category: 'sandbox_escape',
        description: 'escaped policy sandbox',
        trustPenalty: 0.5,
        reputationPenalty: 0.4,
        evidenceRefs: ['evt_incident'],
      },
      {
        status: 'resolved',
        reason: 'patched',
        resolver: 'did:fides:operator',
        evidenceRefs: ['evt_resolution'],
      },
      {
        type: 'policy.evaluated',
        actor: 'did:fides:agentd',
        subject: 'did:fides:target',
        principal: 'did:fides:principal',
        capability: 'payments.prepare',
        input: { amount: 100 },
        output: { decision: 'require_approval' },
        policy: { decision: 'require_approval' },
        decision: 'require_approval',
        riskLevel: 'high',
        privacyMode: 'hash_only',
        metadata: { source: 'sdk-test' },
      },
    ])
  })

  it('types root revocation responses as authority overrides', async () => {
    const record = {
      schema_version: 'fides.revocation.record.v1',
      id: 'rev_1',
      issuer: 'did:fides:operator',
      subject: 'did:fides:agent',
      target_type: 'agent',
      target_id: 'did:fides:agent',
      reason: 'compromised deployment key',
      status: 'active',
      evidence_refs: [],
      created_at: '2026-05-30T00:00:00.000Z',
      payload_hash: 'sha256:revocation',
    }

    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).endsWith('/revocations/rev_1')) {
        return new Response(JSON.stringify({
          id: 'rev_1',
          revoked: true,
          record,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/revocations') && init?.method === 'GET') {
        return new Response(JSON.stringify({
          records: [record],
          active: [record],
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({
        record,
        evidenceRefs: ['evt_revocation'],
        authorityOverride: true,
        explanation: 'Active revocation records override normal trust and policy evaluation for matching requests.',
      }), { status: 201, headers: { 'Content-Type': 'application/json' } })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const created = await client.revocations.create({
      targetType: 'agent',
      targetId: 'did:fides:agent',
      reason: 'compromised deployment key',
    })
    expect(created.record.status).toBe('active')
    expect(created.authorityOverride).toBe(true)

    const listed = await client.revocations.list()
    expect(listed.active[0]?.target_type).toBe('agent')

    const status = await client.revocations.get('rev_1')
    expect(status.revoked).toBe(true)
    expect(status.record?.target_id).toBe('did:fides:agent')
  })

  it('types root incident responses as policy review inputs', async () => {
    const record = {
      schema_version: 'fides.incident.record.v1',
      id: 'inc_1',
      issuer: 'did:fides:reporter',
      subject: 'did:fides:agent',
      reporter: 'did:fides:reporter',
      target_agent_id: 'did:fides:agent',
      severity: 'high',
      category: 'unauthorized_action',
      description: 'attempted invocation outside delegated authority',
      evidence_refs: [],
      resolution_status: 'open',
      trust_penalty: 0.3,
      reputation_penalty: 0.2,
      created_at: '2026-05-30T00:00:00.000Z',
      payload_hash: 'sha256:incident',
    }

    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).endsWith('/incidents/inc_1/resolve')) {
        return new Response(JSON.stringify({
          record: { ...record, resolution_status: 'resolved', resolved_at: '2026-05-30T00:05:00.000Z' },
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/incidents/inc_1')) {
        return new Response(JSON.stringify({ record }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/incidents') && init?.method === 'GET') {
        return new Response(JSON.stringify({
          records: [record],
          open: [record],
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({
        record,
        evidenceRefs: ['evt_incident'],
        explanation: 'Open incident records require policy review for matching target agents until resolved.',
      }), { status: 201, headers: { 'Content-Type': 'application/json' } })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const reported = await client.incidents.report({
      targetAgentId: 'did:fides:agent',
      severity: 'high',
      category: 'unauthorized_action',
      description: 'attempted invocation outside delegated authority',
    })
    expect(reported.record.resolution_status).toBe('open')
    expect(reported.record.trust_penalty).toBe(0.3)

    const listed = await client.incidents.list()
    expect(listed.open[0]?.target_agent_id).toBe('did:fides:agent')

    const fetched = await client.incidents.get('inc_1')
    expect(fetched.record.category).toBe('unauthorized_action')

    const resolved = await client.incidents.resolve('inc_1', { status: 'resolved' })
    expect(resolved.record.resolution_status).toBe('resolved')
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
    await client.identity.list()
    await client.identity.show('did:fides:agent')
    await client.cards.create({ name: 'Invoice Agent', capabilities: [] })
    await client.cards.sign({ id: 'card_1' })
    await client.cards.verify('card_1')
    await client.cards.get('card_1')
    await client.agents.register({ id: 'card_1' })
    await client.agents.list()
    await client.agents.inspect('did:fides:agent')
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
    await client.graph.inspect('did:fides:agent')

    const expectedCalls = [
      ['POST', 'http://localhost:4817/identities'],
      ['GET', 'http://localhost:4817/identities'],
      ['GET', 'http://localhost:4817/identities/did%3Afides%3Aagent'],
      ['POST', 'http://localhost:4817/agent-cards'],
      ['POST', 'http://localhost:4817/agent-cards/card_1/sign'],
      ['POST', 'http://localhost:4817/agent-cards/card_1/verify'],
      ['GET', 'http://localhost:4817/agent-cards/card_1'],
      ['POST', 'http://localhost:4817/agents/register'],
      ['GET', 'http://localhost:4817/agents'],
      ['GET', 'http://localhost:4817/agents/did%3Afides%3Aagent'],
      ['POST', 'http://localhost:4817/discover'],
      ['POST', 'http://localhost:4817/discover/local'],
      ['POST', 'http://localhost:4817/discover/well-known'],
      ['POST', 'http://localhost:4817/discover/registry'],
      ['POST', 'http://localhost:4817/discover/relay'],
      ['POST', 'http://localhost:4817/discover/dht'],
      ['POST', 'http://localhost:4817/discover/federation'],
      ['POST', 'http://localhost:4817/discover/local'],
      ['POST', 'http://localhost:4817/discover/well-known'],
      ['POST', 'http://localhost:4817/discover/registry'],
      ['POST', 'http://localhost:4817/discover/relay'],
      ['POST', 'http://localhost:4817/discover/dht'],
      ['POST', 'http://localhost:4817/discover/federation'],
      ['POST', 'http://localhost:4817/trust/evaluate'],
      ['GET', 'http://localhost:4817/trust/did%3Afides%3Aagent'],
      ['POST', 'http://localhost:4817/reputation/update'],
      ['GET', 'http://localhost:4817/reputation/did%3Afides%3Aagent'],
      ['POST', 'http://localhost:4817/policy/evaluate'],
      ['POST', 'http://localhost:4817/delegations'],
      ['POST', 'http://localhost:4817/approvals'],
      ['GET', 'http://localhost:4817/approvals'],
      ['POST', 'http://localhost:4817/approvals/approval_1/approve'],
      ['POST', 'http://localhost:4817/approvals/approval_1/deny'],
      ['POST', 'http://localhost:4817/killswitch'],
      ['GET', 'http://localhost:4817/killswitch'],
      ['DELETE', 'http://localhost:4817/killswitch/rule_1'],
      ['POST', 'http://localhost:4817/revocations'],
      ['GET', 'http://localhost:4817/revocations'],
      ['GET', 'http://localhost:4817/revocations/rev_1'],
      ['POST', 'http://localhost:4817/incidents'],
      ['GET', 'http://localhost:4817/incidents'],
      ['GET', 'http://localhost:4817/incidents/inc_1'],
      ['POST', 'http://localhost:4817/incidents/inc_1/resolve'],
      ['POST', 'http://localhost:4817/attestations'],
      ['GET', 'http://localhost:4817/attestations/att_1'],
      ['POST', 'http://localhost:4817/attestations/att_1/verify'],
      ['POST', 'http://localhost:4817/sessions'],
      ['GET', 'http://localhost:4817/sessions/sess_1'],
      ['POST', 'http://localhost:4817/sessions/sess_1/verify'],
      ['POST', 'http://localhost:4817/registry/start'],
      ['POST', 'http://localhost:4817/registry/publish'],
      ['POST', 'http://localhost:4817/registry/search'],
      ['GET', 'http://localhost:4817/registry/index'],
      ['POST', 'http://localhost:4817/relay/start'],
      ['POST', 'http://localhost:4817/relay/register'],
      ['POST', 'http://localhost:4817/relay/discover'],
      ['POST', 'http://localhost:4817/dht/start'],
      ['POST', 'http://localhost:4817/dht/publish'],
      ['POST', 'http://localhost:4817/dht/find'],
      ['GET', 'http://localhost:4817/.well-known/fides.json'],
      ['GET', 'http://localhost:4817/.well-known/agents.json'],
      ['GET', 'http://localhost:4817/.well-known/agents/did%3Afides%3Aagent.json'],
      ['POST', 'http://localhost:4817/evidence'],
      ['GET', 'http://localhost:4817/evidence'],
      ['GET', 'http://localhost:4817/evidence/evt_1'],
      ['POST', 'http://localhost:4817/evidence/verify'],
      ['POST', 'http://localhost:4817/evidence/export'],
      ['POST', 'http://localhost:4817/demo/run'],
      ['POST', 'http://localhost:4817/simulate/adversarial'],
      ['POST', 'http://localhost:4817/invoke'],
      ['GET', 'http://localhost:4817/trust/did%3Afides%3Aagent'],
    ]
    expect(calls.map(call => [call.init?.method, call.url])).toEqual(expectedCalls)

    const bodyFor = (url: string) => JSON.parse(calls.find(call => call.url === url)?.init?.body as string)
    expect(bodyFor('http://localhost:4817/discover/registry')).toEqual({
      capability: 'invoice.reconcile',
      supported_versions: ['fides.v2.0'],
      required_versions: ['fides.v2.0'],
    })
    expect(bodyFor('http://localhost:4817/registry/search')).toEqual({
      capability: 'invoice.reconcile',
      supported_versions: ['fides.v2.0'],
      required_versions: ['fides.v2.0'],
    })
    expect(bodyFor('http://localhost:4817/dht/publish')).toEqual({
      capability: 'invoice.reconcile',
      agentId: 'did:fides:agent',
    })
    expect(bodyFor('http://localhost:4817/evidence/export')).toEqual({
      privacy_mode: 'hash_only',
      include_metadata: false,
    })
  })

  it('inspects the local trust graph view without granting authority', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      agentId: 'did:fides:agent',
      trust: [{ capability: 'invoice.reconcile', score: 0.73, band: 'medium' }],
      authorityGranted: false,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const graph = await client.graph.inspect('did:fides:agent')

    expect(graph.agentId).toBe('did:fides:agent')
    expect(graph.authorityGranted).toBe(false)
    expect(graph.graphView.trust[0]?.capability).toBe('invoice.reconcile')
    expect(fetch).toHaveBeenCalledWith('http://localhost:7345/trust/did%3Afides%3Aagent', {
      method: 'GET',
      headers: new Headers(),
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

    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init })
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
      principalId: 'did:fides:principal',
      requesterAgentId: 'did:fides:requester',
      requestedScopes: ['payments:prepare'],
      constraints: { dryRunOnly: true },
      attestationId: 'att_runtime_1',
      approvalGranted: true,
      audience: ['did:fides:agent'],
      expiresAt: '2026-05-30T01:00:00.000Z',
    })

    expect(result.authorized).toBe(true)
    expect(result.authorityGranted).toBe(false)
    expect(result.authorityMode).toBe('dry_run_only')
    expect(result.allowedActions).toEqual(['dry_run'])
    expect(result.session.constraints).toEqual({ dryRunOnly: true })
    expect(JSON.parse(calls[0]?.init?.body as string)).toEqual({
      agentId: 'did:fides:agent',
      capability: 'payments.prepare',
      principalId: 'did:fides:principal',
      requesterAgentId: 'did:fides:requester',
      requestedScopes: ['payments:prepare'],
      constraints: { dryRunOnly: true },
      attestationId: 'att_runtime_1',
      approvalGranted: true,
      audience: ['did:fides:agent'],
      expiresAt: '2026-05-30T01:00:00.000Z',
    })
  })

  it('adds identity trust-anchor attestations through promise helpers', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init })
      return new Response(JSON.stringify({
        attestation: {
          id: 'att_identity_1',
          schema_version: 'fides.identity_attestation.v1',
          identity: 'did:fides:publisher',
          trust_anchor: {
            type: 'github',
            value: 'fides-dev',
            verified: true,
            verifiedAt: '2026-05-30T00:00:00.000Z',
          },
          issued_at: '2026-05-30T00:00:00.000Z',
          mode: 'local_mock',
        },
        identity: {
          type: 'publisher',
          did: 'did:fides:publisher',
          publicKeyHex: '00'.repeat(32),
          createdAt: '2026-05-30T00:00:00.000Z',
          identity: { did: 'did:fides:publisher', type: 'publisher' },
        },
        evidenceRefs: ['evt_1'],
        authorityGranted: false,
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })

    const github = await client.attestations.github({ identity: 'did:fides:publisher', handle: 'fides-dev' })
    await client.attestations.email({ identity: 'did:fides:publisher', email: 'dev@example.com' })
    await client.attestations.domain({ identity: 'did:fides:publisher', domain: 'example.com' })
    await client.attestations.package({
      identity: 'did:fides:publisher',
      registry: 'npm',
      package: '@fides/example-agent',
    })
    await client.attestations.wallet({ identity: 'did:fides:publisher', address: '0xabc' })

    expect(github.attestation.trust_anchor.type).toBe('github')
    expect(github.authorityGranted).toBe(false)
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

  it('types runtime attestation issue and verification responses', async () => {
    const attestation = {
      schema_version: 'fides.runtime_attestation.v1',
      id: 'att_runtime_1',
      issuer: 'mock-tee',
      subject: 'did:fides:agent',
      attestation_id: 'att_runtime_1',
      agent_id: 'did:fides:agent',
      provider: 'mock-tee',
      code_hash: 'sha256:code',
      runtime_hash: 'sha256:runtime',
      policy_hash: 'sha256:policy',
      enclave_measurement: 'sha256:measurement',
      issued_at: '2026-05-30T00:00:00.000Z',
      expires_at: '2026-05-30T01:00:00.000Z',
      payload_hash: 'sha256:payload',
      signature: 'local-mock-signature',
    }

    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).endsWith('/attestations/att_runtime_1/verify')) {
        return new Response(JSON.stringify({
          id: 'att_runtime_1',
          valid: true,
          attestation,
          evidenceRefs: ['evt_attestation_verified'],
          authorityGranted: false,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/attestations/att_runtime_1') && init?.method === 'GET') {
        return new Response(JSON.stringify({ attestation }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return new Response(JSON.stringify({
        attestation,
        evidenceRefs: ['evt_attestation_issued'],
        authorityGranted: false,
      }), { status: 201, headers: { 'Content-Type': 'application/json' } })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const issued = await client.attestations.create({
      agentId: 'did:fides:agent',
      codeHash: 'sha256:code',
      runtimeHash: 'sha256:runtime',
      policyHash: 'sha256:policy',
    })
    expect(issued.attestation.schema_version).toBe('fides.runtime_attestation.v1')

    const runtime = await client.attestations.runtime({
      agentId: 'did:fides:agent',
      codeHash: 'sha256:code',
      runtimeHash: 'sha256:runtime',
      policyHash: 'sha256:policy',
      enclaveMeasurement: 'sha256:measurement',
    })
    expect(runtime.attestation.provider).toBe('mock-tee')
    expect(runtime.authorityGranted).toBe(false)

    const fetched = await client.attestations.get('att_runtime_1')
    expect(fetched.attestation.provider).toBe('mock-tee')

    const verified = await client.attestations.verify('att_runtime_1')
    expect(verified.valid).toBe(true)
    expect(verified.authorityGranted).toBe(false)
  })

  it('types generic attestation issue and verification responses', async () => {
    const attestation = {
      schema_version: 'fides.attestation.v1',
      id: 'att_generic_1',
      issuer: 'did:fides:publisher',
      subject: 'did:fides:agent',
      subject_type: 'agent',
      provider: 'github',
      claims: { handle: 'fides-dev' },
      evidence_refs: [],
      issued_at: '2026-05-30T00:00:00.000Z',
      payload_hash: 'sha256:payload',
      signature: 'local-attestation:payload',
    }

    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).endsWith('/attestations/att_generic_1/verify')) {
        return new Response(JSON.stringify({
          id: 'att_generic_1',
          valid: true,
          attestation,
          evidenceRefs: ['evt_generic_verified'],
          authorityGranted: false,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/attestations/att_generic_1') && init?.method === 'GET') {
        return new Response(JSON.stringify({ attestation, authorityGranted: false }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return new Response(JSON.stringify({
        attestation,
        evidenceRefs: ['evt_generic_issued'],
        authorityGranted: false,
      }), { status: 201, headers: { 'Content-Type': 'application/json' } })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const issued = await client.attestations.generic({
      issuer: 'did:fides:publisher',
      subject: 'did:fides:agent',
      subjectType: 'agent',
      provider: 'github',
      claims: { handle: 'fides-dev' },
    })
    expect(issued.attestation.schema_version).toBe('fides.attestation.v1')
    expect(issued.authorityGranted).toBe(false)

    const fetched = await client.attestations.get('att_generic_1')
    expect(fetched.attestation.schema_version).toBe('fides.attestation.v1')

    const verified = await client.attestations.verify('att_generic_1')
    expect(verified.valid).toBe(true)
    expect(verified.authorityGranted).toBe(false)
  })

  it('types root evidence ledger responses as non-authorizing audit records', async () => {
    const event = {
      schema_version: 'fides.evidence_event.v1',
      id: 'evt_1',
      event_id: 'evt_1',
      issuer: 'did:fides:agentd:local',
      type: 'capability.invoked',
      actor: 'did:fides:agent',
      subject: 'did:fides:target',
      capability: 'invoice.reconcile',
      input_hash: 'sha256:input',
      output_hash: 'sha256:output',
      decision: 'dry_run',
      risk_level: 'medium',
      privacy_mode: 'hash_only',
      issued_at: '2026-05-30T00:00:00.000Z',
      timestamp: '2026-05-30T00:00:00.000Z',
      prev_event_hash: '0',
      payload_hash: 'sha256:payload',
      event_hash: 'sha256:event',
      signature: 'local-evidence-signature',
      metadata: { source: 'test' },
    }

    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).endsWith('/evidence/export')) {
        return new Response(JSON.stringify({
          format: 'json',
          exportedAt: '2026-05-30T00:01:00.000Z',
          valid: true,
          count: 1,
          privacyMode: 'hash_only',
          includeMetadata: false,
          events: [event],
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/evidence/verify')) {
        return new Response(JSON.stringify({
          valid: true,
          count: 1,
          lastHash: 'sha256:event',
          scope: 'root-local-evidence-ledger',
          checkedAt: '2026-05-30T00:01:00.000Z',
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/evidence/evt_1')) {
        return new Response(JSON.stringify({
          event,
          authorityGranted: false,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/evidence') && init?.method === 'GET') {
        return new Response(JSON.stringify({
          events: [event],
          count: 1,
          valid: true,
          lastHash: 'sha256:event',
          authorityGranted: false,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({
        accepted: true,
        event,
        authorityGranted: false,
      }), { status: 201, headers: { 'Content-Type': 'application/json' } })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const appended = await client.evidence.append({
      type: 'capability.invoked',
      actor: 'did:fides:agent',
      privacyMode: 'hash_only',
    })
    expect(appended.accepted).toBe(true)
    expect(appended.authorityGranted).toBe(false)
    expect(appended.event.privacy_mode).toBe('hash_only')

    const listed = await client.evidence.list()
    expect(listed.valid).toBe(true)
    expect(listed.events[0]?.event_hash).toBe('sha256:event')

    const inspected = await client.evidence.inspect('evt_1')
    expect(inspected.event.type).toBe('capability.invoked')
    expect(inspected.authorityGranted).toBe(false)

    const verified = await client.evidence.verify()
    expect(verified.scope).toBe('root-local-evidence-ledger')
    expect(verified.lastHash).toBe('sha256:event')

    const exported = await client.evidence.export({ privacy_mode: 'hash_only', include_metadata: false })
    expect(exported.privacyMode).toBe('hash_only')
    expect(exported.events).toHaveLength(1)
  })

  it('types trust, reputation, and delegation responses as non-authorizing signals', async () => {
    const trust = {
      schema_version: 'fides.trust.result.v1',
      id: 'trust_1',
      issuer: 'fides.trust-engine',
      subject: 'did:fides:agent',
      agent_id: 'did:fides:agent',
      capability: 'invoice.reconcile',
      score: 0.72,
      band: 'high',
      reasons: [
        { component: 'IdentityScore', value: 1, weight: 0.14, description: 'identity verified' },
      ],
      risk_flags: [],
      evidence_refs: ['evt_trust'],
      required_controls: [],
      computed_at: '2026-05-30T00:00:00.000Z',
      payload_hash: 'sha256:trust',
    }
    const reputation = {
      schema_version: 'fides.reputation.record.v1',
      id: 'rep_1',
      issuer: 'fides.reputation-engine',
      subject: 'did:fides:agent',
      agent_id: 'did:fides:agent',
      capability: 'invoice.reconcile',
      score: 0.81,
      successful_invocations: 12,
      failed_invocations: 1,
      incident_count: 0,
      publisher_weight: 0.8,
      context_boundary_penalty: 0,
      reasons: [
        { factor: 'success_rate', value: 0.9231, description: 'capability success rate' },
      ],
      computed_at: '2026-05-30T00:00:00.000Z',
      payload_hash: 'sha256:reputation',
    }
    const token = {
      id: 'del_1',
      delegator: 'did:fides:principal',
      delegatee: 'did:fides:requester',
      capabilities: ['invoice.reconcile'],
      constraints: { maxActions: 1 },
      issuedAt: '2026-05-30T00:00:00.000Z',
      expiresAt: '2026-05-30T01:00:00.000Z',
      nonce: 'nonce_1',
      audience: ['did:fides:agent'],
      signature: 'local-delegation-signature',
    }

    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).endsWith('/trust/evaluate')) {
        return new Response(JSON.stringify({
          trust,
          authorityGranted: false,
          explanation: 'Trust is a signal only. Policy evaluation and scoped session grants are required before invocation.',
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/trust/did%3Afides%3Aagent')) {
        return new Response(JSON.stringify({
          agentId: 'did:fides:agent',
          trust: [trust],
          authorityGranted: false,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/reputation/update')) {
        return new Response(JSON.stringify({
          reputation,
          authorityGranted: false,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String(url).endsWith('/reputation/did%3Afides%3Aagent')) {
        return new Response(JSON.stringify({
          agentId: 'did:fides:agent',
          reputations: [reputation],
          authorityGranted: false,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({
        token,
        signed: true,
        authorityGranted: false,
        explanation: 'Delegation records signed scoped authorization intent. It must still be converted into a policy-checked SessionGrant before invocation.',
      }), { status: 201, headers: { 'Content-Type': 'application/json' } })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const trustResult = await client.trust.evaluate({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    expect(trustResult.trust.band).toBe('high')
    expect(trustResult.authorityGranted).toBe(false)

    const trustList = await client.trust.get('did:fides:agent')
    expect(trustList.trust[0]?.capability).toBe('invoice.reconcile')
    expect(trustList.authorityGranted).toBe(false)

    const reputationResult = await client.reputation.update({ agentId: 'did:fides:agent', capability: 'invoice.reconcile' })
    expect(reputationResult.reputation.score).toBe(0.81)
    expect(reputationResult.authorityGranted).toBe(false)

    const reputationList = await client.reputation.get('did:fides:agent')
    expect(reputationList.reputations[0]?.capability).toBe('invoice.reconcile')
    expect(reputationList.authorityGranted).toBe(false)

    const reputationInspection = await client.reputation.inspect('did:fides:agent', 'invoice.reconcile')
    expect(reputationInspection.reputation?.score).toBe(0.81)
    expect(reputationInspection.reputationSignals).toHaveLength(1)
    expect(reputationInspection.authorityGranted).toBe(false)

    const missingCapabilityInspection = await client.reputation.inspect('did:fides:agent', 'payments.execute')
    expect(missingCapabilityInspection.reputation).toBeNull()
    expect(missingCapabilityInspection.reputationSignals).toEqual([])
    expect(missingCapabilityInspection.authorityGranted).toBe(false)

    const delegation = await client.delegations.create({
      delegator: 'did:fides:principal',
      delegatee: 'did:fides:requester',
      capabilities: ['invoice.reconcile'],
    })
    expect(delegation.token.capabilities).toEqual(['invoice.reconcile'])
    expect(delegation.authorityGranted).toBe(false)
  })

  it('types local discovery infrastructure responses as candidate-only records', async () => {
    const record = {
      id: 'reg_1',
      agentId: 'did:fides:agent',
      cardId: 'card_1',
      capabilities: ['invoice.reconcile'],
      authorityGranted: false,
      reasons: ['registry_record_candidate_only'],
    }
    const pointer = {
      id: 'ptr_1',
      capability: 'invoice.reconcile',
      agentId: 'did:fides:agent',
      agentCardUrl: 'local://agent-cards/card_1',
      signed: true,
      authorityGranted: false,
    }
    const card = {
      schema_version: 'fides.agent_card.v1',
      id: 'card_1',
      agent_id: 'did:fides:agent',
      identity: { did: 'did:fides:agent', publicKey: new Uint8Array(32) },
      capabilities: [],
      endpoints: [],
      policies: [{ requiresRuntimeAttestation: false, requiresApproval: false }],
      createdAt: '2026-05-30T00:00:00.000Z',
      updatedAt: '2026-05-30T00:00:00.000Z',
    }

    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request) => {
      const target = String(url)
      if (target.endsWith('/registry/start')) {
        return new Response(JSON.stringify({
          started: true,
          mode: 'local_mock_registry',
          records: 1,
          authorityGranted: false,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (target.endsWith('/registry/publish')) {
        return new Response(JSON.stringify({ accepted: true, record, authorityGranted: false }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (target.endsWith('/registry/index')) {
        return new Response(JSON.stringify({
          mode: 'local_mock_registry',
          records: [record],
          rejectedRecords: [],
          authorityGranted: false,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (target.endsWith('/relay/start')) {
        return new Response(JSON.stringify({
          started: true,
          mode: 'local_mock_relay',
          records: 1,
          authorityGranted: false,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (target.endsWith('/relay/register')) {
        return new Response(JSON.stringify({ accepted: true, record, authorityGranted: false }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (target.endsWith('/dht/start')) {
        return new Response(JSON.stringify({
          started: true,
          mode: 'in_memory_simulator',
          pointers: 1,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (target.endsWith('/dht/publish')) {
        return new Response(JSON.stringify({ accepted: true, pointer, authorityGranted: false }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (target.endsWith('/dht/find')) {
        return new Response(JSON.stringify({
          capability: 'invoice.reconcile',
          pointers: [pointer],
          rejectedPointers: [],
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (target.endsWith('/.well-known/fides.json')) {
        return new Response(JSON.stringify({
          schema_version: 'fides.well_known.v1',
          protocol: 'fides.v2',
          supported_versions: ['fides.v2.0'],
          endpoints: { agents: '/.well-known/agents.json' },
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (target.endsWith('/.well-known/agents.json')) {
        return new Response(JSON.stringify({
          schema_version: 'fides.well_known.agents.v1',
          agents: [{
            agentId: 'did:fides:agent',
            cardId: 'card_1',
            signed: true,
            cardUrl: '/.well-known/agents/did%3Afides%3Aagent.json',
            authorityGranted: false,
          }],
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({
        agentId: 'did:fides:agent',
        card,
        signed: null,
        authorityGranted: false,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const registryStarted = await client.registry.start()
    expect(registryStarted.mode).toBe('local_mock_registry')
    expect(registryStarted.authorityGranted).toBe(false)

    const registryPublished = await client.registry.publish({ agentCardId: 'card_1' })
    expect(registryPublished.accepted).toBe(true)
    expect(registryPublished.authorityGranted).toBe(false)
    expect(registryPublished.record?.authorityGranted).toBe(false)

    const registryIndex = await client.registry.index()
    expect(registryIndex.records[0]?.agentId).toBe('did:fides:agent')
    expect(registryIndex.authorityGranted).toBe(false)

    const relayStarted = await client.relay.start()
    expect(relayStarted.mode).toBe('local_mock_relay')
    expect(relayStarted.authorityGranted).toBe(false)

    const relayRegistered = await client.relay.register({ agentId: 'did:fides:agent' })
    expect(relayRegistered.authorityGranted).toBe(false)
    expect(relayRegistered.record?.authorityGranted).toBe(false)

    const dhtStarted = await client.dht.start()
    expect(dhtStarted.mode).toBe('in_memory_simulator')

    const dhtPublished = await client.dht.publish({ capability: 'invoice.reconcile', agentId: 'did:fides:agent' })
    expect(dhtPublished.authorityGranted).toBe(false)
    expect(dhtPublished.pointer?.authorityGranted).toBe(false)

    const dhtFind = await client.dht.find({ capability: 'invoice.reconcile' })
    expect(dhtFind.pointers[0]?.capability).toBe('invoice.reconcile')

    const fidesWellKnown = await client.wellKnown.fides()
    expect(fidesWellKnown.protocol).toBe('fides.v2')

    const agentsWellKnown = await client.wellKnown.agents()
    expect(agentsWellKnown.agents[0]?.authorityGranted).toBe(false)

    const agentWellKnown = await client.wellKnown.agent('did:fides:agent')
    expect(agentWellKnown.authorityGranted).toBe(false)
  })

  it('types demo and adversarial simulation responses with authority invariants', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request) => {
      if (String(url).endsWith('/simulate/adversarial')) {
        return new Response(JSON.stringify({
          status: 'detected',
          mode: 'local-first',
          detections: ['fake_agent', 'broken_evidence_chain'],
          scenarios: [
            {
              name: 'fake_agent',
              detected: true,
              outcome: 'policy_limited',
              evidenceRef: 'evt_fake_agent',
            },
            {
              name: 'broken_evidence_chain',
              detected: true,
              outcome: 'evidence_verification_failed',
              evidenceRef: 'evt_broken_chain',
            },
          ],
          evidence: {
            scenarioEvents: {
              fake_agent: 'evt_fake_agent',
              broken_evidence_chain: 'evt_broken_chain',
            },
            incidentEvidenceRef: 'evt_incident',
            rootChainValid: true,
            rootEventCount: 3,
            brokenEvidenceChainValid: false,
          },
          authority: {
            discoveryGrantsAuthority: false,
            policyBeforeExecution: true,
            evidenceProduced: true,
          },
          limitations: ['local mock simulation'],
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({
        status: 'executed',
        mode: 'local-first',
        steps: ['Create principal identity', 'Verify evidence hash chain'],
        identities: {
          principal: 'did:fides:principal',
          invoice: 'did:fides:invoice',
        },
        discovery: {
          registry: { authorityGranted: false },
          dht: { authorityGranted: false },
        },
        verification: {
          agentCardsVerified: true,
          evidenceHashChainValid: true,
          evidenceEventCount: 12,
          evidenceExport: { format: 'json', lastHash: 'sha256:last' },
        },
        authority: {
          discoveryGrantsAuthority: false,
          identityEqualsTrust: false,
          trustScoreEqualsPermission: false,
          policyBeforeExecution: true,
          evidenceProduced: true,
        },
        surfaces: {
          registry: 'local_mock',
          dht: 'in_memory_pointer_records',
          payments: 'dry_run_only',
        },
        limitations: ['local mock demo'],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })
    const demo = await client.demo.run()
    expect(demo.status).toBe('executed')
    expect(demo.verification.evidenceHashChainValid).toBe(true)
    expect(demo.authority.discoveryGrantsAuthority).toBe(false)
    expect(demo.authority.policyBeforeExecution).toBe(true)

    const simulation = await client.simulate.adversarial()
    expect(simulation.status).toBe('detected')
    expect(simulation.scenarios.every(scenario => scenario.detected)).toBe(true)
    expect(simulation.evidence.brokenEvidenceChainValid).toBe(false)
    expect(simulation.authority.discoveryGrantsAuthority).toBe(false)
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
    const card = {
      schema_version: 'fides.agent_card.v1',
      id: 'card_1',
      agent_id: 'did:fides:agent',
      identity: { did: 'did:fides:agent', publicKey: new Uint8Array(32) },
      capabilities: [],
      endpoints: [],
      policies: [{ requiresRuntimeAttestation: false, requiresApproval: false }],
      protocolVersions: ['fides.v2.0'],
      createdAt: '2026-05-30T00:00:00.000Z',
      updatedAt: '2026-05-30T00:00:00.000Z',
    }
    const signed = {
      payload: card,
      proof: {
        type: 'Ed25519Signature2020',
        verificationMethod: 'did:fides:agent',
        proofPurpose: 'assertionMethod',
        created: '2026-05-30T00:00:00.000Z',
        signature: 'local-agent-card-signature',
      },
    }
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init })
      if (String(url).endsWith('/agent-cards/card_1/sign')) {
        return new Response(JSON.stringify({ signed }), { status: 200 })
      }
      if (String(url).endsWith('/agent-cards/card_1/verify')) {
        return new Response(JSON.stringify({
          valid: true,
          signed: true,
          canonicalValid: true,
          identityBound: true,
        }), { status: 200 })
      }
      if (String(url).endsWith('/agent-cards/card_1')) {
        return new Response(JSON.stringify({ card, signed }), { status: 200 })
      }
      return new Response(JSON.stringify({ card, validation: { valid: true, errors: [] } }), { status: 201 })
    }))

    const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })

    await expect(client.cards.create({ identity: { did: 'did:fides:agent' }, capabilities: [] })).resolves.toMatchObject({
      card: { id: 'card_1', schema_version: 'fides.agent_card.v1' },
      validation: { valid: true, errors: [] },
    })
    await expect(client.cards.sign({ id: 'card_1' })).resolves.toMatchObject({
      signed: { payload: { id: 'card_1' }, proof: { verificationMethod: 'did:fides:agent' } },
    })
    await expect(client.cards.verify('card_1')).resolves.toMatchObject({
      valid: true,
      signed: true,
      canonicalValid: true,
      identityBound: true,
    })
    await expect(client.cards.get('card_1')).resolves.toMatchObject({
      card: { id: 'card_1' },
      signed: { payload: { id: 'card_1' } },
    })

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
