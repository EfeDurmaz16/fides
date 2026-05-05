import { describe, it, expect } from 'vitest'
import { evaluateGuard, createTrustContext } from '../src/index.js'
import type { PolicyBundle } from '@fides/policy'

const defaultPolicy: PolicyBundle = {
  id: 'test-policy',
  version: '1.0.0',
  rules: [
    {
      id: 'rate-limit',
      condition: { operator: 'gt', field: 'requestCount', value: 100 },
      action: 'deny',
      explanation: 'Rate limit exceeded',
    },
  ],
  defaultAction: 'allow',
}

describe('Guard Evaluation', () => {
  it('denies when kill switch is engaged', async () => {
    const trust = createTrustContext({
      reputationScore: 0.9,
      killSwitchEngaged: true,
      recentIncidents: 0,
    })

    const result = await evaluateGuard({
      agentDid: 'did:test:agent',
      capabilityId: 'email:send',
      policy: defaultPolicy,
      context: { requestCount: 10 },
      trust,
    })

    expect(result.decision).toBe('deny')
    expect(result.explanation).toContain('Kill switch')
  })

  it('denies when evidence chain is broken', async () => {
    const trust = createTrustContext({
      reputationScore: 0.8,
      killSwitchEngaged: false,
      recentIncidents: 0,
      evidenceChain: {
        events: [
          {
            id: 'e1',
            type: 'test',
            timestamp: '2024-01-01T00:00:00Z',
            actor: 'did:test:agent',
            action: 'test',
            payload: {},
            privacy: { level: 'public' },
            prevHash: 'wrong-hash',
            hash: 'some-hash',
            signature: 'sig',
          },
        ],
      },
    })

    const result = await evaluateGuard({
      agentDid: 'did:test:agent',
      capabilityId: 'email:send',
      policy: defaultPolicy,
      context: { requestCount: 10 },
      trust,
    })

    expect(result.decision).toBe('deny')
    expect(result.explanation).toContain('Evidence chain')
  })

  it('denies when too many recent incidents', async () => {
    const trust = createTrustContext({
      reputationScore: 0.8,
      killSwitchEngaged: false,
      recentIncidents: 10,
    })

    const result = await evaluateGuard({
      agentDid: 'did:test:agent',
      capabilityId: 'email:send',
      policy: defaultPolicy,
      context: { requestCount: 10 },
      trust,
    })

    expect(result.decision).toBe('deny')
    expect(result.explanation).toContain('Too many recent incidents')
  })

  it('denies when the agent authority is revoked', async () => {
    const trust = createTrustContext({
      reputationScore: 0.9,
      killSwitchEngaged: false,
      recentIncidents: 0,
      agentRevoked: true,
      revocationReason: 'principal disabled agent',
    })

    const result = await evaluateGuard({
      agentDid: 'did:test:agent',
      capabilityId: 'payments.execute',
      policy: defaultPolicy,
      context: { requestCount: 10 },
      trust,
    })

    expect(result.decision).toBe('deny')
    expect(result.explanation).toContain('Agent authority revoked')
    expect(result.factors[0]?.factor).toBe('agent-revoked')
  })

  it('denies when the session authority is revoked', async () => {
    const trust = createTrustContext({
      reputationScore: 0.9,
      killSwitchEngaged: false,
      recentIncidents: 0,
      sessionRevoked: true,
      revocationReason: 'session nonce replay',
    })

    const result = await evaluateGuard({
      agentDid: 'did:test:agent',
      capabilityId: 'payments.execute',
      policy: defaultPolicy,
      context: { requestCount: 10 },
      trust,
    })

    expect(result.decision).toBe('deny')
    expect(result.explanation).toContain('Session authority revoked')
    expect(result.factors[0]?.factor).toBe('session-revoked')
  })

  it('denies high-risk capabilities when runtime attestation is required and missing', async () => {
    const trust = createTrustContext({
      reputationScore: 0.9,
      killSwitchEngaged: false,
      recentIncidents: 0,
      capabilityHighRisk: true,
      requiresRuntimeAttestation: true,
    })

    const result = await evaluateGuard({
      agentDid: 'did:test:agent',
      capabilityId: 'wallets.sign',
      policy: defaultPolicy,
      context: { requestCount: 10 },
      trust,
    })

    expect(result.decision).toBe('deny')
    expect(result.explanation).toContain('Runtime attestation is required')
  })

  it('requires approval for high-risk capabilities when approval is missing', async () => {
    const trust = createTrustContext({
      reputationScore: 0.9,
      killSwitchEngaged: false,
      recentIncidents: 0,
      capabilityHighRisk: true,
      requiresApproval: true,
    })

    const result = await evaluateGuard({
      agentDid: 'did:test:agent',
      capabilityId: 'payments.execute',
      policy: defaultPolicy,
      context: { requestCount: 10 },
      trust,
    })

    expect(result.decision).toBe('approve-required')
    expect(result.explanation).toContain('Approval is required')
  })

  it('allows high-risk capabilities when required approval is granted', async () => {
    const trust = createTrustContext({
      reputationScore: 0.9,
      killSwitchEngaged: false,
      recentIncidents: 0,
      capabilityHighRisk: true,
      requiresApproval: true,
      approvalGranted: true,
    })

    const result = await evaluateGuard({
      agentDid: 'did:test:agent',
      capabilityId: 'payments.execute',
      policy: defaultPolicy,
      context: { requestCount: 10 },
      trust,
    })

    expect(result.decision).toBe('allow')
    expect(result.factors.some(f => f.factor === 'high-risk-capability')).toBe(true)
  })

  it('allows with good trust and valid policy', async () => {
    const trust = createTrustContext({
      reputationScore: 0.9,
      killSwitchEngaged: false,
      recentIncidents: 0,
    })

    const result = await evaluateGuard({
      agentDid: 'did:test:agent',
      capabilityId: 'email:send',
      policy: defaultPolicy,
      context: { requestCount: 10 },
      trust,
    })

    expect(result.decision).toBe('allow')
    expect(result.factors.some(f => f.source === 'trust')).toBe(true)
  })

  it('downgrades to dry-run when trust is low', async () => {
    const trust = createTrustContext({
      reputationScore: 0.15,
      killSwitchEngaged: false,
      recentIncidents: 0,
    })

    const result = await evaluateGuard({
      agentDid: 'did:test:agent',
      capabilityId: 'email:send',
      policy: defaultPolicy,
      context: { requestCount: 10 },
      trust,
    })

    expect(result.decision).toBe('dry-run')
    expect(result.explanation).toContain('dry-run')
  })

  it('respects policy deny rules', async () => {
    const trust = createTrustContext({
      reputationScore: 0.9,
      killSwitchEngaged: false,
      recentIncidents: 0,
    })

    const result = await evaluateGuard({
      agentDid: 'did:test:agent',
      capabilityId: 'email:send',
      policy: defaultPolicy,
      context: { requestCount: 200 },
      trust,
    })

    expect(result.decision).toBe('deny')
    expect(result.explanation).toContain('Denied')
  })

  it('includes capability score in factors', async () => {
    const trust = createTrustContext({
      reputationScore: 0.9,
      capabilityScore: 0.95,
      killSwitchEngaged: false,
      recentIncidents: 0,
    })

    const result = await evaluateGuard({
      agentDid: 'did:test:agent',
      capabilityId: 'email:send',
      policy: defaultPolicy,
      context: { requestCount: 10 },
      trust,
    })

    expect(result.factors.some(f => f.factor === 'capability-score-ok')).toBe(true)
  })
})
