import { describe, expect, it } from 'vitest'
import { evaluateFidesPolicy } from '../src/index.js'
import type { CapabilityDescriptor, TrustResult } from '@fides/core'

const capability = (riskLevel: CapabilityDescriptor['riskLevel']): CapabilityDescriptor => ({
  id: riskLevel === 'critical' ? 'payments.execute' : 'invoice.reconcile',
  namespace: riskLevel === 'critical' ? 'payments' : 'invoice',
  action: riskLevel === 'critical' ? 'execute' : 'reconcile',
  name: riskLevel,
  description: riskLevel,
  inputSchema: { type: 'object' },
  outputSchema: { type: 'object' },
  riskLevel,
  requiresApproval: riskLevel === 'critical',
  requiresRuntimeAttestation: riskLevel === 'high' || riskLevel === 'critical',
  requiredScopes: riskLevel === 'critical' ? ['payments:execute'] : ['invoice:read'],
  supportedControls: ['dry_run', 'human_approval', 'runtime_attestation', 'scope_limit'],
})

const trust = (band: TrustResult['band'], score: number): TrustResult => ({
  schema_version: 'fides.trust.result.v1',
  agent_id: 'did:fides:agent',
  capability: 'invoice.reconcile',
  score,
  band,
  reasons: [],
  risk_flags: [],
  evidence_refs: ['evt_1'],
  required_controls: [],
  computed_at: '2026-05-29T00:00:00.000Z',
})

describe('FIDES policy v2', () => {
  it('denies revoked agents before trust or capability scoring', () => {
    const decision = evaluateFidesPolicy({
      principalId: 'did:fides:principal',
      requesterAgentId: 'did:fides:requester',
      targetAgentId: 'did:fides:agent',
      capability: capability('low'),
      trustResult: trust('verified', 0.95),
      requestedScopes: ['invoice:read'],
      revocationActive: true,
    })

    expect(decision.decision).toBe('deny')
    expect(decision.reason_codes).toContain('REVOCATION_ACTIVE')
    expect(decision.human_reasons[0]).toContain('revocation')
  })

  it('lets unknown agents dry-run only instead of granting authority', () => {
    const decision = evaluateFidesPolicy({
      principalId: 'did:fides:principal',
      requesterAgentId: 'did:fides:requester',
      targetAgentId: 'did:fides:agent',
      capability: capability('medium'),
      trustResult: trust('unknown', 0.1),
      requestedScopes: ['invoice:read'],
    })

    expect(decision.decision).toBe('dry_run_only')
    expect(decision.required_controls).toEqual(expect.arrayContaining(['dry_run']))
    expect(decision.reason_codes).toContain('TRUST_UNKNOWN_DRY_RUN_ONLY')
  })

  it('requires runtime attestation or approval for high-risk capabilities', () => {
    const decision = evaluateFidesPolicy({
      principalId: 'did:fides:principal',
      requesterAgentId: 'did:fides:requester',
      targetAgentId: 'did:fides:agent',
      capability: capability('high'),
      trustResult: trust('high', 0.74),
      requestedScopes: ['invoice:read'],
      runtimeAttestationValid: false,
    })

    expect(decision.decision).toBe('require_approval')
    expect(decision.required_controls).toEqual(expect.arrayContaining([
      'runtime_attestation',
      'human_approval',
    ]))
    expect(decision.reason_codes).toContain('HIGH_RISK_REQUIRES_ATTESTATION_OR_APPROVAL')
  })

  it('allows scoped medium-risk actions with compatible trust and scopes', () => {
    const decision = evaluateFidesPolicy({
      principalId: 'did:fides:principal',
      requesterAgentId: 'did:fides:requester',
      targetAgentId: 'did:fides:agent',
      capability: capability('medium'),
      trustResult: trust('high', 0.72),
      requestedScopes: ['invoice:read'],
      runtimeAttestationValid: false,
    })

    expect(decision.decision).toBe('allow')
    expect(decision.reason_codes).toContain('POLICY_ALLOWED')
    expect(decision.machine_reasons.length).toBeGreaterThan(0)
  })
})
