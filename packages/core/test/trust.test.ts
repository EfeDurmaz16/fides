import { describe, expect, it } from 'vitest'
import {
  computeTrustResult,
  trustBandForScore,
  type TrustScoreComponents,
} from '../src/trust.js'
import type { CapabilityDescriptor } from '../src/capability.js'

const mediumCapability: CapabilityDescriptor = {
  id: 'invoice.reconcile',
  namespace: 'invoice',
  action: 'reconcile',
  description: 'Reconcile invoices',
  inputSchema: {},
  outputSchema: {},
  riskLevel: 'medium',
  requiresApproval: false,
  requiresRuntimeAttestation: false,
  requiredScopes: ['read:invoices'],
  supportedControls: ['policy_proof'],
}

const highRiskCapability: CapabilityDescriptor = {
  ...mediumCapability,
  id: 'payments.prepare',
  namespace: 'payments',
  action: 'prepare',
  riskLevel: 'high',
  requiresApproval: true,
  requiresRuntimeAttestation: true,
  requiredScopes: ['payments:prepare'],
  supportedControls: ['dry_run', 'human_approval', 'runtime_attestation'],
}

describe('TrustResult v2', () => {
  it('maps trust scores to stable bands', () => {
    expect(trustBandForScore(0.05)).toBe('unknown')
    expect(trustBandForScore(0.2)).toBe('low')
    expect(trustBandForScore(0.45)).toBe('medium')
    expect(trustBandForScore(0.7)).toBe('high')
    expect(trustBandForScore(0.95)).toBe('verified')
  })

  it('computes a capability-specific trust result with explainability', () => {
    const components: TrustScoreComponents = {
      identity: 0.8,
      publisher: 0.7,
      trustAnchors: 0.6,
      capabilityFit: 0.9,
      evidence: 0.7,
      policyCompliance: 0.8,
      runtimeSafety: 0.6,
      peerAttestation: 0.4,
      incidentPenalty: 0.1,
      noveltyPenalty: 0.05,
      contextBoundaryPenalty: 0,
    }

    const result = computeTrustResult({
      agentId: 'did:fides:agent',
      capability: mediumCapability,
      components,
      evidenceRefs: ['evt_1'],
    })

    expect(result).toMatchObject({
      schema_version: 'fides.trust.result.v1',
      agent_id: 'did:fides:agent',
      capability: 'invoice.reconcile',
      band: 'high',
      evidence_refs: ['evt_1'],
      required_controls: [],
    })
    expect(result.score).toBeGreaterThan(0.6)
    expect(result.reasons.map(reason => reason.component)).toEqual(expect.arrayContaining([
      'IdentityScore',
      'CapabilityFitScore',
      'IncidentPenalty',
    ]))
  })

  it('requires controls for high-risk capabilities when runtime safety is weak', () => {
    const result = computeTrustResult({
      agentId: 'did:fides:payment',
      capability: highRiskCapability,
      components: {
        identity: 0.8,
        publisher: 0.8,
        trustAnchors: 0.7,
        capabilityFit: 0.8,
        evidence: 0.5,
        policyCompliance: 0.7,
        runtimeSafety: 0.1,
        peerAttestation: 0.3,
        incidentPenalty: 0,
        noveltyPenalty: 0.1,
        contextBoundaryPenalty: 0,
      },
    })

    expect(result.required_controls).toEqual(expect.arrayContaining([
      'runtime_attestation',
      'human_approval',
    ]))
    expect(result.risk_flags).toEqual(expect.arrayContaining(['runtime_safety_low']))
  })
})
