import { describe, expect, it } from 'vitest'
import { computeTrustResult, trustBandForScore } from '../src/index.js'

describe('@fides/trust facade', () => {
  it('exports trust scoring primitives', () => {
    const result = computeTrustResult({
      agentId: 'did:fides:agent',
      capability: { id: 'calendar.schedule', riskLevel: 'low', requiredScopes: [] },
      components: {
        identity: 1,
        publisher: 1,
        trustAnchors: 1,
        capabilityFit: 1,
        evidence: 1,
        policyCompliance: 1,
        runtimeSafety: 1,
        peerAttestation: 1,
        incidentPenalty: 0,
        noveltyPenalty: 0,
        contextBoundaryPenalty: 0,
      },
    })

    expect(result.band).toBe('verified')
    expect(trustBandForScore(result.score)).toBe('verified')
  })
})
