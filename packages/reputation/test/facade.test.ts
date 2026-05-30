import { describe, expect, it } from 'vitest'
import { computeCapabilityReputation } from '../src/index.js'

describe('@fides/reputation facade', () => {
  it('exports capability-scoped reputation primitives', () => {
    const reputation = computeCapabilityReputation({
      agentId: 'did:fides:agent',
      capability: 'invoice.reconcile',
      successfulInvocations: 10,
      failedInvocations: 0,
    })

    expect(reputation.capability).toBe('invoice.reconcile')
    expect(reputation.score).toBeGreaterThan(0)
  })
})
