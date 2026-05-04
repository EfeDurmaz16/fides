import { describe, it, expect } from 'vitest'
import { MockTEEProvider, InMemoryKillSwitch } from '../src/index.js'
import type { KillSwitchTarget } from '../src/index.js'

describe('MockTEEProvider', () => {
  it('should create and verify attestation', async () => {
    const provider = new MockTEEProvider()
    const attestation = await provider.attest('did:fides:agent1')

    expect(attestation.provider).toBe('mock-tee')
    expect(attestation.agentDid).toBe('did:fides:agent1')

    const valid = await provider.verify(attestation)
    expect(valid).toBe(true)
  })

  it('should reject expired attestation', async () => {
    const provider = new MockTEEProvider()
    const attestation = await provider.attest('did:fides:agent1')
    attestation.expiresAt = new Date(Date.now() - 1000).toISOString()

    const valid = await provider.verify(attestation)
    expect(valid).toBe(false)
  })
})

describe('InMemoryKillSwitch', () => {
  it('should engage and disengage per agent', () => {
    const ks = new InMemoryKillSwitch()
    const target: KillSwitchTarget = { type: 'agent', did: 'did:fides:alice' }

    expect(ks.isEngaged(target)).toBe(false)
    ks.engage(target)
    expect(ks.isEngaged(target)).toBe(true)
    ks.disengage(target)
    expect(ks.isEngaged(target)).toBe(false)
  })

  it('should global override agent state', () => {
    const ks = new InMemoryKillSwitch()
    const agent: KillSwitchTarget = { type: 'agent', did: 'did:fides:alice' }

    ks.engage({ type: 'global' })
    expect(ks.isEngaged(agent)).toBe(true)

    ks.disengage({ type: 'global' })
    expect(ks.isEngaged(agent)).toBe(false)
  })
})
