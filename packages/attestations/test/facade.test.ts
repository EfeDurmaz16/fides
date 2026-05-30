import { describe, expect, it } from 'vitest'
import { MockTEEProvider, verifyRuntimeAttestation } from '../src/index.js'

describe('@fides/attestations facade', () => {
  it('exports MockTEE issue and verify primitives', async () => {
    const provider = new MockTEEProvider()
    const hash = (value: string) => `sha256:${value.repeat(64).slice(0, 64)}`
    const attestation = await provider.issue({
      agentId: 'did:fides:agent',
      codeHash: hash('a'),
      runtimeHash: hash('b'),
      policyHash: hash('c'),
    })

    expect(attestation.provider).toBe('mock-tee')
    expect(await verifyRuntimeAttestation(attestation, provider)).toBe(true)
  })
})
