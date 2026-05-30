import { describe, expect, it } from 'vitest'
import {
  MockTEEProvider,
  createAttestation,
  signAttestation,
  verifyRuntimeAttestation,
  verifySignedAttestationIssuer,
} from '../src/index.js'
import { createAgentIdentity } from '@fides/core'

describe('@fides/attestations facade', () => {
  it('exports generic canonical Attestation primitives', async () => {
    const issuer = await createAgentIdentity()
    const attestation = createAttestation({
      issuer: issuer.identity.did,
      subject: 'did:fides:agent',
      subjectType: 'agent',
      provider: 'github',
      claims: { handle: 'fides-dev' },
      evidenceRefs: ['evt_github_1'],
    })

    const signed = await signAttestation(attestation, issuer.privateKey, issuer.identity.did)

    expect(attestation.schema_version).toBe('fides.attestation.v1')
    expect(attestation.payload_hash).toMatch(/^sha256:/)
    expect(await verifySignedAttestationIssuer(signed)).toBe(true)
  })

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
