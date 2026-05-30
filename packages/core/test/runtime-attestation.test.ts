import { describe, expect, it } from 'vitest'
import {
  MockTEEProvider,
  NullAttestationProvider,
  isRuntimeAttestationExpired,
  verifyRuntimeAttestation,
} from '../src/runtime-attestation.js'

describe('runtime attestation v2', () => {
  it('issues and verifies mock TEE attestations with the FIDES v2 schema', async () => {
    const provider = new MockTEEProvider()
    const attestation = await provider.issue({
      agentId: 'did:fides:agent',
      codeHash: `sha256:${'a'.repeat(64)}`,
      runtimeHash: `sha256:${'b'.repeat(64)}`,
      policyHash: `sha256:${'c'.repeat(64)}`,
    })

    expect(attestation).toMatchObject({
      schema_version: 'fides.runtime_attestation.v1',
      id: expect.any(String),
      issuer: 'mock-tee',
      subject: 'did:fides:agent',
      agent_id: 'did:fides:agent',
      provider: 'mock-tee',
      code_hash: `sha256:${'a'.repeat(64)}`,
      runtime_hash: `sha256:${'b'.repeat(64)}`,
      policy_hash: `sha256:${'c'.repeat(64)}`,
      enclave_measurement: expect.stringMatching(/^sha256:/),
    })
    expect(attestation.attestation_id).toBe(attestation.id)
    expect(attestation.payload_hash).toMatch(/^sha256:/)
    expect(attestation.signature).toMatch(/^local-attestation:/)
    expect(await provider.verify(attestation)).toBe(true)
    expect(await verifyRuntimeAttestation(attestation, provider)).toBe(true)
  })

  it('rejects tampered mock TEE attestation payload fields', async () => {
    const provider = new MockTEEProvider()
    const attestation = await provider.issue({
      agentId: 'did:fides:agent',
      codeHash: `sha256:${'a'.repeat(64)}`,
      runtimeHash: `sha256:${'b'.repeat(64)}`,
      policyHash: `sha256:${'c'.repeat(64)}`,
    })

    attestation.code_hash = `sha256:${'d'.repeat(64)}`

    expect(await provider.verify(attestation)).toBe(false)
    expect(await verifyRuntimeAttestation(attestation, provider)).toBe(false)
  })

  it('rejects expired attestations', async () => {
    const provider = new MockTEEProvider()
    const attestation = await provider.issue({
      agentId: 'did:fides:agent',
      codeHash: `sha256:${'a'.repeat(64)}`,
      runtimeHash: `sha256:${'b'.repeat(64)}`,
      policyHash: `sha256:${'c'.repeat(64)}`,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    })

    expect(isRuntimeAttestationExpired(attestation)).toBe(true)
    expect(await provider.verify(attestation)).toBe(false)
  })

  it('null provider is explicit and never verifies high-risk attestations', async () => {
    const provider = new NullAttestationProvider()
    const attestation = await provider.issue({
      agentId: 'did:fides:agent',
      codeHash: `sha256:${'a'.repeat(64)}`,
      runtimeHash: `sha256:${'b'.repeat(64)}`,
      policyHash: `sha256:${'c'.repeat(64)}`,
    })

    expect(attestation.provider).toBe('null')
    expect(attestation.issuer).toBe('null')
    expect(attestation.subject).toBe('did:fides:agent')
    expect(attestation.payload_hash).toMatch(/^sha256:/)
    expect(await provider.verify(attestation)).toBe(false)
  })
})
