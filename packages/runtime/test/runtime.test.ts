import { describe, it, expect } from 'vitest'
import {
  AwsNitroTEEAdapter,
  BuildProvenanceAttestationProvider,
  ContainerImageAttestationProvider,
  GitHubActionsAttestationProvider,
  InMemoryKillSwitch,
  MockTEEProvider,
  PackageRegistryAttestationProvider,
} from '../src/index.js'
import type { KillSwitchTarget } from '../src/index.js'

describe('MockTEEProvider', () => {
  it('should create and verify attestation', async () => {
    const provider = new MockTEEProvider()
    const attestation = await provider.attest('did:fides:agent1')

    expect(attestation.provider).toBe('mock-tee')
    expect(attestation.agentDid).toBe('did:fides:agent1')
    expect(attestation.signature).toMatch(/^local-attestation:/)

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

  it('rejects tampered mock attestation fields', async () => {
    const provider = new MockTEEProvider()
    const attestation = await provider.attest('did:fides:agent1')
    attestation.measurement = 'mock-measurement-did:fides:agent2'

    await expect(provider.verify(attestation)).resolves.toBe(false)
  })
})

describe('Production attestation adapters', () => {
  it('verifies build provenance attestations', async () => {
    const provider = new BuildProvenanceAttestationProvider()
    const attestation = await provider.attest({
      agentDid: 'did:fides:agent1',
      imageDigest: 'sha256:abc',
      sourceCommit: 'abc123',
      builderId: 'builder://github/actions',
    })

    expect(attestation.provider).toBe('build-provenance')
    expect(await provider.verify(attestation)).toBe(true)

    attestation.measurement = 'sha256:tampered'
    expect(await provider.verify(attestation)).toBe(false)
  })

  it('rejects tampered local structured attestation signatures', async () => {
    const provider = new BuildProvenanceAttestationProvider()
    const attestation = await provider.attest({
      agentDid: 'did:fides:agent1',
      imageDigest: 'sha256:abc',
      sourceCommit: 'abc123',
      builderId: 'builder://github/actions',
    })

    attestation.signature = 'local-attestation:tampered'
    await expect(provider.verify(attestation)).resolves.toBe(false)
  })

  it('verifies container image attestations against allowed images', async () => {
    const provider = new ContainerImageAttestationProvider([
      { registry: 'ghcr.io', repository: 'efedurmaz16/fides-agent' },
    ])
    const digest = `sha256:${'a'.repeat(64)}`
    const attestation = await provider.attest({
      agentDid: 'did:fides:agent1',
      registry: 'ghcr.io',
      repository: 'efedurmaz16/fides-agent',
      digest,
      tag: 'main',
      sourceCommit: 'abc123',
    })

    expect(attestation.provider).toBe('container-image')
    expect(attestation.measurement).toBe(digest)
    expect(await provider.verify(attestation)).toBe(true)

    ;(attestation.evidence as any).repository = 'other/image'
    expect(await provider.verify(attestation)).toBe(false)
  })

  it('rejects malformed container image digests', async () => {
    const provider = new ContainerImageAttestationProvider()
    const attestation = await provider.attest({
      agentDid: 'did:fides:agent1',
      registry: 'ghcr.io',
      repository: 'efedurmaz16/fides-agent',
      digest: 'sha256:not-a-real-digest',
    })

    expect(await provider.verify(attestation)).toBe(false)
  })

  it('verifies GitHub Actions attestations against allowed repositories', async () => {
    const provider = new GitHubActionsAttestationProvider(['EfeDurmaz16/fides'])
    const attestation = await provider.attest({
      agentDid: 'did:fides:agent1',
      repository: 'EfeDurmaz16/fides',
      workflowRef: 'EfeDurmaz16/fides/.github/workflows/ci.yml@refs/heads/main',
      sha: 'abc123',
      runId: '42',
    })

    expect(await provider.verify(attestation)).toBe(true)
    ;(attestation.evidence as any).repository = 'other/repo'
    expect(await provider.verify(attestation)).toBe(false)
  })

  it('verifies package registry attestations', async () => {
    const provider = new PackageRegistryAttestationProvider()
    const attestation = await provider.attest({
      agentDid: 'did:fides:agent1',
      registry: 'npm',
      packageName: '@fides/core',
      version: '0.1.0',
      integrity: 'sha512-test',
    })

    expect(await provider.verify(attestation)).toBe(true)
  })

  it('uses HTTP TEE verifier endpoints for Nitro-style adapters', async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = (async (url: string | URL | Request) => {
      if (String(url).endsWith('/attest')) {
        return new Response(JSON.stringify({
          id: 'att-1',
          agentDid: 'did:fides:agent1',
          provider: 'aws-nitro',
          measurement: 'pcr0:test',
          timestamp: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 3600_000).toISOString(),
          evidence: { document: 'nitro-doc' },
          signature: 'sig',
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({ valid: true }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    }) as typeof fetch

    try {
      const adapter = new AwsNitroTEEAdapter('https://attestor.example')
      const attestation = await adapter.attest('did:fides:agent1')
      expect(attestation.provider).toBe('aws-nitro')
      expect(await adapter.verify(attestation)).toBe(true)
    } finally {
      globalThis.fetch = originalFetch
    }
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

  it('should disengage every scoped kill switch', () => {
    const ks = new InMemoryKillSwitch()
    const agent: KillSwitchTarget = { type: 'agent', did: 'did:fides:alice' }
    const capability: KillSwitchTarget = { type: 'capability', id: 'payments.execute' }

    ks.engage({ type: 'global' })
    ks.engage(agent)
    ks.engage(capability)

    ks.disengageAll()

    expect(ks.isEngaged({ type: 'global' })).toBe(false)
    expect(ks.isEngaged(agent)).toBe(false)
    expect(ks.isEngaged(capability)).toBe(false)
  })
})
