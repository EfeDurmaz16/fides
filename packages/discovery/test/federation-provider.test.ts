import { describe, expect, it } from 'vitest'
import {
  createAgentIdentity,
  createCapabilityDescriptor,
  createDiscoveryQuery,
  createRegistryPeerRecord,
  signRegistryPeerRecord,
  type AgentCard,
} from '@fides/core'
import { LocalDiscoveryProvider } from '../src/local-provider.js'
import { LocalFederationDiscoveryProvider } from '../src/federation-provider.js'

describe('LocalFederationDiscoveryProvider', () => {
  async function fixture(options: { capabilities?: Array<'registry_search' | 'revocation_propagation'>; expiresAt?: string } = {}) {
    const issuer = await createAgentIdentity()
    const agent = await createAgentIdentity()
    const card: AgentCard = {
      id: agent.identity.did,
      agent_id: agent.identity.did,
      identity: agent.identity,
      capabilities: [createCapabilityDescriptor({ id: 'invoice.reconcile' })],
      endpoints: [],
      policies: [{ requiresRuntimeAttestation: false, requiresApproval: false }],
      createdAt: '2026-05-30T00:00:00.000Z',
      updatedAt: '2026-05-30T00:00:00.000Z',
    }
    const local = new LocalDiscoveryProvider({ storePath: `/tmp/fides-federation-${crypto.randomUUID()}.json` })
    local.registerCard(card)
    const record = createRegistryPeerRecord({
      issuer: issuer.identity.did,
      peerId: 'peer_registry',
      registryUrl: 'https://peer.example',
      peeringMode: 'federated',
      supportedVersions: ['fides.v2.0'],
      capabilities: options.capabilities ?? ['registry_search'],
      expiresAt: options.expiresAt,
    })
    const signed = await signRegistryPeerRecord(record, issuer.privateKey, issuer.identity.did)
    return { card, local, signed }
  }

  it('discovers candidates through signed federation peers without granting authority', async () => {
    const { local, signed } = await fixture()
    const federation = new LocalFederationDiscoveryProvider({
      peers: [{ record: signed, provider: local }],
    })

    const candidates = await federation.discover(createDiscoveryQuery({ capability: 'invoice.reconcile' }))

    expect(candidates).toHaveLength(1)
    expect(candidates[0]).toMatchObject({
      provider: 'federation',
      capability: 'invoice.reconcile',
      verified: false,
    })
    expect(candidates[0].explanations[0]).toContain('federation is not authority')
  })

  it('ignores expired peers and peers without registry search capability', async () => {
    const expired = await fixture({ expiresAt: '2000-01-01T00:00:00.000Z' })
    const propagationOnly = await fixture({ capabilities: ['revocation_propagation'] })
    const federation = new LocalFederationDiscoveryProvider({
      peers: [
        { record: expired.signed, provider: expired.local },
        { record: propagationOnly.signed, provider: propagationOnly.local },
      ],
    })

    await expect(federation.discover(createDiscoveryQuery({ capability: 'invoice.reconcile' })))
      .resolves.toEqual([])
  })
})
