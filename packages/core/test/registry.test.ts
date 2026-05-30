import { describe, expect, it } from 'vitest'
import { createIdentityKeyPair } from '../src/identity.js'
import {
  createRegistryIndexRecord,
  createRegistryPeerRecord,
  isRegistryIndexRecordExpired,
  isRegistryPeerRecordExpired,
  signRegistryIndexRecord,
  signRegistryPeerRecord,
  verifySignedRegistryIndexRecord,
  verifySignedRegistryPeerRecord,
} from '../src/registry.js'

describe('registry and federation records', () => {
  it('creates and verifies signed registry index records', async () => {
    const issuer = await createIdentityKeyPair()
    const record = createRegistryIndexRecord({
      issuer: issuer.did,
      mode: 'public',
      agentCardId: 'card_123',
      agentId: 'did:fides:agent',
      capabilityIds: ['invoice.reconcile'],
      agentCardHash: 'sha256:card',
      registryUrl: 'https://registry.example',
      supportedVersions: ['fides.v2.0'],
    })

    expect(record).toMatchObject({
      schema_version: 'fides.registry.index.v1',
      issuer: issuer.did,
      mode: 'public',
      agent_id: 'did:fides:agent',
      capability_ids: ['invoice.reconcile'],
      supported_versions: ['fides.v2.0'],
    })

    const signed = await signRegistryIndexRecord(record, issuer.privateKey, issuer.did)
    expect(await verifySignedRegistryIndexRecord(signed)).toBe(true)
  })

  it('creates and verifies signed federation peer records', async () => {
    const issuer = await createIdentityKeyPair()
    const record = createRegistryPeerRecord({
      issuer: issuer.did,
      peerId: 'peer_1',
      registryUrl: 'https://peer.example',
      trustDomain: 'example',
      peeringMode: 'private',
      supportedVersions: ['fides.v2.0'],
      capabilities: ['revocation_propagation', 'incident_propagation'],
    })

    expect(record).toMatchObject({
      schema_version: 'fides.registry.peer.v1',
      peer_id: 'peer_1',
      peering_mode: 'private',
      capabilities: ['revocation_propagation', 'incident_propagation'],
    })

    const signed = await signRegistryPeerRecord(record, issuer.privateKey, issuer.did)
    expect(await verifySignedRegistryPeerRecord(signed)).toBe(true)
  })

  it('detects expired registry and federation records', async () => {
    const issuer = await createIdentityKeyPair()
    const expiredAt = '2026-05-29T00:00:00.000Z'
    const now = new Date('2026-05-30T00:00:00.000Z')

    expect(isRegistryIndexRecordExpired(createRegistryIndexRecord({
      issuer: issuer.did,
      mode: 'hosted',
      agentCardId: 'card_expired',
      agentId: 'did:fides:agent',
      capabilityIds: ['calendar.schedule'],
      agentCardHash: 'sha256:card',
      registryUrl: 'https://registry.example',
      supportedVersions: ['fides.v2.0'],
      expiresAt: expiredAt,
    }), now)).toBe(true)

    expect(isRegistryPeerRecordExpired(createRegistryPeerRecord({
      issuer: issuer.did,
      peerId: 'peer_expired',
      registryUrl: 'https://peer.example',
      peeringMode: 'federated',
      supportedVersions: ['fides.v2.0'],
      capabilities: ['registry_search'],
      expiresAt: expiredAt,
    }), now)).toBe(true)
  })
})
