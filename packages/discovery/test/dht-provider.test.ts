import { describe, expect, it } from 'vitest'
import { DHTDiscoveryProvider } from '../src/dht-provider.js'
import {
  createAgentIdentity,
  createCapabilityDescriptor,
  createDHTPointerRecord,
  createDiscoveryQuery,
  hashAgentCard,
  signAgentCard,
  signDHTPointerRecord,
  type AgentCard,
} from '@fides/core'

describe('DHTDiscoveryProvider', () => {
  async function fixture() {
    const publisher = await createAgentIdentity()
    const agent = await createAgentIdentity()
    const card: AgentCard = {
      id: agent.identity.did,
      agent_id: agent.identity.did,
      identity: agent.identity,
      capabilities: [createCapabilityDescriptor({ id: 'invoice.reconcile' })],
      endpoints: [{ url: 'https://agent.example/card.json', protocol: 'https' }],
      policies: [{ requiresRuntimeAttestation: false, requiresApproval: false }],
      createdAt: '2026-05-29T00:00:00.000Z',
      updatedAt: '2026-05-29T00:00:00.000Z',
    }
    const signedCard = await signAgentCard(card, agent.privateKey, agent.identity.did)
    const pointer = await signDHTPointerRecord(createDHTPointerRecord({
      capability: 'invoice.reconcile',
      agentId: agent.identity.did,
      agentCardUrl: 'https://agent.example/card.json',
      agentCardHash: hashAgentCard(signedCard.payload),
      publisherId: publisher.identity.did,
      expiresAt: '2999-01-01T00:00:00.000Z',
    }), publisher.privateKey)
    return { card, signedCard, pointer }
  }

  it('discovers cards through signed DHT pointers', async () => {
    const { signedCard, pointer } = await fixture()
    const provider = new DHTDiscoveryProvider()

    await provider.register(signedCard)
    await provider.publishPointer(pointer)

    const candidates = await provider.discover(createDiscoveryQuery({
      capability: 'invoice.reconcile',
    }))

    expect(candidates).toHaveLength(1)
    expect(candidates[0]).toMatchObject({
      provider: 'dht',
      capability: 'invoice.reconcile',
      verified: true,
    })
    expect(candidates[0].explanations[0]).toContain('not an authority')
  })

  it('does not return mismatched capability pointers', async () => {
    const { signedCard, pointer } = await fixture()
    const provider = new DHTDiscoveryProvider()

    await provider.register(signedCard)
    await provider.publishPointer(pointer)

    const candidates = await provider.discover(createDiscoveryQuery({
      capability: 'calendar.schedule',
    }))

    expect(candidates).toEqual([])
  })
})
