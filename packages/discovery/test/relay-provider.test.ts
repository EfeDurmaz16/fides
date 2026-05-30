import { beforeEach, describe, expect, it, vi } from 'vitest'
import { RelayDiscoveryProvider } from '../src/relay-provider.js'
import { createAgentIdentity, signAgentCard, type AgentCard } from '@fides/core'

describe('RelayDiscoveryProvider', () => {
  const fetchMock = vi.fn()
  const card: AgentCard = {
    id: 'did:fides:relay-agent',
    identity: {
      did: 'did:fides:relay-agent',
      publicKey: new Uint8Array(32),
      keyType: 'Ed25519',
      createdAt: '2026-01-01T00:00:00.000Z',
    },
    capabilities: [],
    endpoints: [],
    policies: [{ requiresRuntimeAttestation: false, requiresApproval: false }],
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  }
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
  })

  it('resolves agent cards from relay messages', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        count: 1,
        messages: [{
          id: 'relay-1',
          to: card.id,
          from: 'publisher',
          status: 'pending',
          createdAt: card.createdAt,
          expiresAt: card.updatedAt,
          payload: {
            type: 'fides.agent_card',
            card,
          },
        }],
      }),
    })

    const provider = new RelayDiscoveryProvider({ relayUrl: 'http://relay.test/' })

    await expect(provider.resolve(card.id)).resolves.toEqual(card)
    expect(fetchMock).toHaveBeenCalledWith('http://relay.test/v1/relay/did%3Afides%3Arelay-agent/messages')
  })

  it('ignores invalid or mismatched relay payloads', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        count: 2,
        messages: [
          { id: 'relay-1', to: card.id, from: 'publisher', status: 'pending', createdAt: card.createdAt, expiresAt: card.updatedAt, payload: { card: { id: card.id } } },
          { id: 'relay-2', to: card.id, from: 'publisher', status: 'pending', createdAt: card.createdAt, expiresAt: card.updatedAt, payload: { card: { ...card, id: 'did:fides:other' } } },
        ],
      }),
    })

    const provider = new RelayDiscoveryProvider({ relayUrl: 'http://relay.test' })

    await expect(provider.resolve(card.id)).resolves.toBeNull()
  })

  it('registers signed agent cards through the relay service', async () => {
    const agent = await createAgentIdentity()
    const agentCard = {
      ...card,
      id: agent.identity.did,
      identity: agent.identity,
    }
    const signedCard = await signAgentCard(agentCard, agent.privateKey, agent.identity.did)
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ accepted: true, relayId: 'relay-1' }),
    })

    const provider = new RelayDiscoveryProvider({
      relayUrl: 'http://relay.test',
      apiKey: 'relay-key',
      from: 'did:fides:publisher',
    })

    await expect(provider.register(signedCard)).resolves.toBeUndefined()

    expect(fetchMock).toHaveBeenCalledWith(
      'http://relay.test/v1/relay',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          to: agent.identity.did,
          from: 'did:fides:publisher',
          payload: {
            type: 'fides.agent_card',
            card: signedCard.payload,
          },
        }),
      })
    )
    const [, init] = fetchMock.mock.calls[0]
    expect((init.headers as Headers).get('Content-Type')).toBe('application/json')
    expect((init.headers as Headers).get('X-API-Key')).toBe('relay-key')
  })

  it('rejects AgentCards not signed by the advertised agent identity', async () => {
    const agent = await createAgentIdentity()
    const attacker = await createAgentIdentity()
    const agentCard = {
      ...card,
      id: agent.identity.did,
      identity: agent.identity,
    }
    const signedCard = await signAgentCard(agentCard, attacker.privateKey, attacker.identity.did)
    const provider = new RelayDiscoveryProvider({ relayUrl: 'http://relay.test' })

    await expect(provider.register(signedCard)).rejects.toThrow(
      'Relay registration requires an identity-bound signed AgentCard',
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
