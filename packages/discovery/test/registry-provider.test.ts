import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createAgentIdentity, signAgentCard, type AgentCard } from '@fides/core'
import { RegistryDiscoveryProvider } from '../src/registry-provider.js'

describe('RegistryDiscoveryProvider', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
  })

  async function signedCard() {
    const agent = await createAgentIdentity()
    const card: AgentCard = {
      id: agent.identity.did,
      agent_id: agent.identity.did,
      identity: agent.identity,
      capabilities: [],
      endpoints: [],
      policies: [{ requiresRuntimeAttestation: false, requiresApproval: false }],
      createdAt: '2026-05-30T00:00:00.000Z',
      updatedAt: '2026-05-30T00:00:00.000Z',
    }
    return {
      agent,
      card,
      signed: await signAgentCard(card, agent.privateKey, agent.identity.did),
    }
  }

  it('publishes identity-bound signed AgentCards to the registry', async () => {
    const { signed } = await signedCard()
    fetchMock.mockResolvedValueOnce({ ok: true })
    const registry = new RegistryDiscoveryProvider({ baseUrl: 'https://registry.example' })

    await expect(registry.register(signed)).resolves.toBeUndefined()

    expect(fetchMock).toHaveBeenCalledWith(
      'https://registry.example/v1/cards',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify(signed),
      }),
    )
  })

  it('rejects AgentCards not signed by the advertised agent identity before publishing', async () => {
    const { card } = await signedCard()
    const attacker = await createAgentIdentity()
    const signed = await signAgentCard(card, attacker.privateKey, attacker.identity.did)
    const registry = new RegistryDiscoveryProvider({ baseUrl: 'https://registry.example' })

    await expect(registry.register(signed)).rejects.toThrow(
      'Registry registration requires an identity-bound signed AgentCard',
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
