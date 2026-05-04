import { describe, it, expect, vi } from 'vitest'
import { DiscoveryOrchestrator } from '../src/orchestrator.js'
import { WellKnownDiscoveryProvider } from '../src/well-known-provider.js'
import { RegistryDiscoveryProvider } from '../src/registry-provider.js'
import type { DiscoveryProvider } from '../src/provider.js'
import type { AgentCard } from '@fides/core'

describe('DiscoveryOrchestrator', () => {
  const mockCard: AgentCard = {
    id: 'did:fides:agent1',
    identity: {
      did: 'did:fides:agent1',
      publicKey: new Uint8Array(32),
      keyType: 'Ed25519',
      createdAt: new Date().toISOString(),
    },
    capabilities: [],
    endpoints: [],
    policies: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  it('should return card from first successful provider', async () => {
    const provider1: DiscoveryProvider = {
      name: 'p1',
      resolve: vi.fn().mockResolvedValue(null),
    }
    const provider2: DiscoveryProvider = {
      name: 'p2',
      resolve: vi.fn().mockResolvedValue(mockCard),
    }

    const orchestrator = new DiscoveryOrchestrator([provider1, provider2])
    const result = await orchestrator.resolve('did:fides:agent1')

    expect(result).toEqual(mockCard)
    expect(provider1.resolve).toHaveBeenCalledWith('did:fides:agent1')
    expect(provider2.resolve).toHaveBeenCalledWith('did:fides:agent1')
  })

  it('should return null when all providers fail', async () => {
    const provider1: DiscoveryProvider = {
      name: 'p1',
      resolve: vi.fn().mockRejectedValue(new Error('network error')),
    }
    const provider2: DiscoveryProvider = {
      name: 'p2',
      resolve: vi.fn().mockResolvedValue(null),
    }

    const orchestrator = new DiscoveryOrchestrator([provider1, provider2])
    const result = await orchestrator.resolve('did:fides:agent1')

    expect(result).toBeNull()
  })

  it('should skip failed providers and continue', async () => {
    const provider1: DiscoveryProvider = {
      name: 'p1',
      resolve: vi.fn().mockRejectedValue(new Error('down')),
    }
    const provider2: DiscoveryProvider = {
      name: 'p2',
      resolve: vi.fn().mockResolvedValue(mockCard),
    }

    const orchestrator = new DiscoveryOrchestrator([provider1, provider2])
    const result = await orchestrator.resolve('did:fides:agent1')

    expect(result).toEqual(mockCard)
  })
})
