import { describe, it, expect, vi } from 'vitest'
import { DiscoveryOrchestrator } from '../src/orchestrator.js'
import { LocalDiscoveryProvider } from '../src/local-provider.js'
import { WellKnownDiscoveryProvider } from '../src/well-known-provider.js'
import { RegistryDiscoveryProvider } from '../src/registry-provider.js'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { DiscoveryProvider } from '../src/provider.js'
import { createCapabilityDescriptor, createDiscoveryQuery, type AgentCard } from '@fides/core'

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

  it('discovers capability candidates through provider discover implementations', async () => {
    const card = {
      ...mockCard,
      protocolVersions: ['fides.v2.0'],
    }
    const provider: DiscoveryProvider = {
      name: 'query-provider',
      resolve: vi.fn(),
      discover: vi.fn().mockResolvedValue([{
        schema_version: 'fides.discovery_candidate.v1',
        provider: 'query-provider',
        agentId: card.id,
        card,
        capability: 'calendar.schedule',
        verified: true,
        rank: 10,
        explanations: ['matched'],
        errors: [],
      }]),
    }
    const query = createDiscoveryQuery({ capability: 'calendar.schedule' })

    const candidates = await new DiscoveryOrchestrator([provider]).discover(query)

    expect(candidates).toHaveLength(1)
    expect(provider.discover).toHaveBeenCalledWith(query)
    expect(candidates[0].versionNegotiation).toMatchObject({
      compatible: true,
      negotiated_version: 'fides.v2.0',
    })
    expect(candidates[0].authority).toBe('candidate_only')
    expect(candidates[0].evidence_refs).toEqual([])
    expect(candidates[0].explanations).toContain('Protocol version fides.v2.0 is compatible')
  })

  it('filters provider candidates with incompatible protocol versions', async () => {
    const provider: DiscoveryProvider = {
      name: 'query-provider',
      resolve: vi.fn(),
      discover: vi.fn().mockResolvedValue([{
        schema_version: 'fides.discovery_candidate.v1',
        provider: 'query-provider',
        agentId: mockCard.id,
        card: {
          ...mockCard,
          protocolVersions: ['fides.v1'],
        },
        capability: 'calendar.schedule',
        verified: true,
        rank: 10,
        explanations: ['matched'],
        errors: [],
      }]),
    }

    const candidates = await new DiscoveryOrchestrator([provider]).discover(createDiscoveryQuery({
      capability: 'calendar.schedule',
      supported_versions: ['fides.v2.0'],
      required_versions: ['fides.v2.0'],
    }))

    expect(candidates).toEqual([])
  })

  it('falls back to legacy DID resolution when requester_agent_id is present', async () => {
    const card: AgentCard = {
      ...mockCard,
      capabilities: [createCapabilityDescriptor({ id: 'calendar.schedule' })],
      protocolVersions: ['fides.v2.0'],
    }
    const provider: DiscoveryProvider = {
      name: 'legacy-provider',
      resolve: vi.fn().mockResolvedValue(card),
    }

    const candidates = await new DiscoveryOrchestrator([provider]).discover(createDiscoveryQuery({
      capability: 'calendar.schedule',
      requester_agent_id: card.id,
    }))

    expect(candidates).toHaveLength(1)
    expect(candidates[0]).toMatchObject({
      provider: 'legacy-provider',
      agentId: card.id,
      capability: 'calendar.schedule',
      authority: 'candidate_only',
      verified: false,
      evidence_refs: [],
    })
    expect(candidates[0].versionNegotiation?.compatible).toBe(true)
  })

  it('filters legacy DID resolution candidates with incompatible protocol versions', async () => {
    const card: AgentCard = {
      ...mockCard,
      capabilities: [createCapabilityDescriptor({ id: 'calendar.schedule' })],
      protocolVersions: ['fides.v1'],
    }
    const provider: DiscoveryProvider = {
      name: 'legacy-provider',
      resolve: vi.fn().mockResolvedValue(card),
    }

    const candidates = await new DiscoveryOrchestrator([provider]).discover(createDiscoveryQuery({
      capability: 'calendar.schedule',
      requester_agent_id: card.id,
      supported_versions: ['fides.v2.0'],
      required_versions: ['fides.v2.0'],
    }))

    expect(candidates).toEqual([])
  })

  it('local provider discovers registered cards by capability', async () => {
    const path = join(tmpdir(), `fides-local-agents-${crypto.randomUUID()}.json`)
    const provider = new LocalDiscoveryProvider({ storePath: path })
    const card: AgentCard = {
      ...mockCard,
      capabilities: [createCapabilityDescriptor({ id: 'invoice.reconcile' })],
    }
    provider.registerCard(card)

    const candidates = await provider.discover(createDiscoveryQuery({
      capability: 'invoice.reconcile',
    }))

    expect(candidates).toHaveLength(1)
    expect(candidates[0].provider).toBe('local')
    expect(candidates[0].authority).toBe('candidate_only')
    expect(candidates[0].evidence_refs).toEqual([])
    expect(candidates[0].explanations[0]).toContain('invoice.reconcile')
  })
})
