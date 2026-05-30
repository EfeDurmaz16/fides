import {
  cardSupportsCapability,
  createDiscoveryCandidate,
  negotiateDiscoveryCandidateVersion,
  type AgentCard,
  type DiscoveryCandidate,
  type DiscoveryQuery,
} from '@fides/core'
import { DiscoveryProvider } from './provider.js'

/**
 * DiscoveryOrchestrator tries multiple providers in priority order
 * until an AgentCard is found.
 */
export class DiscoveryOrchestrator {
  constructor(private providers: DiscoveryProvider[]) {}

  async discover(query: DiscoveryQuery): Promise<DiscoveryCandidate[]> {
    const candidates: DiscoveryCandidate[] = []

    for (const provider of this.providers) {
      if (query.providers && !query.providers.includes(provider.name)) continue

      try {
        if (provider.discover) {
          candidates.push(...filterVersionCompatibleCandidates(query, await provider.discover(query)))
          continue
        }

        if (query.requester_agent_id) {
          const card = await provider.resolve(query.requester_agent_id)
          if (card && cardSupportsCapability(card, query.capability)) {
            const versionNegotiation = negotiateDiscoveryCandidateVersion(query, card)
            if (!versionNegotiation.compatible) continue
            candidates.push(createDiscoveryCandidate({
              provider: provider.name,
              card,
              capability: query.capability,
              verified: false,
              explanations: ['Resolved through legacy DID provider path'],
              versionNegotiation,
            }))
          }
        }
      } catch (error) {
        console.warn(`Discovery provider ${provider.name} failed for query ${query.id}:`, error)
      }
    }

    return candidates
      .sort((a, b) => b.rank - a.rank || a.provider.localeCompare(b.provider))
      .slice(0, query.limit ?? candidates.length)
  }

  async resolve(did: string): Promise<AgentCard | null> {
    for (const provider of this.providers) {
      try {
        const card = await provider.resolve(did)
        if (card) return card
      } catch (error) {
        // Log and continue to next provider
        console.warn(`Discovery provider ${provider.name} failed for ${did}:`, error)
      }
    }
    return null
  }

  async register(card: AgentCard): Promise<void> {
    for (const provider of this.providers) {
      if (provider.register) {
        try {
          await provider.register(card as any)
        } catch (error) {
          console.warn(`Failed to register with ${provider.name}:`, error)
        }
      }
    }
  }

  async deregister(did: string): Promise<void> {
    for (const provider of this.providers) {
      if (provider.deregister) {
        try {
          await provider.deregister(did)
        } catch (error) {
          console.warn(`Failed to deregister from ${provider.name}:`, error)
        }
      }
    }
  }
}

function filterVersionCompatibleCandidates(
  query: DiscoveryQuery,
  candidates: DiscoveryCandidate[]
): DiscoveryCandidate[] {
  return candidates.flatMap((candidate) => {
    const versionNegotiation = candidate.versionNegotiation ?? negotiateDiscoveryCandidateVersion(query, candidate.card)
    if (!versionNegotiation.compatible) return []
    return [{
      ...candidate,
      authority: 'candidate_only' as const,
      versionNegotiation,
      evidence_refs: candidate.evidence_refs ?? [],
      errors: (candidate.errors ?? []).filter(error => error.code !== 'VERSION_INCOMPATIBLE'),
      explanations: [
        ...(candidate.explanations ?? []),
        `Protocol version ${versionNegotiation.negotiated_version} is compatible`,
      ],
    }]
  })
}
