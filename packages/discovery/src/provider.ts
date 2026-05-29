import type { AgentCard, DiscoveryCandidate, DiscoveryQuery, SignedAgentCard } from '@fides/core'

/**
 * DiscoveryProvider is the interface that all discovery mechanisms implement.
 */
export interface DiscoveryProvider {
  readonly name: string
  discover?(query: DiscoveryQuery): Promise<DiscoveryCandidate[]>
  resolve(did: string): Promise<AgentCard | null>
  register?(card: SignedAgentCard): Promise<void>
  deregister?(did: string): Promise<void>
}
