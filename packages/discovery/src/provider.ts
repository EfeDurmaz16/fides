import type { AgentCard, SignedAgentCard } from '@fides/core'

/**
 * DiscoveryProvider is the interface that all discovery mechanisms implement.
 */
export interface DiscoveryProvider {
  readonly name: string
  resolve(did: string): Promise<AgentCard | null>
  register?(card: SignedAgentCard): Promise<void>
  deregister?(did: string): Promise<void>
}
