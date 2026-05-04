import type { AgentCard } from '@fides/core'
import { DiscoveryProvider } from './provider.js'

/**
 * DiscoveryOrchestrator tries multiple providers in priority order
 * until an AgentCard is found.
 */
export class DiscoveryOrchestrator {
  constructor(private providers: DiscoveryProvider[]) {}

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
