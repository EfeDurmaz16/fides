import type { AgentCard, SignedAgentCard } from '@fides/core'
import { DiscoveryProvider } from './provider.js'

/**
 * RegistryDiscoveryProvider resolves AgentCards from a hosted registry.
 *
 * Stub implementation — ready for registry integration.
 */
export class RegistryDiscoveryProvider implements DiscoveryProvider {
  readonly name = 'registry'

  constructor(private options: { baseUrl: string }) {}

  async resolve(did: string): Promise<AgentCard | null> {
    try {
      const response = await fetch(`${this.options.baseUrl}/v1/cards/${encodeURIComponent(did)}`)
      if (response.ok) {
        const data = await response.json()
        return data as AgentCard
      }
    } catch {
      // Network error — return null
    }
    return null
  }

  async register(card: SignedAgentCard): Promise<void> {
    const response = await fetch(`${this.options.baseUrl}/v1/cards`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(card),
    })
    if (!response.ok) {
      throw new Error(`Registry registration failed: ${response.status}`)
    }
  }

  async deregister(did: string): Promise<void> {
    const response = await fetch(`${this.options.baseUrl}/v1/cards/${encodeURIComponent(did)}`, {
      method: 'DELETE',
    })
    if (!response.ok) {
      throw new Error(`Registry deregistration failed: ${response.status}`)
    }
  }
}
