import type { AgentCard } from '@fides/core'
import { DiscoveryProvider } from './provider.js'

/**
 * LocalDiscoveryProvider discovers agents on the local network.
 *
 * Stub implementation — ready for mDNS integration.
 */
export class LocalDiscoveryProvider implements DiscoveryProvider {
  readonly name = 'local'

  async resolve(did: string): Promise<AgentCard | null> {
    // TODO: Implement mDNS / Bonjour browsing
    return null
  }
}
