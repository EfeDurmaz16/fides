import type { AgentCard } from '@fides/core'
import { DiscoveryProvider } from './provider.js'

/**
 * DHTDiscoveryProvider resolves AgentCards via a Distributed Hash Table.
 *
 * Stub implementation — ready for libp2p / DHT integration.
 */
export class DHTDiscoveryProvider implements DiscoveryProvider {
  readonly name = 'dht'

  async resolve(did: string): Promise<AgentCard | null> {
    // TODO: Implement DHT lookup
    return null
  }
}
