import type { AgentCard } from '@fides/core'
import { DiscoveryProvider } from './provider.js'

/**
 * RelayDiscoveryProvider resolves AgentCards via a relay server.
 *
 * Stub implementation — ready for relay integration.
 */
export class RelayDiscoveryProvider implements DiscoveryProvider {
  readonly name = 'relay'

  constructor(private options: { relayUrl: string }) {}

  async resolve(did: string): Promise<AgentCard | null> {
    // TODO: Implement relay message protocol
    return null
  }
}
