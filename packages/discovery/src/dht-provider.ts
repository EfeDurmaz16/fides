import type { AgentCard, SignedAgentCard } from '@fides/core'
import { DiscoveryProvider } from './provider.js'

/**
 * DHTDiscoveryProvider resolves AgentCards via an in-memory DHT simulator.
 *
 * Simulates a Distributed Hash Table with:
 * - Key-value storage (DID → AgentCard)
 * - Peer nodes that replicate data
 * - Configurable replication factor
 *
 * This is a development/testing implementation. Production should use libp2p.
 */
export class DHTDiscoveryProvider implements DiscoveryProvider {
  readonly name = 'dht'

  // This node's local store
  private localStore = new Map<string, AgentCard>()
  // Simulated peer nodes (each has its own store)
  private peers: DHTDiscoveryProvider[] = []
  // Replication factor
  private replicationFactor: number

  constructor(options?: { replicationFactor?: number }) {
    this.replicationFactor = options?.replicationFactor ?? 3
  }

  async resolve(did: string): Promise<AgentCard | null> {
    // Check local store first
    if (this.localStore.has(did)) {
      return this.localStore.get(did) || null
    }

    // Query peers
    for (const peer of this.peers) {
      const result = await peer.resolve(did)
      if (result) {
        // Cache locally
        this.localStore.set(did, result)
        return result
      }
    }

    return null
  }

  async register(card: SignedAgentCard): Promise<void> {
    const did = card.payload.id
    const agentCard = card.payload as AgentCard

    // Store locally
    this.localStore.set(did, agentCard)

    // Replicate to peers
    const peersToReplicate = this.peers.slice(0, this.replicationFactor - 1)
    for (const peer of peersToReplicate) {
      peer.localStore.set(did, agentCard)
    }
  }

  async deregister(did: string): Promise<void> {
    this.localStore.delete(did)
    for (const peer of this.peers) {
      peer.localStore.delete(did)
    }
  }

  /**
   * Add a peer node to this DHT network.
   */
  addPeer(peer: DHTDiscoveryProvider): void {
    if (!this.peers.includes(peer)) {
      this.peers.push(peer)
      // Mutual peering
      if (!peer.peers.includes(this)) {
        peer.addPeer(this)
      }
    }
  }

  /**
   * Register an AgentCard directly (without SignedAgentCard wrapper).
   */
  registerCard(card: AgentCard): void {
    this.localStore.set(card.id, card)
    // Replicate to peers
    const peersToReplicate = this.peers.slice(0, this.replicationFactor - 1)
    for (const peer of peersToReplicate) {
      peer.localStore.set(card.id, card)
    }
  }

  /**
   * Get the number of entries in this node's local store.
   */
  get size(): number {
    return this.localStore.size
  }

  /**
   * Get all DIDs known to this node.
   */
  get keys(): string[] {
    return Array.from(this.localStore.keys())
  }

  /**
   * Get network stats.
   */
  getStats(): { localEntries: number; peerCount: number; replicationFactor: number } {
    return {
      localEntries: this.localStore.size,
      peerCount: this.peers.length,
      replicationFactor: this.replicationFactor,
    }
  }
}
