import {
  createDiscoveryCandidate,
  isRegistryPeerRecordExpired,
  verifySignedRegistryPeerRecord,
  type AgentCard,
  type DiscoveryCandidate,
  type DiscoveryQuery,
  type RegistryPeerRecord,
  type SignedAgentCard,
  type SignedRegistryPeerRecord,
} from '@fides/core'
import { DiscoveryProvider } from './provider.js'

export interface FederationDiscoveryPeer {
  readonly record: SignedRegistryPeerRecord
  readonly provider: DiscoveryProvider
}

export interface FederationDiscoveryProviderOptions {
  peers?: FederationDiscoveryPeer[]
}

/**
 * Local mock federation provider.
 *
 * Federation only expands the discovery search space. Peer records and peer
 * provider results are not authority; callers must still verify AgentCards,
 * trust, policy, revocation, incident, and session grants before invocation.
 */
export class LocalFederationDiscoveryProvider implements DiscoveryProvider {
  readonly name = 'federation'
  private readonly peers = new Map<string, FederationDiscoveryPeer>()

  constructor(options: FederationDiscoveryProviderOptions = {}) {
    for (const peer of options.peers ?? []) {
      this.addPeer(peer)
    }
  }

  addPeer(peer: FederationDiscoveryPeer): void {
    this.peers.set(peer.record.payload.peer_id, peer)
  }

  listPeers(): RegistryPeerRecord[] {
    return Array.from(this.peers.values()).map(peer => peer.record.payload)
  }

  async resolve(did: string): Promise<AgentCard | null> {
    for (const peer of this.peers.values()) {
      if (!await this.isUsablePeer(peer)) continue
      const card = await peer.provider.resolve(did)
      if (card) return card
    }
    return null
  }

  async discover(query: DiscoveryQuery): Promise<DiscoveryCandidate[]> {
    const candidates: DiscoveryCandidate[] = []
    for (const peer of this.peers.values()) {
      if (!await this.isUsablePeer(peer)) continue
      const peerCandidates = peer.provider.discover
        ? await peer.provider.discover(query)
        : await this.discoverThroughResolve(peer.provider, query)
      for (const candidate of peerCandidates) {
        candidates.push({
          ...candidate,
          provider: this.name,
          verified: false,
          rank: candidate.rank - 1,
          explanations: [
            `Federated peer ${peer.record.payload.peer_id} returned candidate via ${candidate.provider}; federation is not authority`,
            ...candidate.explanations,
          ],
        })
      }
    }
    return candidates
      .sort((a, b) => b.rank - a.rank || a.agentId.localeCompare(b.agentId))
      .slice(0, query.limit ?? candidates.length)
  }

  async register(_card: SignedAgentCard): Promise<void> {
    throw new Error('Federation discovery does not publish AgentCards directly; publish to a registry peer instead')
  }

  async deregister(_did: string): Promise<void> {
    throw new Error('Federation discovery does not deregister AgentCards directly; deregister from the source peer instead')
  }

  private async discoverThroughResolve(provider: DiscoveryProvider, query: DiscoveryQuery): Promise<DiscoveryCandidate[]> {
    if (!query.requester_agent_id) return []
    const card = await provider.resolve(query.requester_agent_id)
    if (!card) return []
    return [createDiscoveryCandidate({
      provider: provider.name,
      card,
      capability: query.capability,
      verified: false,
      explanations: ['Resolved through federated legacy DID provider path'],
    })]
  }

  private async isUsablePeer(peer: FederationDiscoveryPeer): Promise<boolean> {
    if (isRegistryPeerRecordExpired(peer.record.payload)) return false
    if (!peer.record.payload.capabilities.includes('registry_search')) return false
    return verifySignedRegistryPeerRecord(peer.record)
  }
}
