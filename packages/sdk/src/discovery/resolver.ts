import type { AgentIdentity } from '@fides/shared'
import { DID_PREFIX } from '@fides/shared'
import { DiscoveryClient } from './client.js'

interface CacheEntry {
  identity: AgentIdentity
  timestamp: number
}

export class IdentityResolver {
  private client: DiscoveryClient
  private cache: Map<string, CacheEntry> = new Map()
  private cacheTtlMs: number

  constructor(options: { discoveryUrl: string; cacheTtlMs?: number }) {
    this.client = new DiscoveryClient({ baseUrl: options.discoveryUrl })
    this.cacheTtlMs = options.cacheTtlMs ?? 5 * 60 * 1000 // Default 5 minutes
  }

  /**
   * Resolve an identity by DID or domain
   * - If starts with 'did:fides:', use discovery service
   * - Otherwise, try .well-known first, then fallback to discovery
   */
  async resolve(didOrDomain: string): Promise<AgentIdentity | null> {
    // Check cache first
    const cached = this.cache.get(didOrDomain)
    if (cached && Date.now() - cached.timestamp < this.cacheTtlMs) {
      return cached.identity
    }

    let identity: AgentIdentity | null = null

    if (didOrDomain.startsWith(DID_PREFIX)) {
      // Resolve via discovery service
      identity = await this.client.resolve(didOrDomain)
    } else {
      // Try .well-known first
      const wellKnownDoc = await this.client.resolveFromWellKnown(didOrDomain)
      if (wellKnownDoc) {
        // Convert DiscoveryDocument to AgentIdentity
        identity = {
          did: wellKnownDoc.did,
          publicKey: wellKnownDoc.publicKey,
          algorithm: wellKnownDoc.algorithm,
          endpoints: wellKnownDoc.endpoints,
          createdAt: wellKnownDoc.createdAt,
        }
      } else {
        // Fallback to discovery service (using domain as DID)
        identity = await this.client.resolve(didOrDomain)
      }
    }

    // Cache the result if found
    if (identity) {
      this.cache.set(didOrDomain, {
        identity,
        timestamp: Date.now(),
      })
    }

    return identity
  }

  /**
   * Clear the identity cache
   */
  clearCache(): void {
    this.cache.clear()
  }
}
