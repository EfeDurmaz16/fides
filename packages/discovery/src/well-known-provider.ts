import type { AgentCard } from '@fides/core'
import { DiscoveryProvider } from './provider.js'

/**
 * WellKnownDiscoveryProvider resolves AgentCards via HTTP .well-known endpoints.
 *
 * Supports two DID formats:
 * - did:web:example.com:agent:alice → https://example.com/.well-known/fides.json
 * - did:fides:alice → requires a domain mapping (provided via constructor)
 */
export class WellKnownDiscoveryProvider implements DiscoveryProvider {
  readonly name = 'well-known'
  private domainMap: Map<string, string>

  constructor(
    private options?: {
      timeoutMs?: number
      /** Map of DIDs to domains for did:fides: style DIDs */
      domainMap?: Map<string, string>
    }
  ) {
    this.domainMap = options?.domainMap ?? new Map()
  }

  async resolve(did: string): Promise<AgentCard | null> {
    const domain = this.extractDomainFromDid(did)
    if (!domain) return null

    const urls = [
      `https://${domain}/.well-known/fides.json`,
      `https://${domain}/.well-known/agent.json`,
    ]

    for (const url of urls) {
      try {
        const controller = new AbortController()
        const timeout = setTimeout(
          () => controller.abort(),
          this.options?.timeoutMs ?? 5000
        )
        const response = await fetch(url, { signal: controller.signal })
        clearTimeout(timeout)

        if (response.ok) {
          const data = await response.json()
          if (data && typeof data === 'object') {
            if ('identity' in data && data.identity?.did === did) {
              return data as AgentCard
            }
            if ('did' in data && data.did === did) {
              return data as AgentCard
            }
          }
        }
      } catch {
        // Try next URL
      }
    }

    return null
  }

  /**
   * Register a domain mapping for a DID.
   * Useful for did:fides: style DIDs that don't embed domain info.
   */
  registerDomain(did: string, domain: string): void {
    this.domainMap.set(did, domain)
  }

  private extractDomainFromDid(did: string): string | null {
    // Check explicit domain mapping first
    if (this.domainMap.has(did)) {
      return this.domainMap.get(did) ?? null
    }

    // Support did:web:domain:path format
    if (did.startsWith('did:web:')) {
      const parts = did.split(':')
      if (parts.length >= 3) {
        return parts[2]
      }
    }

    // Support did:fides:did:domain:example.com format
    const domainMatch = did.match(/did:fides:.*:domain:([^:]+)/)
    if (domainMatch) {
      return domainMatch[1]
    }

    return null
  }
}
