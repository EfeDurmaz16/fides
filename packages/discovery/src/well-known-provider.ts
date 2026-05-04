import type { AgentCard } from '@fides/core'
import { DiscoveryProvider } from './provider.js'

/**
 * WellKnownDiscoveryProvider resolves AgentCards via HTTP .well-known endpoints.
 *
 * Attempts to fetch:
 *   https://<host>/.well-known/fides.json
 *   https://<host>/.well-known/agent.json
 */
export class WellKnownDiscoveryProvider implements DiscoveryProvider {
  readonly name = 'well-known'

  constructor(private options?: { timeoutMs?: number }) {}

  async resolve(did: string): Promise<AgentCard | null> {
    // Extract host from DID metadata or use a resolver mapping
    // For now, this is a simplified implementation that expects
    // the DID to be resolvable to a domain.
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
            // Validate that the returned card matches the requested DID
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

  private extractDomainFromDid(did: string): string | null {
    // Simple heuristic: if the DID has an associated domain record,
    // we would look it up. For this reference implementation,
    // we expect a DNS TXT record or a local mapping.
    // Stub: return null to indicate no domain is known.
    return null
  }
}
