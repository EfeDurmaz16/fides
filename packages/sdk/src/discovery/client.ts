import type { AgentIdentity, DiscoveryDocument } from '@fides/shared'
import { DiscoveryError } from '@fides/shared'
import { WELL_KNOWN_PATH } from '@fides/shared'

export interface RegisterIdentityParams {
  did: string
  publicKey: string
  metadata?: Record<string, unknown>
  domain?: string
  organizationDomain?: string
}

export interface VerifyIdentityDomainResponse {
  did: string
  publicKey: string
  metadata: Record<string, unknown>
  domain: string
  domainVerified: true
  domainVerifiedAt: string
  verificationMethod: 'dns'
  createdAt: string
  updatedAt: string
  verification: {
    domain: string
    did: string
    recordName: string
    verified: true
  }
}

export interface VerifyOrganizationDomainResponse {
  did: string
  publicKey: string
  metadata: Record<string, unknown>
  organizationDomain: string
  organizationDomainVerified: true
  organizationDomainVerifiedAt: string
  organizationVerificationMethod: 'dns'
  createdAt: string
  updatedAt: string
  verification: {
    domain: string
    did: string
    recordName: string
    verified: true
  }
}

export class DiscoveryClient {
  constructor(private options: { baseUrl: string }) {}

  /**
   * Register an identity with the discovery service
   */
  async register(identity: RegisterIdentityParams): Promise<AgentIdentity> {
    try {
      const response = await fetch(`${this.options.baseUrl}/identities`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(identity),
      })

      if (!response.ok) {
        const text = await response.text()
        throw new DiscoveryError(
          `Failed to register identity: ${response.status} ${text}`
        )
      }

      return await response.json()
    } catch (error) {
      if (error instanceof DiscoveryError) {
        throw error
      }
      throw new DiscoveryError(
        `Failed to register identity: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Resolve a DID to an agent identity
   */
  async resolve(did: string): Promise<AgentIdentity | null> {
    try {
      const response = await fetch(
        `${this.options.baseUrl}/identities/${encodeURIComponent(did)}`
      )

      if (response.status === 404) {
        return null
      }

      if (!response.ok) {
        const text = await response.text()
        throw new DiscoveryError(
          `Failed to resolve DID: ${response.status} ${text}`
        )
      }

      return await response.json()
    } catch (error) {
      if (error instanceof DiscoveryError) {
        throw error
      }
      throw new DiscoveryError(
        `Failed to resolve DID: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Verify a registered identity's domain through DNS TXT and persist the result.
   */
  async verifyDomain(did: string, domain?: string): Promise<VerifyIdentityDomainResponse> {
    try {
      const response = await fetch(
        `${this.options.baseUrl}/identities/${encodeURIComponent(did)}/domain/verify`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(domain ? { domain } : {}),
        }
      )

      if (!response.ok) {
        const text = await response.text()
        throw new DiscoveryError(
          `Failed to verify identity domain: ${response.status} ${text}`
        )
      }

      return await response.json()
    } catch (error) {
      if (error instanceof DiscoveryError) {
        throw error
      }
      throw new DiscoveryError(
        `Failed to verify identity domain: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Verify a registered identity's organization domain through DNS TXT and persist the result.
   */
  async verifyOrganizationDomain(did: string, domain?: string): Promise<VerifyOrganizationDomainResponse> {
    try {
      const response = await fetch(
        `${this.options.baseUrl}/identities/${encodeURIComponent(did)}/organization-domain/verify`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(domain ? { domain } : {}),
        }
      )

      if (!response.ok) {
        const text = await response.text()
        throw new DiscoveryError(
          `Failed to verify organization domain: ${response.status} ${text}`
        )
      }

      return await response.json()
    } catch (error) {
      if (error instanceof DiscoveryError) {
        throw error
      }
      throw new DiscoveryError(
        `Failed to verify organization domain: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Resolve an identity from a domain's .well-known endpoint
   */
  async resolveFromWellKnown(domain: string): Promise<DiscoveryDocument | null> {
    try {
      const url = `https://${domain}${WELL_KNOWN_PATH}`
      const response = await fetch(url)

      if (response.status === 404) {
        return null
      }

      if (!response.ok) {
        const text = await response.text()
        throw new DiscoveryError(
          `Failed to resolve well-known: ${response.status} ${text}`
        )
      }

      return await response.json()
    } catch (error) {
      if (error instanceof DiscoveryError) {
        throw error
      }
      throw new DiscoveryError(
        `Failed to resolve well-known: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }
}
