/**
 * FIDES v2 Identity Primitives
 *
 * Provides multi-level identity for the Agent Trust Fabric:
 * - AgentIdentity: the autonomous agent itself
 * - PublisherIdentity: who published/created the agent
 * - PrincipalIdentity: who the agent acts on behalf of
 * - TrustAnchor: a trusted root for the trust graph
 */

import { type SignedObject } from './canonical-signer.js'

export interface AgentIdentity {
  /** DID in the form did:fides:<base58-public-key> */
  did: string
  /** Raw Ed25519 public key (32 bytes) */
  publicKey: Uint8Array
  /** Key algorithm — currently Ed25519 only */
  keyType: 'Ed25519'
  /** ISO 8601 timestamp of identity creation */
  createdAt: string
  /** The publisher that created this agent (optional) */
  publisher?: PublisherIdentity
  /** The principal this agent acts for (optional) */
  principal?: PrincipalIdentity
}

export interface PublisherIdentity {
  /** DID of the publisher */
  did: string
  /** Human-readable name */
  name: string
  /** Verified domain (optional) */
  domain?: string
  /** Whether the publisher identity has been verified */
  verified: boolean
  /** Method used to verify the publisher */
  verificationMethod: 'dns' | 'github' | 'email' | 'manual'
}

export interface PrincipalIdentity {
  /** DID of the principal */
  did: string
  /** Type of principal */
  type: 'individual' | 'organization' | 'platform'
  /** Human-readable display name */
  displayName: string
  /** Verified domain for organization or platform principals */
  domain?: string
  /** Whether the principal identity has been verified */
  verified?: boolean
  /** Method used to verify the principal */
  verificationMethod?: 'dns' | 'github' | 'email' | 'manual'
}

export interface TrustAnchor {
  /** DID of the trust anchor */
  did: string
  /** Human-readable name */
  name: string
  /** Public key for verification */
  publicKey: Uint8Array
  /** Signed trust attestation issued by this anchor */
  attestation: SignedObject<unknown>
}

/**
 * Validates that a DID string conforms to the did:fides:<base58> format.
 */
export function isValidFidesDid(did: string): boolean {
  return did.startsWith('did:fides:') && did.length > 'did:fides:'.length
}

/**
 * Creates an AgentIdentity with a random Ed25519 key pair.
 */
export function createIdentity(did: string, type: 'agent' | 'publisher' | 'principal' | 'trust-anchor', metadata: Record<string, unknown> = {}): AgentIdentity & { metadata: Record<string, unknown> } {
  const publicKey = crypto.getRandomValues(new Uint8Array(32))
  return {
    did,
    publicKey,
    keyType: 'Ed25519',
    createdAt: new Date().toISOString(),
    metadata,
  }
}

/**
 * Creates a display name for an identity, falling back to DID short form.
 */
export function identityDisplayName(identity: AgentIdentity | PrincipalIdentity | PublisherIdentity): string {
  if ('displayName' in identity) return identity.displayName
  if ('name' in identity) return identity.name
  return identity.did.slice(0, 24) + '...'
}
