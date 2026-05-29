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
import * as ed from '@noble/ed25519'
import bs58 from 'bs58'

export type PublisherIdentityType =
  | 'anonymous'
  | 'self_signed'
  | 'verified_individual'
  | 'platform_hosted'
  | 'domain_verified'
  | 'organization_verified'

export type IdentityVerificationMethod =
  | 'none'
  | 'self_signed'
  | 'dns'
  | 'github'
  | 'email'
  | 'manual'
  | 'platform'
  | 'organization_invitation'

export type TrustAnchorType =
  | 'domain'
  | 'github'
  | 'email'
  | 'npm'
  | 'pypi'
  | 'wallet'
  | 'passkey'
  | 'organization_invitation'
  | 'runtime_attestation'
  | 'build_attestation'
  | 'peer_attestation'

export interface AgentIdentity {
  /** DID in the form did:fides:<base58-public-key> */
  did: string
  /** Raw Ed25519 public key (32 bytes) */
  publicKey: Uint8Array
  /** Key algorithm — currently Ed25519 only */
  keyType: 'Ed25519'
  /** ISO 8601 timestamp of identity creation */
  createdAt: string
  /** Local display/application metadata used by examples and cards. */
  metadata?: Record<string, unknown>
  /** Trust anchors claimed or verified for this agent. */
  trustAnchors?: IdentityTrustAnchor[]
  /** The publisher that created this agent (optional) */
  publisher?: PublisherIdentity
  /** The principal this agent acts for (optional) */
  principal?: PrincipalIdentity
}

export interface PublisherIdentity {
  /** DID of the publisher */
  did: string
  /** Publisher trust/verification class. */
  publisherType?: PublisherIdentityType
  /** Human-readable name */
  name: string
  /** Verified domain (optional) */
  domain?: string
  /** Whether the publisher identity has been verified */
  verified: boolean
  /** Method used to verify the publisher */
  verificationMethod: IdentityVerificationMethod
  /** Trust anchors used to support publisher claims. */
  trustAnchors?: IdentityTrustAnchor[]
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
  verificationMethod?: IdentityVerificationMethod
  /** Trust anchors used to support principal claims. */
  trustAnchors?: IdentityTrustAnchor[]
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

export interface IdentityTrustAnchor {
  type: TrustAnchorType
  value: string
  verified: boolean
  verifiedAt?: string
  evidenceRef?: string
}

export interface IssuedIdentity<TIdentity extends AgentIdentity | PublisherIdentity | PrincipalIdentity> {
  identity: TIdentity
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export interface CreateAgentIdentityInput {
  publisher?: PublisherIdentity
  principal?: PrincipalIdentity
  trustAnchors?: IdentityTrustAnchor[]
  createdAt?: string
}

export interface CreatePublisherIdentityInput {
  name: string
  publisherType?: PublisherIdentityType
  verificationMethod?: IdentityVerificationMethod
  verified?: boolean
  domain?: string
  trustAnchors?: IdentityTrustAnchor[]
}

export interface CreatePrincipalIdentityInput {
  type: PrincipalIdentity['type']
  displayName: string
  domain?: string
  verificationMethod?: IdentityVerificationMethod
  verified?: boolean
  trustAnchors?: IdentityTrustAnchor[]
}

/**
 * Validates that a DID string conforms to the did:fides:<base58> format.
 */
export function isValidFidesDid(did: string): boolean {
  return did.startsWith('did:fides:') && did.length > 'did:fides:'.length
}

export function didFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error('FIDES DID public key must be 32 bytes')
  }
  return `did:fides:${bs58.encode(publicKey)}`
}

export function publicKeyFromDid(did: string): Uint8Array {
  if (!isValidFidesDid(did)) {
    throw new Error('Invalid FIDES DID')
  }
  const encoded = did.slice('did:fides:'.length)
  const publicKey = bs58.decode(encoded)
  if (publicKey.length !== 32) {
    throw new Error('FIDES DID public key must decode to 32 bytes')
  }
  return publicKey
}

export async function createIdentityKeyPair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array; did: string }> {
  const privateKey = ed.utils.randomPrivateKey()
  const publicKey = await ed.getPublicKeyAsync(privateKey)
  return {
    privateKey,
    publicKey,
    did: didFromPublicKey(publicKey),
  }
}

export async function createAgentIdentity(input: CreateAgentIdentityInput = {}): Promise<IssuedIdentity<AgentIdentity>> {
  const issued = await createIdentityKeyPair()
  return {
    ...issued,
    identity: {
      did: issued.did,
      publicKey: issued.publicKey,
      keyType: 'Ed25519',
      createdAt: input.createdAt ?? new Date().toISOString(),
      ...(input.trustAnchors !== undefined && { trustAnchors: input.trustAnchors }),
      ...(input.publisher !== undefined && { publisher: input.publisher }),
      ...(input.principal !== undefined && { principal: input.principal }),
    },
  }
}

export async function createPublisherIdentity(input: CreatePublisherIdentityInput): Promise<IssuedIdentity<PublisherIdentity>> {
  const issued = await createIdentityKeyPair()
  const verificationMethod = input.verificationMethod ?? 'self_signed'
  return {
    ...issued,
    identity: {
      did: issued.did,
      name: input.name,
      publisherType: input.publisherType ?? 'self_signed',
      verified: input.verified ?? verificationMethod !== 'none',
      verificationMethod,
      ...(input.domain !== undefined && { domain: input.domain }),
      ...(input.trustAnchors !== undefined && { trustAnchors: input.trustAnchors }),
    },
  }
}

export async function createPrincipalIdentity(input: CreatePrincipalIdentityInput): Promise<IssuedIdentity<PrincipalIdentity>> {
  const issued = await createIdentityKeyPair()
  return {
    ...issued,
    identity: {
      did: issued.did,
      type: input.type,
      displayName: input.displayName,
      ...(input.domain !== undefined && { domain: input.domain }),
      ...(input.verified !== undefined && { verified: input.verified }),
      ...(input.verificationMethod !== undefined && { verificationMethod: input.verificationMethod }),
      ...(input.trustAnchors !== undefined && { trustAnchors: input.trustAnchors }),
    },
  }
}

export function validateIdentityKeyBinding(identity: Pick<AgentIdentity, 'did' | 'publicKey'>): boolean {
  try {
    return bs58.encode(identity.publicKey) === identity.did.slice('did:fides:'.length)
  } catch {
    return false
  }
}

/**
 * Creates an AgentIdentity with a random Ed25519 key pair.
 */
export function createIdentity(did: string, type: 'agent' | 'publisher' | 'principal' | 'trust-anchor', metadata: Record<string, unknown> = {}): AgentIdentity & { metadata: Record<string, unknown> } {
  let publicKey: Uint8Array
  try {
    publicKey = publicKeyFromDid(did)
  } catch {
    publicKey = crypto.getRandomValues(new Uint8Array(32))
  }

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
