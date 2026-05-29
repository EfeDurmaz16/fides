/**
 * FIDES v2 Agent Card Primitives
 *
 * An AgentCard is the signed, self-describing metadata document that
 * an agent publishes to advertise its identity, capabilities, endpoints,
 * and policy requirements.
 */

import type { AgentIdentity, PublisherIdentity } from './identity.js'
import { signObject, verifyObject, type SignedObject } from './canonical-signer.js'
import type { CapabilityDescriptor } from './capability.js'
import type { RuntimeAttestation } from './runtime-attestation.js'
import type { IdentityTrustAnchor } from './identity.js'

export interface EndpointDescriptor {
  /** Endpoint URL */
  url: string
  /** Transport protocol: http, https, websocket, grpc */
  protocol: 'http' | 'https' | 'websocket' | 'grpc'
  /** Capability IDs supported at this endpoint */
  capabilities?: string[]
  /** Authentication method required */
  auth?: 'none' | 'signature' | 'bearer' | 'delegation'
}

export interface PolicyRequirement {
  /** Policy bundle ID that must be satisfied */
  policyBundleId?: string
  /** Minimum trust score required (0.0 - 1.0) */
  minTrustScore?: number
  /** Whether runtime attestation is required */
  requiresRuntimeAttestation: boolean
  /** Whether approval is required for high-risk capabilities */
  requiresApproval: boolean
}

export interface AgentCard {
  /** Schema version for v2 AgentCards. */
  schema_version?: 'fides.agent_card.v1'
  /** Unique identifier (typically the agent's DID) */
  id: string
  /** Stable agent DID, repeated for compatibility with external card formats. */
  agent_id?: string
  /** Agent identity */
  identity: AgentIdentity
  /** Publisher identity (optional) */
  publisher?: PublisherIdentity
  /** Advertised capabilities */
  capabilities: CapabilityDescriptor[]
  /** Service endpoints */
  endpoints: EndpointDescriptor[]
  /** Policy requirements for invokers */
  policies: PolicyRequirement[]
  /** Public keys advertised for verification and invocation. */
  publicKeys?: Array<{ id: string; type: 'Ed25519'; publicKey: string }>
  /** Trust anchors claimed or verified for this card. */
  trustAnchors?: IdentityTrustAnchor[]
  /** Runtime attestations bound to this card. */
  runtimeAttestations?: RuntimeAttestation[]
  /** Supported protocol versions. */
  protocolVersions?: string[]
  /** Revocation URL for this card or agent. */
  revocationUrl?: string
  /** Revocation record reference when available. */
  revocationRef?: string
  /** ISO 8601 expiry timestamp. */
  expiresAt?: string
  /** ISO 8601 creation timestamp */
  createdAt: string
  /** ISO 8601 last update timestamp */
  updatedAt: string
}

/** A signed AgentCard — the canonical form used in discovery and verification */
export type SignedAgentCard = SignedObject<AgentCard>

export async function signAgentCard(
  card: AgentCard,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<SignedAgentCard> {
  return signObject(normalizeAgentCard(card), privateKey, {
    verificationMethod,
    proofPurpose: 'assertionMethod',
  })
}

export async function verifySignedAgentCard(card: SignedAgentCard): Promise<boolean> {
  const validation = validateAgentCard(card.payload)
  if (!validation.valid) return false
  return verifyObject(card)
}

/**
 * Validate that an AgentCard has all required fields and sensible values.
 */
export function validateAgentCard(card: AgentCard): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  if (!card.id) errors.push('AgentCard.id is required')
  if (!card.identity?.did) errors.push('AgentCard.identity.did is required')
  if (!card.identity?.publicKey || card.identity.publicKey.length !== 32) {
    errors.push('AgentCard.identity.publicKey must be 32 bytes')
  }
  if (!Array.isArray(card.capabilities)) errors.push('AgentCard.capabilities must be an array')
  if (!Array.isArray(card.endpoints)) errors.push('AgentCard.endpoints must be an array')
  if (!Array.isArray(card.policies)) errors.push('AgentCard.policies must be an array')
  if (!card.createdAt) errors.push('AgentCard.createdAt is required')
  if (!card.updatedAt) errors.push('AgentCard.updatedAt is required')
  if (card.agent_id && card.agent_id !== card.identity.did) {
    errors.push('AgentCard.agent_id must match AgentCard.identity.did')
  }
  if (card.expiresAt && new Date(card.expiresAt).getTime() <= Date.now()) {
    errors.push('AgentCard.expiresAt must be in the future')
  }
  for (const capability of card.capabilities ?? []) {
    if (!capability.id) errors.push('CapabilityDescriptor.id is required')
    if (capability.namespace && capability.id.split('.')[0] !== capability.namespace) {
      errors.push(`CapabilityDescriptor ${capability.id} namespace does not match id`)
    }
  }

  return { valid: errors.length === 0, errors }
}

export function normalizeAgentCard(card: AgentCard): AgentCard {
  return {
    ...card,
    schema_version: card.schema_version ?? 'fides.agent_card.v1',
    agent_id: card.agent_id ?? card.identity.did,
  }
}
