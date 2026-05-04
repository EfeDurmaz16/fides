/**
 * FIDES v2 Agent Card Primitives
 *
 * An AgentCard is the signed, self-describing metadata document that
 * an agent publishes to advertise its identity, capabilities, endpoints,
 * and policy requirements.
 */

import type { AgentIdentity, PublisherIdentity } from './identity.js'
import type { SignedObject } from './canonical-signer.js'
import type { CapabilityDescriptor } from './capability.js'

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
  /** Unique identifier (typically the agent's DID) */
  id: string
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
  /** ISO 8601 creation timestamp */
  createdAt: string
  /** ISO 8601 last update timestamp */
  updatedAt: string
}

/** A signed AgentCard — the canonical form used in discovery and verification */
export type SignedAgentCard = SignedObject<AgentCard>

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

  return { valid: errors.length === 0, errors }
}
