/**
 * FIDES v2 Core Primitives
 *
 * This module exports the foundational types and functions for the
 * FIDES Agent Trust Fabric:
 * - Identity v2 (Agent, Publisher, Principal)
 * - Canonical object signing
 * - Delegation tokens
 * - Policy bundles
 * - Evidence events
 * - Runtime attestations
 */

export * from './identity.js'
export * from './protocol.js'
export * from './errors.js'
export * from './versioning.js'
export * from './trust-anchor.js'
export * from './domain-verifier.js'
export * from './passkey.js'
export * from './canonical-signer.js'
export * from './agent-card.js'
export * from './capability.js'
export * from './runtime-attestation.js'
export * from './delegation.js'
export * from './session-store.js'
export * from './revocation.js'
