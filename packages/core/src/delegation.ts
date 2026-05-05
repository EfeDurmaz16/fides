/**
 * FIDES v2 Delegation Primitives
 *
 * Ported from OAPS DelegationToken with FIDES signing.
 */

import type { SignedObject } from './canonical-signer.js'
import { canonicalDigest } from './canonical-signer.js'
import * as ed from '@noble/ed25519'
import { bytesToHex } from '@noble/hashes/utils'

export interface DelegationConstraint {
  maxActions?: number
  maxSpend?: string
  allowedContexts?: string[]
  forbiddenContexts?: string[]
}

export interface DelegationToken {
  id: string
  delegator: string
  delegatee: string
  capabilities: string[]
  constraints: DelegationConstraint
  issuedAt: string
  expiresAt: string
  nonce: string
  audience?: string[]
  signature: string
}

export type SignedDelegationToken = SignedObject<DelegationToken>

export interface SessionGrant {
  id: string
  token: DelegationToken
  sessionKey: string
  expiresAt: string
  boundTo?: string
}

export interface DelegationInput {
  delegator: string
  delegatee: string
  capabilities: string[]
  constraints: DelegationConstraint
  expiresAt: string
  audience?: string[]
}

export function createDelegationToken(input: DelegationInput): DelegationToken {
  return {
    id: crypto.randomUUID(),
    delegator: input.delegator,
    delegatee: input.delegatee,
    capabilities: input.capabilities,
    constraints: input.constraints,
    issuedAt: new Date().toISOString(),
    expiresAt: input.expiresAt,
    nonce: crypto.randomUUID(),
    audience: input.audience,
    signature: '',
  }
}

/**
 * Sign a delegation token with the delegator's private key.
 * The signature covers the canonical JSON of the token (excluding signature field).
 */
export async function signDelegationToken(
  token: DelegationToken,
  privateKey: Uint8Array
): Promise<DelegationToken> {
  const { signature: _, ...unsigned } = token
  const digest = canonicalDigest(unsigned)
  const sig = await ed.signAsync(digest, privateKey)
  return { ...token, signature: bytesToHex(sig) }
}

/**
 * Verify a delegation token's signature against the delegator's public key.
 */
export async function verifyDelegationTokenSignature(
  token: DelegationToken,
  delegatorPublicKey: Uint8Array
): Promise<boolean> {
  if (!token.signature) return false
  const { signature, ...unsigned } = token
  const digest = canonicalDigest(unsigned)
  const sigBytes = Uint8Array.from(Buffer.from(signature, 'hex'))
  return ed.verifyAsync(sigBytes, digest, delegatorPublicKey)
}

export function isDelegationExpired(token: DelegationToken): boolean {
  return new Date(token.expiresAt) < new Date()
}

export function isSessionExpired(session: SessionGrant): boolean {
  return new Date(session.expiresAt) < new Date()
}

export function validateDelegationToken(token: DelegationToken): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  if (!token.id) errors.push('DelegationToken.id is required')
  if (!token.delegator) errors.push('DelegationToken.delegator is required')
  if (!token.delegatee) errors.push('DelegationToken.delegatee is required')
  if (!token.capabilities || token.capabilities.length === 0) errors.push('DelegationToken.capabilities must not be empty')
  if (!token.nonce) errors.push('DelegationToken.nonce is required')
  if (!token.signature) errors.push('DelegationToken.signature is required')
  if (isDelegationExpired(token)) errors.push('DelegationToken is expired')
  return { valid: errors.length === 0, errors }
}
