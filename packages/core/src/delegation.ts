/**
 * FIDES v2 Delegation Primitives
 *
 * Ported from OAPS DelegationToken with FIDES signing.
 */

import type { SignedObject } from './canonical-signer.js'

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
    signature: '', // Must be signed separately using CanonicalSigner
  }
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
