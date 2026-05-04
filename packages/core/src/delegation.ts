/**
 * FIDES v2 Delegation Primitives
 *
 * Ported from OAPS DelegationToken with FIDES signing.
 */

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

export interface SessionGrant {
  id: string
  token: DelegationToken
  sessionKey: string
  expiresAt: string
  boundTo?: string
}

export function isDelegationExpired(token: DelegationToken): boolean {
  return new Date(token.expiresAt) < new Date()
}

export function isSessionExpired(session: SessionGrant): boolean {
  return new Date(session.expiresAt) < new Date()
}
