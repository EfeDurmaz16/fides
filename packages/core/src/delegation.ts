/**
 * FIDES v2 Delegation Primitives
 *
 * Ported from OAPS DelegationToken with FIDES signing.
 */

import type { SignedObject } from './canonical-signer.js'
import { canonicalDigest, signObject, verifyObject } from './canonical-signer.js'
import { FIDES_PROTOCOL_VERSION, FIDES_SUPPORTED_PROTOCOL_VERSIONS, hashProtocolPayload } from './protocol.js'
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

export interface SessionGrantV2 {
  schema_version: 'fides.session_grant.v1'
  id: string
  session_id: string
  subject: string
  requester_agent_id: string
  target_agent_id: string
  principal_id: string
  capability: string
  scopes: string[]
  constraints: Record<string, unknown>
  policy_hash: string
  trust_result_hash: string
  issued_at: string
  expires_at: string
  nonce: string
  audience: string[]
  supported_versions: string[]
  required_versions?: string[]
  negotiated_version: string
  issuer: string
  payload_hash: string
}

export type SignedSessionGrantV2 = SignedObject<SessionGrantV2>

export interface DelegationInput {
  delegator: string
  delegatee: string
  capabilities: string[]
  constraints: DelegationConstraint
  expiresAt: string
  audience?: string[]
}

export interface SessionGrantV2Input {
  requesterAgentId: string
  targetAgentId: string
  principalId: string
  capability: string
  scopes: string[]
  constraints?: Record<string, unknown>
  policyHash: string
  trustResultHash: string
  audience?: string[]
  supportedVersions?: string[]
  requiredVersions?: string[]
  negotiatedVersion?: string
  issuer: string
  issuedAt?: string
  expiresAt: string
  nonce?: string
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

export function createSessionGrantV2(input: SessionGrantV2Input): SessionGrantV2 {
  const sessionId = crypto.randomUUID()
  const supportedVersions = input.supportedVersions?.length
    ? input.supportedVersions
    : [...FIDES_SUPPORTED_PROTOCOL_VERSIONS]
  const negotiatedVersion = input.negotiatedVersion ?? (
    supportedVersions.includes(FIDES_PROTOCOL_VERSION) ? FIDES_PROTOCOL_VERSION : supportedVersions[0]
  )
  const payload = {
    schema_version: 'fides.session_grant.v1' as const,
    id: sessionId,
    session_id: sessionId,
    subject: input.targetAgentId,
    requester_agent_id: input.requesterAgentId,
    target_agent_id: input.targetAgentId,
    principal_id: input.principalId,
    capability: input.capability,
    scopes: input.scopes,
    constraints: input.constraints ?? {},
    policy_hash: input.policyHash,
    trust_result_hash: input.trustResultHash,
    issued_at: input.issuedAt ?? new Date().toISOString(),
    expires_at: input.expiresAt,
    nonce: input.nonce ?? crypto.randomUUID(),
    audience: input.audience ?? [input.targetAgentId],
    supported_versions: supportedVersions,
    ...(input.requiredVersions?.length ? { required_versions: input.requiredVersions } : {}),
    negotiated_version: negotiatedVersion,
    issuer: input.issuer,
  }

  return {
    ...payload,
    payload_hash: hashProtocolPayload(payload),
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

export function isSessionGrantV2Expired(session: SessionGrantV2, now: Date = new Date()): boolean {
  return new Date(session.expires_at) <= now
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

export function validateSessionGrantV2(session: SessionGrantV2): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  if (session.schema_version !== 'fides.session_grant.v1') errors.push('SessionGrant.schema_version is invalid')
  if (!session.id) errors.push('SessionGrant.id is required')
  if (!session.session_id) errors.push('SessionGrant.session_id is required')
  if (session.id && session.session_id && session.id !== session.session_id) {
    errors.push('SessionGrant.id must match SessionGrant.session_id')
  }
  if (!session.subject) errors.push('SessionGrant.subject is required')
  if (!session.requester_agent_id) errors.push('SessionGrant.requester_agent_id is required')
  if (!session.target_agent_id) errors.push('SessionGrant.target_agent_id is required')
  if (session.subject && session.target_agent_id && session.subject !== session.target_agent_id) {
    errors.push('SessionGrant.subject must match SessionGrant.target_agent_id')
  }
  if (!session.principal_id) errors.push('SessionGrant.principal_id is required')
  if (!session.capability) errors.push('SessionGrant.capability is required')
  if (!session.scopes || session.scopes.length === 0) errors.push('SessionGrant.scopes must not be empty')
  if (!session.policy_hash) errors.push('SessionGrant.policy_hash is required')
  if (!session.trust_result_hash) errors.push('SessionGrant.trust_result_hash is required')
  if (!session.nonce) errors.push('SessionGrant.nonce is required')
  if (!session.supported_versions || session.supported_versions.length === 0) {
    errors.push('SessionGrant.supported_versions must not be empty')
  }
  if (!session.negotiated_version) errors.push('SessionGrant.negotiated_version is required')
  if (
    session.negotiated_version &&
    session.supported_versions?.length &&
    !session.supported_versions.includes(session.negotiated_version)
  ) {
    errors.push('SessionGrant.negotiated_version must be included in supported_versions')
  }
  if (
    session.required_versions?.length &&
    session.supported_versions?.length &&
    session.required_versions.some(version => !session.supported_versions.includes(version))
  ) {
    errors.push('SessionGrant.required_versions must be included in supported_versions')
  }
  if (!session.issuer) errors.push('SessionGrant.issuer is required')
  if (!session.expires_at) errors.push('SessionGrant.expires_at is required')
  if (session.expires_at && isSessionGrantV2Expired(session)) errors.push('SessionGrant is expired')
  return { valid: errors.length === 0, errors }
}

export function signSessionGrantV2(
  session: SessionGrantV2,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<SignedSessionGrantV2> {
  return signObject(session, privateKey, { verificationMethod, proofPurpose: 'delegation' })
}

export function verifySignedSessionGrantV2(signed: SignedSessionGrantV2): Promise<boolean> {
  return verifyObject(signed)
}

export async function verifySignedSessionGrantV2Issuer(signed: SignedSessionGrantV2): Promise<boolean> {
  return signed.proof.verificationMethod === signed.payload.issuer && await verifySignedSessionGrantV2(signed)
}

export interface RevokedSession extends SessionGrant {
  revoked: boolean
  revokedAt: string
}

export function createSessionGrant(options: {
  token: DelegationToken
  boundTo?: string
  ttlMs?: number
}): SessionGrant {
  const privateKey = ed.utils.randomPrivateKey()
  const ttl = options.ttlMs ?? 3600_000
  const now = new Date()
  const expiresAt = new Date(now.getTime() + ttl)

  return {
    id: crypto.randomUUID(),
    token: options.token,
    sessionKey: bytesToHex(privateKey),
    expiresAt: expiresAt.toISOString(),
    boundTo: options.boundTo,
  }
}

export function validateSessionGrant(session: SessionGrant): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  if (!session.id) errors.push('SessionGrant.id is required')
  if (!session.token) errors.push('SessionGrant.token is required')
  if (!session.sessionKey) errors.push('SessionGrant.sessionKey is required')
  if (!session.expiresAt) errors.push('SessionGrant.expiresAt is required')
  if (isSessionExpired(session)) errors.push('SessionGrant is expired')
  if (session.token) {
    const tokenValidation = validateDelegationToken(session.token)
    if (!tokenValidation.valid) {
      errors.push(...tokenValidation.errors.map(e => `SessionGrant.token: ${e}`))
    }
  }
  return { valid: errors.length === 0, errors }
}

export async function deriveEd25519PublicKeyHex(privateKeyHex: string): Promise<string> {
  const privateKeyBytes = Uint8Array.from(Buffer.from(privateKeyHex, 'hex'))
  const publicKey = await ed.getPublicKeyAsync(privateKeyBytes)
  return bytesToHex(publicKey)
}

export async function deriveSessionPublicKey(sessionKeyHex: string): Promise<string> {
  return deriveEd25519PublicKeyHex(sessionKeyHex)
}

export function revokeSession(session: SessionGrant): RevokedSession {
  return {
    ...session,
    revoked: true,
    revokedAt: new Date().toISOString(),
  }
}
