import type { TrustAnchor } from './identity.js'

export type TrustAnchorStatus = 'active' | 'suspended' | 'revoked'

export interface GovernedTrustAnchor extends TrustAnchor {
  /** Operational state controlled by trust-anchor governance. */
  status: TrustAnchorStatus
  /** Capability, domain, or federation scopes this anchor is allowed to attest. */
  scopes: string[]
  /** DID of the authority that admitted this anchor into the local trust root set. */
  issuerDid?: string
  /** ISO 8601 timestamp for admission into the local trust root set. */
  createdAt: string
  /** ISO 8601 timestamp for the latest governance update. */
  updatedAt?: string
  /** Optional expiry for temporary or delegated anchors. */
  expiresAt?: string
  /** ISO 8601 timestamp for revocation, required when status is revoked. */
  revokedAt?: string
  /** Human-readable governance reason for suspension or revocation. */
  reason?: string
  metadata?: Record<string, unknown>
}

export interface TrustAnchorGovernancePolicy {
  /** Require this scope to be present on the anchor before accepting it. */
  requiredScope?: string
  /** Restrict accepted governance issuers. Empty/omitted means any issuer. */
  trustedIssuerDids?: string[]
  /** Evaluation time, defaults to now. */
  now?: string | Date
}

export interface TrustAnchorValidationResult {
  valid: boolean
  errors: string[]
}

export interface TrustAnchorDistribution {
  version: 'fides.trust-anchors.v1'
  generatedAt: string
  issuerDid?: string
  anchors: TrustAnchorDistributionEntry[]
}

export interface TrustAnchorDistributionEntry {
  did: string
  name: string
  publicKey: string
  scopes: string[]
  issuerDid?: string
  createdAt: string
  updatedAt?: string
  expiresAt?: string
}

export function validateTrustAnchor(
  anchor: GovernedTrustAnchor,
  policy: TrustAnchorGovernancePolicy = {}
): TrustAnchorValidationResult {
  const errors: string[] = []
  const now = normalizeTime(policy.now ?? new Date())

  if (!anchor.did?.startsWith('did:fides:')) {
    errors.push('TrustAnchor.did must be a did:fides DID')
  }
  if (!anchor.name) {
    errors.push('TrustAnchor.name is required')
  }
  if (!(anchor.publicKey instanceof Uint8Array) || anchor.publicKey.length !== 32) {
    errors.push('TrustAnchor.publicKey must be 32 bytes')
  }
  if (!Array.isArray(anchor.scopes) || anchor.scopes.length === 0) {
    errors.push('TrustAnchor.scopes must contain at least one scope')
  }
  if (!anchor.createdAt || Number.isNaN(Date.parse(anchor.createdAt))) {
    errors.push('TrustAnchor.createdAt must be an ISO 8601 timestamp')
  }
  if (anchor.status === 'revoked' && !anchor.revokedAt) {
    errors.push('revoked trust anchors must include revokedAt')
  }
  if (anchor.status !== 'active') {
    errors.push(`trust anchor is ${anchor.status}`)
  }
  if (anchor.expiresAt && normalizeTime(anchor.expiresAt).getTime() <= now.getTime()) {
    errors.push('trust anchor has expired')
  }
  if (policy.requiredScope && !anchor.scopes.includes(policy.requiredScope)) {
    errors.push(`trust anchor is not authorized for scope ${policy.requiredScope}`)
  }
  if (
    policy.trustedIssuerDids &&
    policy.trustedIssuerDids.length > 0 &&
    (!anchor.issuerDid || !policy.trustedIssuerDids.includes(anchor.issuerDid))
  ) {
    errors.push('trust anchor issuer is not trusted')
  }

  return { valid: errors.length === 0, errors }
}

export function createTrustAnchorDistribution(
  anchors: GovernedTrustAnchor[],
  options: { issuerDid?: string; generatedAt?: string | Date; policy?: TrustAnchorGovernancePolicy } = {}
): TrustAnchorDistribution {
  const generatedAt = normalizeTime(options.generatedAt ?? new Date()).toISOString()
  const policy = { ...options.policy, now: generatedAt }
  const activeAnchors = anchors
    .filter(anchor => validateTrustAnchor(anchor, policy).valid)
    .sort((a, b) => a.did.localeCompare(b.did))
    .map(anchor => ({
      did: anchor.did,
      name: anchor.name,
      publicKey: bytesToHex(anchor.publicKey),
      scopes: [...anchor.scopes].sort(),
      issuerDid: anchor.issuerDid,
      createdAt: anchor.createdAt,
      updatedAt: anchor.updatedAt,
      expiresAt: anchor.expiresAt,
    }))

  return {
    version: 'fides.trust-anchors.v1',
    generatedAt,
    issuerDid: options.issuerDid,
    anchors: activeAnchors,
  }
}

function normalizeTime(value: string | Date): Date {
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) {
    throw new Error('Invalid trust anchor timestamp')
  }
  return date
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('')
}
