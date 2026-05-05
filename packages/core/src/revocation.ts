/**
 * FIDES v2 Revocation and Incident Primitives
 *
 * Provides creation, signing, verification, and propagation of
 * revocation records and incident reports.
 */

import { canonicalDigest } from './canonical-signer.js'
import * as ed from '@noble/ed25519'
import { bytesToHex } from '@noble/hashes/utils'

export interface RevocationRecord {
  id: string
  did: string
  reason: string
  revokedAt: string
  revokedBy: string
  signature: string
  propagatedTo: string[]
}

export interface RevocationInput {
  did: string
  reason: string
  revokedBy: string
}

export interface IncidentRecord {
  id: string
  type: 'compromise' | 'misbehavior' | 'policy_violation' | 'runtime_failure' | 'sybil'
  severity: 'low' | 'medium' | 'high' | 'critical'
  actor: string
  description: string
  evidenceRefs: string[]
  reportedAt: string
  resolvedAt?: string
  impact: {
    trustPenalty: number
    reputationPenalty: number
    capabilitiesRevoked: string[]
  }
  signature: string
}

export interface IncidentInput {
  type: IncidentRecord['type']
  severity: IncidentRecord['severity']
  actor: string
  description: string
  evidenceRefs?: string[]
  trustPenalty?: number
  reputationPenalty?: number
  capabilitiesRevoked?: string[]
}

const SEVERITY_PENALTY: Record<string, { trust: number; reputation: number }> = {
  low: { trust: 0.05, reputation: 0.1 },
  medium: { trust: 0.15, reputation: 0.3 },
  high: { trust: 0.35, reputation: 0.7 },
  critical: { trust: 0.6, reputation: 1.0 },
}

/**
 * Create a revocation record (unsigned).
 */
export function createRevocationRecord(input: RevocationInput): RevocationRecord {
  return {
    id: crypto.randomUUID(),
    did: input.did,
    reason: input.reason,
    revokedAt: new Date().toISOString(),
    revokedBy: input.revokedBy,
    signature: '',
    propagatedTo: [],
  }
}

/**
 * Sign a revocation record with the revoker's private key.
 */
export async function signRevocationRecord(
  record: RevocationRecord,
  privateKey: Uint8Array
): Promise<RevocationRecord> {
  const { signature: _, ...unsigned } = record
  const digest = canonicalDigest(unsigned)
  const sig = await ed.signAsync(digest, privateKey)
  return { ...record, signature: bytesToHex(sig) }
}

/**
 * Verify a revocation record's signature.
 */
export async function verifyRevocationRecord(
  record: RevocationRecord,
  revokerPublicKey: Uint8Array
): Promise<boolean> {
  if (!record.signature) return false
  const { signature, ...unsigned } = record
  const digest = canonicalDigest(unsigned)
  const sigBytes = Uint8Array.from(Buffer.from(signature, 'hex'))
  return ed.verifyAsync(sigBytes, digest, revokerPublicKey)
}

/**
 * Mark a revocation as propagated to a node.
 */
export function markPropagated(record: RevocationRecord, nodeId: string): RevocationRecord {
  if (record.propagatedTo.includes(nodeId)) return record
  return { ...record, propagatedTo: [...record.propagatedTo, nodeId] }
}

/**
 * Create an incident record (unsigned).
 */
export function createIncidentRecord(input: IncidentInput): IncidentRecord {
  const penalties = SEVERITY_PENALTY[input.severity] ?? { trust: 0.1, reputation: 0.2 }
  return {
    id: crypto.randomUUID(),
    type: input.type,
    severity: input.severity,
    actor: input.actor,
    description: input.description,
    evidenceRefs: input.evidenceRefs ?? [],
    reportedAt: new Date().toISOString(),
    impact: {
      trustPenalty: input.trustPenalty ?? penalties.trust,
      reputationPenalty: input.reputationPenalty ?? penalties.reputation,
      capabilitiesRevoked: input.capabilitiesRevoked ?? [],
    },
    signature: '',
  }
}

/**
 * Sign an incident record with the reporter's private key.
 */
export async function signIncidentRecord(
  record: IncidentRecord,
  privateKey: Uint8Array
): Promise<IncidentRecord> {
  const { signature: _, ...unsigned } = record
  const digest = canonicalDigest(unsigned)
  const sig = await ed.signAsync(digest, privateKey)
  return { ...record, signature: bytesToHex(sig) }
}

/**
 * Verify an incident record's signature.
 */
export async function verifyIncidentRecord(
  record: IncidentRecord,
  reporterPublicKey: Uint8Array
): Promise<boolean> {
  if (!record.signature) return false
  const { signature, ...unsigned } = record
  const digest = canonicalDigest(unsigned)
  const sigBytes = Uint8Array.from(Buffer.from(signature, 'hex'))
  return ed.verifyAsync(sigBytes, digest, reporterPublicKey)
}

/**
 * Resolve an incident (mark as resolved).
 */
export function resolveIncident(record: IncidentRecord): IncidentRecord {
  return { ...record, resolvedAt: new Date().toISOString() }
}

/**
 * Check if a revocation is still valid (not superseded).
 */
export function isRevocationValid(record: RevocationRecord, cutoffDate?: Date): boolean {
  const revokedAt = new Date(record.revokedAt)
  if (cutoffDate && revokedAt > cutoffDate) return false
  return true
}

/**
 * Aggregate incident impact for a DID.
 */
export function aggregateIncidentImpact(
  incidents: IncidentRecord[]
): {
  totalTrustPenalty: number
  totalReputationPenalty: number
  allRevokedCapabilities: string[]
  incidentCount: number
  criticalCount: number
} {
  let totalTrustPenalty = 0
  let totalReputationPenalty = 0
  const allRevokedCapabilities = new Set<string>()
  let criticalCount = 0

  for (const inc of incidents) {
    totalTrustPenalty += inc.impact.trustPenalty
    totalReputationPenalty += inc.impact.reputationPenalty
    for (const cap of inc.impact.capabilitiesRevoked) {
      allRevokedCapabilities.add(cap)
    }
    if (inc.severity === 'critical') criticalCount++
  }

  return {
    totalTrustPenalty: Math.min(totalTrustPenalty, 1.0),
    totalReputationPenalty: Math.min(totalReputationPenalty, 1.0),
    allRevokedCapabilities: Array.from(allRevokedCapabilities),
    incidentCount: incidents.length,
    criticalCount,
  }
}
