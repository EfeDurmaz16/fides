/**
 * FIDES v2 Revocation and Incident Primitives
 *
 * Provides creation, signing, verification, and propagation of
 * revocation records and incident reports.
 */

import { canonicalDigest, signObject, verifyObject, type SignedObject } from './canonical-signer.js'
import { hashProtocolPayload } from './protocol.js'
import * as ed from '@noble/ed25519'
import { bytesToHex } from '@noble/hashes/utils'

export type RevocationTargetType =
  | 'key'
  | 'identity'
  | 'agent'
  | 'agent_card'
  | 'capability'
  | 'session'
  | 'attestation'
  | 'publisher'

export type IncidentCategory =
  | 'policy_violation'
  | 'data_exfiltration'
  | 'malicious_output'
  | 'sandbox_escape'
  | 'unauthorized_action'
  | 'prompt_injection_failure'
  | 'payment_error'
  | 'suspicious_behavior'

export interface RevocationRecordV2 {
  schema_version: 'fides.revocation.record.v1'
  id: string
  issuer: string
  subject: string
  target_type: RevocationTargetType
  target_id: string
  reason: string
  status: 'active' | 'superseded' | 'expired'
  evidence_refs: string[]
  created_at: string
  expires_at?: string
  payload_hash: string
}

export interface IncidentRecordV2 {
  schema_version: 'fides.incident.record.v1'
  id: string
  issuer: string
  subject: string
  reporter: string
  target_agent_id: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  category: IncidentCategory
  description: string
  evidence_refs: string[]
  resolution_status: 'open' | 'resolved' | 'dismissed' | 'false_positive'
  trust_penalty: number
  reputation_penalty: number
  created_at: string
  resolved_at?: string
  payload_hash: string
}

export interface RevocationInputV2 {
  issuer: string
  targetType: RevocationTargetType
  targetId: string
  reason: string
  evidenceRefs?: string[]
  createdAt?: string
  expiresAt?: string
}

export interface IncidentInputV2 {
  reporter: string
  targetAgentId: string
  severity: IncidentRecordV2['severity']
  category: IncidentCategory
  description: string
  evidenceRefs?: string[]
  trustPenalty?: number
  reputationPenalty?: number
  createdAt?: string
}

export type SignedRevocationRecordV2 = SignedObject<RevocationRecordV2>
export type SignedIncidentRecordV2 = SignedObject<IncidentRecordV2>

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
  reportedBy: string
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
  reportedBy: string
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

export function createRevocationRecordV2(input: RevocationInputV2): RevocationRecordV2 {
  const payload = {
    schema_version: 'fides.revocation.record.v1' as const,
    id: crypto.randomUUID(),
    issuer: input.issuer,
    subject: input.targetId,
    target_type: input.targetType,
    target_id: input.targetId,
    reason: input.reason,
    status: 'active' as const,
    evidence_refs: input.evidenceRefs ?? [],
    created_at: input.createdAt ?? new Date().toISOString(),
    expires_at: input.expiresAt,
  }
  return {
    ...payload,
    payload_hash: hashProtocolPayload(payload),
  }
}

export function createIncidentRecordV2(input: IncidentInputV2): IncidentRecordV2 {
  const penalties = SEVERITY_PENALTY[input.severity] ?? { trust: 0.1, reputation: 0.2 }
  const payload = {
    schema_version: 'fides.incident.record.v1' as const,
    id: crypto.randomUUID(),
    issuer: input.reporter,
    subject: input.targetAgentId,
    reporter: input.reporter,
    target_agent_id: input.targetAgentId,
    severity: input.severity,
    category: input.category,
    description: input.description,
    evidence_refs: input.evidenceRefs ?? [],
    resolution_status: 'open' as const,
    trust_penalty: input.trustPenalty ?? penalties.trust,
    reputation_penalty: input.reputationPenalty ?? penalties.reputation,
    created_at: input.createdAt ?? new Date().toISOString(),
  }
  return {
    ...payload,
    payload_hash: hashProtocolPayload(payload),
  }
}

export function resolveIncidentRecordV2(
  record: IncidentRecordV2,
  status: Exclude<IncidentRecordV2['resolution_status'], 'open'> = 'resolved'
): IncidentRecordV2 {
  const payload = {
    ...record,
    resolution_status: status,
    resolved_at: new Date().toISOString(),
    payload_hash: undefined,
  }
  const { payload_hash: _, ...withoutHash } = payload
  return {
    ...record,
    resolution_status: status,
    resolved_at: payload.resolved_at,
    payload_hash: hashProtocolPayload(withoutHash),
  }
}

export function signRevocationRecordV2(
  record: RevocationRecordV2,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<SignedRevocationRecordV2> {
  return signObject(record, privateKey, { verificationMethod, proofPurpose: 'assertionMethod' })
}

export function verifySignedRevocationRecordV2(signed: SignedRevocationRecordV2): Promise<boolean> {
  return verifyObject(signed)
}

export function signIncidentRecordV2(
  record: IncidentRecordV2,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<SignedIncidentRecordV2> {
  return signObject(record, privateKey, { verificationMethod, proofPurpose: 'assertionMethod' })
}

export function verifySignedIncidentRecordV2(signed: SignedIncidentRecordV2): Promise<boolean> {
  return verifyObject(signed)
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
    reportedBy: input.reportedBy,
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
