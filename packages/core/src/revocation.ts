/**
 * FIDES v2 Revocation and Incident Primitives
 */

export interface RevocationRecord {
  id: string
  did: string
  reason: string
  revokedAt: string
  revokedBy: string
  signature: string
  propagatedTo: string[]
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
}
