export interface ReputationReason {
  factor: 'success_rate' | 'volume_confidence' | 'publisher_weight' | 'incident_penalty' | 'context_boundary_penalty'
  value: number
  description: string
}

export interface ReputationRecord {
  schema_version: 'fides.reputation.record.v1'
  agent_id: string
  publisher_id?: string
  principal_id?: string
  capability: string
  score: number
  successful_invocations: number
  failed_invocations: number
  incident_count: number
  publisher_weight: number
  context_boundary_penalty: number
  reasons: ReputationReason[]
  computed_at: string
}

export interface ComputeCapabilityReputationInput {
  agentId: string
  publisherId?: string
  principalId?: string
  capability: string
  successfulInvocations?: number
  failedInvocations?: number
  incidentCount?: number
  publisherWeight?: number
  contextBoundaryMismatch?: boolean
  computedAt?: string
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0
  return Math.min(1, Math.max(0, value))
}

export function computeCapabilityReputation(input: ComputeCapabilityReputationInput): ReputationRecord {
  const successful = Math.max(0, input.successfulInvocations ?? 0)
  const failed = Math.max(0, input.failedInvocations ?? 0)
  const incidentCount = Math.max(0, input.incidentCount ?? 0)
  const total = successful + failed
  const successRate = total === 0 ? 0 : successful / total
  const volumeConfidence = Math.min(1, total / 20)
  const publisherWeight = clamp01(input.publisherWeight ?? 0.5)
  const incidentPenalty = Math.min(1, incidentCount * 0.18)
  const contextBoundaryPenalty = input.contextBoundaryMismatch ? 0.2 : 0

  const score = clamp01(
    (successRate * 0.48) +
    (volumeConfidence * 0.22) +
    (publisherWeight * 0.20) +
    0.10 -
    incidentPenalty -
    contextBoundaryPenalty
  )

  return {
    schema_version: 'fides.reputation.record.v1',
    agent_id: input.agentId,
    publisher_id: input.publisherId,
    principal_id: input.principalId,
    capability: input.capability,
    score: Number(score.toFixed(4)),
    successful_invocations: successful,
    failed_invocations: failed,
    incident_count: incidentCount,
    publisher_weight: publisherWeight,
    context_boundary_penalty: contextBoundaryPenalty,
    reasons: [
      { factor: 'success_rate', value: Number(successRate.toFixed(4)), description: 'Capability-specific invocation success rate' },
      { factor: 'volume_confidence', value: Number(volumeConfidence.toFixed(4)), description: 'Confidence from observed volume for this capability' },
      { factor: 'publisher_weight', value: publisherWeight, description: 'Publisher-weighted reputation signal' },
      { factor: 'incident_penalty', value: incidentPenalty, description: 'Penalty from incidents scoped to this capability or agent' },
      { factor: 'context_boundary_penalty', value: contextBoundaryPenalty, description: 'Penalty for applying reputation outside its capability context' },
    ],
    computed_at: input.computedAt ?? new Date().toISOString(),
  }
}

export function createReputationRecord(input: ComputeCapabilityReputationInput): ReputationRecord {
  return computeCapabilityReputation(input)
}
