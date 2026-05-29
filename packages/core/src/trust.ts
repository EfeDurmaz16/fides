import type { CapabilityControl, CapabilityDescriptor } from './capability.js'

export type TrustBand = 'unknown' | 'low' | 'medium' | 'high' | 'verified'

export interface TrustScoreComponents {
  identity: number
  publisher: number
  trustAnchors: number
  capabilityFit: number
  evidence: number
  policyCompliance: number
  runtimeSafety: number
  peerAttestation: number
  incidentPenalty: number
  noveltyPenalty: number
  contextBoundaryPenalty: number
}

export type TrustReasonComponent =
  | 'IdentityScore'
  | 'PublisherScore'
  | 'TrustAnchorScore'
  | 'CapabilityFitScore'
  | 'EvidenceScore'
  | 'PolicyComplianceScore'
  | 'RuntimeSafetyScore'
  | 'PeerAttestationScore'
  | 'IncidentPenalty'
  | 'NoveltyPenalty'
  | 'ContextBoundaryPenalty'

export interface TrustReason {
  component: TrustReasonComponent
  value: number
  weight: number
  description: string
}

export interface TrustResult {
  schema_version: 'fides.trust.result.v1'
  agent_id: string
  capability: string
  score: number
  band: TrustBand
  reasons: TrustReason[]
  risk_flags: string[]
  evidence_refs: string[]
  required_controls: CapabilityControl[]
  computed_at: string
}

export interface ComputeTrustResultInput {
  agentId: string
  capability: CapabilityDescriptor
  components: TrustScoreComponents
  evidenceRefs?: string[]
  computedAt?: string
}

const POSITIVE_WEIGHTS: Array<{
  key: keyof Omit<TrustScoreComponents, 'incidentPenalty' | 'noveltyPenalty' | 'contextBoundaryPenalty'>
  component: TrustReasonComponent
  weight: number
  description: string
}> = [
  { key: 'identity', component: 'IdentityScore', weight: 0.14, description: 'Cryptographic identity validity and continuity' },
  { key: 'publisher', component: 'PublisherScore', weight: 0.12, description: 'Publisher identity strength' },
  { key: 'trustAnchors', component: 'TrustAnchorScore', weight: 0.12, description: 'Verified trust anchors for this agent or publisher' },
  { key: 'capabilityFit', component: 'CapabilityFitScore', weight: 0.14, description: 'Capability descriptor fit for the requested action' },
  { key: 'evidence', component: 'EvidenceScore', weight: 0.12, description: 'Evidence history quality' },
  { key: 'policyCompliance', component: 'PolicyComplianceScore', weight: 0.14, description: 'Historical policy compliance' },
  { key: 'runtimeSafety', component: 'RuntimeSafetyScore', weight: 0.12, description: 'Runtime or build attestation safety signal' },
  { key: 'peerAttestation', component: 'PeerAttestationScore', weight: 0.10, description: 'Peer attestation signal' },
]

const PENALTY_WEIGHTS: Array<{
  key: keyof Pick<TrustScoreComponents, 'incidentPenalty' | 'noveltyPenalty' | 'contextBoundaryPenalty'>
  component: TrustReasonComponent
  weight: number
  description: string
}> = [
  { key: 'incidentPenalty', component: 'IncidentPenalty', weight: 0.45, description: 'Penalty from unresolved or recent incidents' },
  { key: 'noveltyPenalty', component: 'NoveltyPenalty', weight: 0.20, description: 'Penalty for insufficient history' },
  { key: 'contextBoundaryPenalty', component: 'ContextBoundaryPenalty', weight: 0.25, description: 'Penalty for reputation or trust used outside its context' },
]

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0
  return Math.min(1, Math.max(0, value))
}

export function trustBandForScore(score: number): TrustBand {
  const value = clamp01(score)
  if (value < 0.15) return 'unknown'
  if (value < 0.35) return 'low'
  if (value < 0.6) return 'medium'
  if (value < 0.9) return 'high'
  return 'verified'
}

export function computeTrustResult(input: ComputeTrustResultInput): TrustResult {
  const reasons: TrustReason[] = []
  let score = 0

  for (const item of POSITIVE_WEIGHTS) {
    const value = clamp01(input.components[item.key])
    score += value * item.weight
    reasons.push({
      component: item.component,
      value,
      weight: item.weight,
      description: item.description,
    })
  }

  for (const item of PENALTY_WEIGHTS) {
    const value = clamp01(input.components[item.key])
    score -= value * item.weight
    reasons.push({
      component: item.component,
      value,
      weight: -item.weight,
      description: item.description,
    })
  }

  const riskFlags: string[] = []
  const requiredControls = new Set<CapabilityControl>()

  if ((input.capability.riskLevel === 'high' || input.capability.riskLevel === 'critical') && input.components.runtimeSafety < 0.5) {
    riskFlags.push('runtime_safety_low')
    requiredControls.add('runtime_attestation')
  }

  if (input.capability.requiresApproval || input.capability.riskLevel === 'critical') {
    requiredControls.add('human_approval')
  }

  if (input.components.incidentPenalty > 0.25) riskFlags.push('incident_history')
  if (input.components.contextBoundaryPenalty > 0) riskFlags.push('context_boundary')
  if (input.components.noveltyPenalty > 0.4) riskFlags.push('limited_history')

  return {
    schema_version: 'fides.trust.result.v1',
    agent_id: input.agentId,
    capability: input.capability.id,
    score: Number(clamp01(score).toFixed(4)),
    band: trustBandForScore(score),
    reasons,
    risk_flags: riskFlags,
    evidence_refs: input.evidenceRefs ?? [],
    required_controls: Array.from(requiredControls),
    computed_at: input.computedAt ?? new Date().toISOString(),
  }
}
