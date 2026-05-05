/**
 * FIDES v2 Guard — Unified Decision Engine
 *
 * Integrates policy evaluation, trust scores, runtime attestation,
 * evidence chain integrity, and kill switch status into a single
 * authorization decision.
 */

import type { PolicyBundle, PolicyContext, PolicyResult } from '@fides/policy'
import { evaluatePolicy, runPreExecutionPipeline, type Guard } from '@fides/policy'
import type { RuntimeAttestation, KillSwitch } from '@fides/runtime'
import type { EvidenceChain } from '@fides/evidence'
import { verifyEvidenceChain } from '@fides/evidence'
import { TrustError } from '@fides/shared'

export interface TrustContext {
  /** Overall reputation score (0-1) */
  reputationScore: number
  /** Capability-specific score (0-1), if available */
  capabilityScore?: number
  /** Whether the agent's TEE attestation is valid */
  attestationValid: boolean
  /** Active runtime attestation, if any */
  attestation?: RuntimeAttestation
  /** Evidence chain for this agent, if available */
  evidenceChain?: EvidenceChain
  /** Whether the kill switch is engaged for this agent */
  killSwitchEngaged: boolean
  /** Whether the agent authority has been revoked */
  agentRevoked?: boolean
  /** Whether the active session grant has been revoked */
  sessionRevoked?: boolean
  /** Revocation reason, if available */
  revocationReason?: string
  /** Whether this capability is treated as high-risk */
  capabilityHighRisk?: boolean
  /** Whether policy requires runtime attestation for this request */
  requiresRuntimeAttestation?: boolean
  /** Whether policy requires human/principal approval for this request */
  requiresApproval?: boolean
  /** Whether the required approval has already been granted */
  approvalGranted?: boolean
  /** Incident count in last 24h */
  recentIncidents: number
}

export interface GuardRequest {
  /** Agent DID making the request */
  agentDid: string
  /** Capability being invoked */
  capabilityId: string
  /** Policy bundle to evaluate */
  policy: PolicyBundle
  /** Additional context for policy evaluation */
  context: Record<string, unknown>
  /** Trust context (scores, attestation, evidence) */
  trust: TrustContext
}

export interface GuardDecision {
  /** Final decision */
  decision: 'allow' | 'deny' | 'approve-required' | 'dry-run'
  /** Human-readable explanation */
  explanation: string
  /** Factors that influenced the decision */
  factors: Array<{ source: string; factor: string; weight: number; description: string }>
  /** Underlying policy result, if evaluated */
  policyResult?: PolicyResult
}

/**
 * Minimum trust score threshold for automatic allow.
 * Below this, policy evaluation still runs but trust is a negative factor.
 */
const MIN_TRUST_THRESHOLD = 0.3

/**
 * Maximum recent incidents before automatic deny.
 */
const MAX_RECENT_INCIDENTS = 5

/**
 * Unified guard evaluation.
 *
 * Decision flow:
 * 1. Kill switch check (immediate deny if engaged)
 * 2. Attestation check (deny if invalid and required)
 * 3. Evidence chain integrity check (deny if broken)
 * 4. Incident rate check (deny if too many recent incidents)
 * 5. Trust score check (factor into decision)
 * 6. Policy evaluation (final decision)
 */
export async function evaluateGuard(request: GuardRequest): Promise<GuardDecision> {
  const factors: GuardDecision['factors'] = []
  const { trust, agentDid, capabilityId, policy, context } = request

  // 1. Kill switch check — immediate deny
  if (trust.killSwitchEngaged) {
    return {
      decision: 'deny',
      explanation: `Kill switch engaged for agent ${agentDid}`,
      factors: [{ source: 'kill-switch', factor: 'kill-switch-engaged', weight: 1.0, description: 'Emergency kill switch is active' }],
    }
  }

  if (trust.agentRevoked) {
    return {
      decision: 'deny',
      explanation: `Agent authority revoked for ${agentDid}`,
      factors: [{ source: 'revocation', factor: 'agent-revoked', weight: 1.0, description: trust.revocationReason ?? 'Agent revocation record is active' }],
    }
  }

  if (trust.sessionRevoked) {
    return {
      decision: 'deny',
      explanation: `Session authority revoked for ${agentDid}`,
      factors: [{ source: 'revocation', factor: 'session-revoked', weight: 1.0, description: trust.revocationReason ?? 'Session revocation record is active' }],
    }
  }

  // 2. Attestation check
  if (trust.capabilityHighRisk) {
    factors.push({
      source: 'risk',
      factor: 'high-risk-capability',
      weight: 0.7,
      description: `${capabilityId} is marked as high-risk`,
    })
  }

  if (trust.requiresRuntimeAttestation && !trust.attestationValid) {
    return {
      decision: 'deny',
      explanation: `Runtime attestation is required for ${capabilityId}`,
      factors: [...factors, { source: 'attestation', factor: 'attestation-required', weight: 1.0, description: 'No valid runtime attestation is available' }],
    }
  }

  if (trust.requiresApproval && !trust.approvalGranted) {
    return {
      decision: 'approve-required',
      explanation: `Approval is required for ${capabilityId}`,
      factors: [...factors, { source: 'approval', factor: 'approval-required', weight: 1.0, description: 'Policy requires principal approval before execution' }],
    }
  }

  if (trust.attestation) {
    const expiresAt = new Date(trust.attestation.expiresAt)
    if (expiresAt < new Date()) {
      factors.push({
        source: 'attestation',
        factor: 'attestation-expired',
        weight: 0.8,
        description: 'Runtime attestation has expired',
      })
    } else if (!trust.attestationValid) {
      factors.push({
        source: 'attestation',
        factor: 'attestation-invalid',
        weight: 0.9,
        description: 'Runtime attestation verification failed',
      })
    } else {
      factors.push({
        source: 'attestation',
        factor: 'attestation-valid',
        weight: 0.3,
        description: `Valid attestation from ${trust.attestation.provider}`,
      })
    }
  }

  // 3. Evidence chain integrity
  if (trust.evidenceChain) {
    const chainValid = verifyEvidenceChain(trust.evidenceChain)
    if (!chainValid) {
      return {
        decision: 'deny',
        explanation: 'Evidence chain integrity verification failed',
        factors: [...factors, { source: 'evidence', factor: 'chain-broken', weight: 1.0, description: 'Evidence hash chain is invalid' }],
      }
    }
    factors.push({
      source: 'evidence',
      factor: 'chain-valid',
      weight: 0.2,
      description: `Evidence chain verified (${trust.evidenceChain.events.length} events)`,
    })
  }

  // 4. Incident rate check
  if (trust.recentIncidents >= MAX_RECENT_INCIDENTS) {
    return {
      decision: 'deny',
      explanation: `Too many recent incidents (${trust.recentIncidents}) for agent ${agentDid}`,
      factors: [...factors, { source: 'incidents', factor: 'high-incident-rate', weight: 1.0, description: `${trust.recentIncidents} incidents in last 24h exceeds threshold of ${MAX_RECENT_INCIDENTS}` }],
    }
  } else if (trust.recentIncidents > 0) {
    factors.push({
      source: 'incidents',
      factor: 'recent-incidents',
      weight: trust.recentIncidents * 0.1,
      description: `${trust.recentIncidents} recent incidents`,
    })
  }

  // 5. Trust score factor
  if (trust.reputationScore < MIN_TRUST_THRESHOLD) {
    factors.push({
      source: 'trust',
      factor: 'low-reputation',
      weight: 0.7,
      description: `Reputation score ${trust.reputationScore.toFixed(2)} below threshold ${MIN_TRUST_THRESHOLD}`,
    })
  } else {
    factors.push({
      source: 'trust',
      factor: 'reputation-ok',
      weight: 0.2,
      description: `Reputation score ${trust.reputationScore.toFixed(2)}`,
    })
  }

  if (trust.capabilityScore !== undefined) {
    if (trust.capabilityScore < MIN_TRUST_THRESHOLD) {
      factors.push({
        source: 'trust',
        factor: 'low-capability-score',
        weight: 0.8,
        description: `Capability score ${trust.capabilityScore.toFixed(2)} for ${capabilityId}`,
      })
    } else {
      factors.push({
        source: 'trust',
        factor: 'capability-score-ok',
        weight: 0.2,
        description: `Capability score ${trust.capabilityScore.toFixed(2)} for ${capabilityId}`,
      })
    }
  }

  // 6. Build policy context with trust scores injected
  const policyContext: PolicyContext = {
    ...context,
    agentDid,
    capabilityId,
    reputationScore: trust.reputationScore,
    ...(trust.capabilityScore !== undefined && { capabilityScore: trust.capabilityScore }),
    recentIncidents: trust.recentIncidents,
    attestationValid: trust.attestationValid,
    agentRevoked: trust.agentRevoked ?? false,
    sessionRevoked: trust.sessionRevoked ?? false,
    capabilityHighRisk: trust.capabilityHighRisk ?? false,
    requiresRuntimeAttestation: trust.requiresRuntimeAttestation ?? false,
    requiresApproval: trust.requiresApproval ?? false,
    approvalGranted: trust.approvalGranted ?? false,
  }

  // Run pre-execution pipeline (guards)
  const trustGuard: Guard = {
    name: 'trust-threshold',
    evaluate: (ctx) => {
      const score = (ctx.reputationScore as number) ?? 0
      if (score < 0.1) return 'block'
      if (score < MIN_TRUST_THRESHOLD) return 'warn'
      return 'allow'
    },
  }

  const pipelineResult = await runPreExecutionPipeline([trustGuard], policyContext)
  if (pipelineResult.decision === 'block') {
    return {
      decision: 'deny',
      explanation: `Blocked by trust threshold guard (score: ${trust.reputationScore.toFixed(2)})`,
      factors: [...factors, { source: 'pipeline', factor: 'trust-guard-block', weight: 1.0, description: 'Reputation score below minimum threshold' }],
    }
  }

  // Evaluate policy bundle
  const policyResult = evaluatePolicy(policy, policyContext)

  // If policy denies, return immediately
  if (policyResult.decision === 'deny') {
    return {
      decision: 'deny',
      explanation: policyResult.explanation.decision,
      factors: [...factors, ...policyResult.explanation.factors.map(f => ({ source: 'policy', ...f }))],
      policyResult,
    }
  }

  // If policy requires approval, return
  if (policyResult.decision === 'approve-required') {
    return {
      decision: 'approve-required',
      explanation: policyResult.explanation.decision,
      factors: [...factors, ...policyResult.explanation.factors.map(f => ({ source: 'policy', ...f }))],
      policyResult,
    }
  }

  // Policy allows — check if trust factors should downgrade
  if (pipelineResult.decision === 'warn') {
    return {
      decision: 'dry-run',
      explanation: `Allowed by policy but trust score is low — dry-run mode`,
      factors: [...factors, ...policyResult.explanation.factors.map(f => ({ source: 'policy', ...f }))],
      policyResult,
    }
  }

  return {
    decision: policyResult.decision,
    explanation: policyResult.explanation.decision,
    factors: [...factors, ...policyResult.explanation.factors.map(f => ({ source: 'policy', ...f }))],
    policyResult,
  }
}

/**
 * Create a trust context from raw inputs.
 * Helper for building GuardRequest objects.
 */
export function createTrustContext(input: {
  reputationScore: number
  capabilityScore?: number
  attestation?: RuntimeAttestation | null
  evidenceChain?: EvidenceChain | null
  killSwitchEngaged: boolean
  recentIncidents: number
  agentRevoked?: boolean
  sessionRevoked?: boolean
  revocationReason?: string
  capabilityHighRisk?: boolean
  requiresRuntimeAttestation?: boolean
  requiresApproval?: boolean
  approvalGranted?: boolean
}): TrustContext {
  return {
    reputationScore: input.reputationScore,
    capabilityScore: input.capabilityScore,
    attestationValid: input.attestation !== null && input.attestation !== undefined,
    attestation: input.attestation ?? undefined,
    evidenceChain: input.evidenceChain ?? undefined,
    killSwitchEngaged: input.killSwitchEngaged,
    agentRevoked: input.agentRevoked ?? false,
    sessionRevoked: input.sessionRevoked ?? false,
    revocationReason: input.revocationReason,
    capabilityHighRisk: input.capabilityHighRisk ?? false,
    requiresRuntimeAttestation: input.requiresRuntimeAttestation ?? false,
    requiresApproval: input.requiresApproval ?? false,
    approvalGranted: input.approvalGranted ?? false,
    recentIncidents: input.recentIncidents,
  }
}
