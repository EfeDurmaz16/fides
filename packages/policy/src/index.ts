import { hashProtocolPayload, type CapabilityControl, type CapabilityDescriptor, type HashValue, type TrustResult } from '@fides/core'

/**
 * FIDES v2 Policy Engine
 *
 * Ported from OAPS @oaps/policy with Sardis-inspired pre-execution pipeline.
 */

export interface PolicyExpression {
  operator: 'eq' | 'neq' | 'lt' | 'lte' | 'gt' | 'gte' | 'in' | 'all' | 'any'
  field: string
  value: unknown
}

export interface PolicyRule {
  id: string
  condition: PolicyExpression
  action: 'allow' | 'deny' | 'approve-required' | 'dry-run'
  explanation: string
}

export interface PolicyBundle {
  id: string
  version: string
  rules: PolicyRule[]
  defaultAction: 'allow' | 'deny' | 'approve-required'
}

export interface PolicyContext {
  [field: string]: unknown
}

export interface DecisionExplanation {
  decision: string
  factors: { factor: string; weight: number; description: string }[]
}

export interface PolicyResult {
  decision: 'allow' | 'deny' | 'approve-required' | 'dry-run'
  explanation: DecisionExplanation
  matchedRules: string[]
}

export type FidesPolicyDecisionAction =
  | 'allow'
  | 'deny'
  | 'require_approval'
  | 'dry_run_only'
  | 'scope_limit'
  | 'risk_limit'

export interface PolicyReason {
  code: string
  severity: 'info' | 'warning' | 'error'
  message: string
  evidence_refs: string[]
}

export interface FidesPolicyDecision {
  schema_version: 'fides.policy.decision.v1'
  id: string
  issuer: string
  subject: string
  decision: FidesPolicyDecisionAction
  principal_id: string
  requester_agent_id: string
  target_agent_id: string
  capability: string
  reason_codes: string[]
  machine_reasons: PolicyReason[]
  human_reasons: string[]
  required_controls: CapabilityControl[]
  evidence_refs: string[]
  issued_at: string
  evaluated_at: string
  payload_hash: HashValue
}

export interface FidesPolicyEvaluationInput {
  issuerId?: string
  decisionId?: string
  principalId: string
  requesterAgentId: string
  targetAgentId: string
  capability: CapabilityDescriptor
  trustResult: TrustResult
  requestedScopes?: string[]
  runtimeAttestationValid?: boolean
  revocationActive?: boolean
  killSwitchActive?: boolean
  incidentsActive?: boolean
  approvalGranted?: boolean
  evidenceRefs?: string[]
  evaluatedAt?: string
}

function evaluateExpression(expr: PolicyExpression, context: PolicyContext): boolean {
  const fieldValue = context[expr.field]
  switch (expr.operator) {
    case 'eq': return fieldValue === expr.value
    case 'neq': return fieldValue !== expr.value
    case 'lt': return (fieldValue as number) < (expr.value as number)
    case 'lte': return (fieldValue as number) <= (expr.value as number)
    case 'gt': return (fieldValue as number) > (expr.value as number)
    case 'gte': return (fieldValue as number) >= (expr.value as number)
    case 'in': return Array.isArray(expr.value) && expr.value.includes(fieldValue)
    case 'all': return Array.isArray(fieldValue) && Array.isArray(expr.value) && (expr.value as unknown[]).every(v => (fieldValue as unknown[]).includes(v))
    case 'any': return Array.isArray(fieldValue) && Array.isArray(expr.value) && (expr.value as unknown[]).some(v => (fieldValue as unknown[]).includes(v))
    default: return false
  }
}

export function evaluatePolicy(bundle: PolicyBundle, context: PolicyContext): PolicyResult {
  const matchedRules: string[] = []
  const factors: DecisionExplanation['factors'] = []

  for (const rule of bundle.rules) {
    if (evaluateExpression(rule.condition, context)) {
      matchedRules.push(rule.id)
      factors.push({
        factor: rule.id,
        weight: 1.0,
        description: rule.explanation,
      })
      if (rule.action === 'deny') {
        return {
          decision: 'deny',
          explanation: { decision: `Denied by rule ${rule.id}`, factors },
          matchedRules,
        }
      }
      if (rule.action === 'approve-required' || rule.action === 'dry-run') {
        return {
          decision: rule.action,
          explanation: { decision: `Rule ${rule.id} requires approval / dry-run`, factors },
          matchedRules,
        }
      }
    }
  }

  if (matchedRules.length > 0) {
    return {
      decision: 'allow',
      explanation: { decision: 'Allowed by matched rules', factors },
      matchedRules,
    }
  }

  return {
    decision: bundle.defaultAction,
    explanation: { decision: `Default action: ${bundle.defaultAction}`, factors: [] },
    matchedRules: [],
  }
}

function createDecision(
  input: FidesPolicyEvaluationInput,
  decision: FidesPolicyDecisionAction,
  reasons: PolicyReason[],
  requiredControls: CapabilityControl[] = []
): FidesPolicyDecision {
  const evaluatedAt = input.evaluatedAt ?? new Date().toISOString()
  const evidenceRefs = Array.from(new Set([
    ...(input.evidenceRefs ?? []),
    ...input.trustResult.evidence_refs,
    ...reasons.flatMap(reason => reason.evidence_refs),
  ]))

  const payload = {
    schema_version: 'fides.policy.decision.v1',
    id: input.decisionId ?? crypto.randomUUID(),
    issuer: input.issuerId ?? input.requesterAgentId,
    subject: input.targetAgentId,
    decision,
    principal_id: input.principalId,
    requester_agent_id: input.requesterAgentId,
    target_agent_id: input.targetAgentId,
    capability: input.capability.id,
    reason_codes: reasons.map(reason => reason.code),
    machine_reasons: reasons,
    human_reasons: reasons.map(reason => reason.message),
    required_controls: Array.from(new Set(requiredControls)),
    evidence_refs: evidenceRefs,
    issued_at: evaluatedAt,
    evaluated_at: evaluatedAt,
  } satisfies Omit<FidesPolicyDecision, 'payload_hash'>

  return {
    ...payload,
    payload_hash: hashProtocolPayload(payload),
  }
}

function reason(code: string, severity: PolicyReason['severity'], message: string, evidenceRefs: string[] = []): PolicyReason {
  return {
    code,
    severity,
    message,
    evidence_refs: evidenceRefs,
  }
}

function missingScopes(requiredScopes: string[], requestedScopes: string[]): string[] {
  return requiredScopes.filter(scope => !requestedScopes.includes(scope))
}

export function evaluateFidesPolicy(input: FidesPolicyEvaluationInput): FidesPolicyDecision {
  if (input.killSwitchActive) {
    return createDecision(input, 'deny', [
      reason('KILL_SWITCH_ACTIVE', 'error', 'A kill switch rule is active for this request.'),
    ])
  }

  if (input.revocationActive) {
    return createDecision(input, 'deny', [
      reason('REVOCATION_ACTIVE', 'error', 'An active revocation record blocks this request.'),
    ])
  }

  if (input.incidentsActive) {
    return createDecision(input, 'deny', [
      reason('INCIDENT_REQUIRES_REVIEW', 'error', 'An active incident requires review before execution.'),
    ], ['human_approval'])
  }

  const requestedScopes = input.requestedScopes ?? []
  const requiredScopes = input.capability.requiredScopes ?? []
  const missing = missingScopes(requiredScopes, requestedScopes)
  if (missing.length > 0) {
    return createDecision(input, 'scope_limit', [
      reason('SESSION_SCOPE_INVALID', 'error', `Missing required scopes: ${missing.join(', ')}.`),
    ], ['scope_limit'])
  }

  if (input.trustResult.band === 'unknown') {
    return createDecision(input, 'dry_run_only', [
      reason('TRUST_UNKNOWN_DRY_RUN_ONLY', 'warning', 'Unknown agents can be discovered but only dry-run authority is available.'),
    ], ['dry_run'])
  }

  if (input.trustResult.band === 'low') {
    return createDecision(input, 'risk_limit', [
      reason('TRUST_BELOW_THRESHOLD', 'error', 'Trust is below the threshold for execution.'),
    ], ['scope_limit'])
  }

  const highRisk = input.capability.riskLevel === 'high' || input.capability.riskLevel === 'critical'
  if (highRisk && !input.runtimeAttestationValid && !input.approvalGranted) {
    return createDecision(input, 'require_approval', [
      reason('HIGH_RISK_REQUIRES_ATTESTATION_OR_APPROVAL', 'warning', 'High-risk capabilities require valid runtime attestation or explicit approval.'),
    ], ['runtime_attestation', 'human_approval'])
  }

  if (input.capability.riskLevel === 'critical' && !input.approvalGranted) {
    return createDecision(input, 'require_approval', [
      reason('CRITICAL_CAPABILITY_REQUIRES_APPROVAL', 'warning', 'Critical capabilities require explicit approval before execution.'),
    ], ['human_approval'])
  }

  return createDecision(input, 'allow', [
    reason('POLICY_ALLOWED', 'info', 'Policy allowed the request for this capability and scope.', input.trustResult.evidence_refs),
  ])
}

/**
 * Pre-execution pipeline with Allow / Warn / Block guards.
 * Ported from Sardis pattern.
 */
export type GuardDecision = 'allow' | 'warn' | 'block'

export interface Guard {
  name: string
  evaluate(context: PolicyContext): GuardDecision | Promise<GuardDecision>
}

export async function runPreExecutionPipeline(
  guards: Guard[],
  context: PolicyContext
): Promise<{ decision: GuardDecision; blockingGuard?: string; warnings: string[] }> {
  const warnings: string[] = []
  for (const guard of guards) {
    const decision = await guard.evaluate(context)
    if (decision === 'block') {
      return { decision: 'block', blockingGuard: guard.name, warnings }
    }
    if (decision === 'warn') {
      warnings.push(guard.name)
    }
  }
  return { decision: warnings.length > 0 ? 'warn' : 'allow', warnings }
}
