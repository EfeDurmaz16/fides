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
