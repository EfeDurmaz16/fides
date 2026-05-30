import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { bodyLimit } from 'hono/body-limit'
import { cors } from 'hono/cors'
import type { MiddlewareHandler } from 'hono'
import { evaluatePolicy, type PolicyBundle, type PolicyContext, type PolicyResult } from '@fides/policy'
import { evaluateApiKeyAuth, MetricsCollector, metricsMiddleware, parseScopedApiKeys } from '@fides/shared'

const app = new Hono()
const startTime = Date.now()
const collector = new MetricsCollector()
const POLICY_ENGINE_API_SCOPES = {
  evaluate: 'policy:evaluate',
} as const

app.use('*', metricsMiddleware(collector))
app.use('*', cors({ origin: getCorsOrigin() }))
app.use('*', bodyLimit({ maxSize: 1024 * 1024 }))

app.get('/health', (c) => c.json({
  status: 'healthy',
  service: 'policy-engine',
  uptime: Math.floor((Date.now() - startTime) / 1000),
  timestamp: new Date().toISOString(),
}))

app.get('/metrics', (c) => {
  return c.text(collector.toPrometheus(), 200, { 'Content-Type': 'text/plain; version=0.0.4' })
})

app.post('/v1/policies/evaluate', apiKeyAuth(), async (c) => {
  const body = await c.req.json().catch(() => null)
  if (!body || typeof body !== 'object') {
    return c.json({ error: 'JSON body is required' }, 400)
  }

  const validation = validatePolicyBundle(body.policy)
  if (!validation.valid) {
    return c.json({ error: 'invalid policy bundle', details: validation.errors }, 400)
  }

  const context: PolicyContext = {
    ...(isRecord(body.context) ? body.context : {}),
    ...(body.agentDid && { agentDid: body.agentDid }),
    ...(body.capabilityId && { capabilityId: body.capabilityId }),
  }

  return c.json(normalizePolicyResult(evaluatePolicy(body.policy as PolicyBundle, context)))
})

app.post('/v1/evaluate', apiKeyAuth(), async (c) => {
  const body = await c.req.json().catch(() => null)
  if (!body || typeof body !== 'object') {
    return c.json({ error: 'JSON body is required' }, 400)
  }

  const validation = validatePolicyBundle(body.policy)
  if (!validation.valid) {
    return c.json({ error: 'invalid policy bundle', details: validation.errors }, 400)
  }

  return c.json(normalizePolicyResult(evaluatePolicy(body.policy as PolicyBundle, isRecord(body.context) ? body.context : {})))
})

export { app }

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.POLICY_ENGINE_PORT || process.env.PORT || '3300', 10)
  console.log(`FIDES policy-engine starting on port ${port}`)
  serve({ fetch: app.fetch, port })
}

function validatePolicyBundle(policy: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  if (!isRecord(policy)) {
    return { valid: false, errors: ['policy must be an object'] }
  }
  if (typeof policy.id !== 'string' || policy.id.length === 0) errors.push('policy.id is required')
  if (typeof policy.version !== 'string' || policy.version.length === 0) errors.push('policy.version is required')
  if (!Array.isArray(policy.rules)) errors.push('policy.rules must be an array')
  if (!['allow', 'deny', 'approve-required'].includes(String(policy.defaultAction))) {
    errors.push('policy.defaultAction must be allow, deny, or approve-required')
  }

  if (Array.isArray(policy.rules)) {
    for (const [index, rule] of policy.rules.entries()) {
      if (!isRecord(rule)) {
        errors.push(`policy.rules[${index}] must be an object`)
        continue
      }
      if (typeof rule.id !== 'string' || rule.id.length === 0) errors.push(`policy.rules[${index}].id is required`)
      if (!['allow', 'deny', 'approve-required', 'dry-run'].includes(String(rule.action))) {
        errors.push(`policy.rules[${index}].action is invalid`)
      }
      if (!isRecord(rule.condition)) {
        errors.push(`policy.rules[${index}].condition must be an object`)
      } else {
        if (typeof rule.condition.field !== 'string' || rule.condition.field.length === 0) {
          errors.push(`policy.rules[${index}].condition.field is required`)
        }
        if (!['eq', 'neq', 'lt', 'lte', 'gt', 'gte', 'in', 'all', 'any'].includes(String(rule.condition.operator))) {
          errors.push(`policy.rules[${index}].condition.operator is invalid`)
        }
      }
    }
  }

  return { valid: errors.length === 0, errors }
}

function getCorsOrigin(): string {
  if (process.env.NODE_ENV === 'production') {
    return process.env.CORS_ORIGIN || 'https://localhost'
  }
  return process.env.CORS_ORIGIN || '*'
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === 'object' && value !== null
}

function normalizePolicyResult(result: PolicyResult) {
  return {
    ...result,
    decision: result.decision === 'approve-required'
      ? 'require_approval'
      : result.decision === 'dry-run'
        ? 'dry_run_only'
        : result.decision,
    legacyDecision: result.decision,
  }
}

function apiKeyAuth(): MiddlewareHandler {
  return async (c, next) => {
    const scopedKeys = parseScopedApiKeys(process.env.POLICY_ENGINE_API_KEYS, 'POLICY_ENGINE_API_KEYS')
    if (!scopedKeys.ok) {
      return c.json({ error: scopedKeys.error }, 503)
    }

    const decision = evaluateApiKeyAuth({
      configuredKey: process.env.SERVICE_API_KEY,
      configuredKeys: scopedKeys.value,
      providedKey: c.req.header('X-API-Key'),
      nodeEnv: process.env.NODE_ENV,
      productionRequirement: 'policy evaluation',
      requiredScope: POLICY_ENGINE_API_SCOPES.evaluate,
    })
    if (!decision.ok) {
      return c.json({ error: decision.error }, decision.status)
    }

    return next()
  }
}
