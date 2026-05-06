import { evaluateApiKeyAuth, parseScopedApiKeys } from '@fides/shared'
import type { MiddlewareHandler } from 'hono'

export const TRUST_GRAPH_API_SCOPES = {
  edgesWrite: 'trust:edges:write',
  capabilityInvoke: 'trust:capability:invoke',
  incidentsWrite: 'trust:incidents:write',
  revocationsWrite: 'trust:revocations:write',
} as const

export const apiKeyAuth = (requiredScope: string): MiddlewareHandler => {
  return async (c, next) => {
    const scopedKeys = parseScopedApiKeys(process.env.TRUST_GRAPH_API_KEYS, 'TRUST_GRAPH_API_KEYS')
    if (!scopedKeys.ok) {
      return c.json({ error: scopedKeys.error }, 503)
    }

    const decision = evaluateApiKeyAuth({
      configuredKey: process.env.SERVICE_API_KEY,
      configuredKeys: scopedKeys.value,
      providedKey: c.req.header('X-API-Key'),
      nodeEnv: process.env.NODE_ENV,
      productionRequirement: 'trust-graph writes',
      requiredScope,
    })
    if (!decision.ok) {
      return c.json({ error: decision.error }, decision.status)
    }

    return next()
  }
}
