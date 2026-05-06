import { evaluateApiKeyAuth } from '@fides/shared'
import type { MiddlewareHandler } from 'hono'

export const apiKeyAuth = (): MiddlewareHandler => {
  return async (c, next) => {
    const decision = evaluateApiKeyAuth({
      configuredKey: process.env.SERVICE_API_KEY,
      providedKey: c.req.header('X-API-Key'),
      nodeEnv: process.env.NODE_ENV,
      productionRequirement: 'mutating endpoints',
    })
    if (!decision.ok) {
      return c.json({ error: decision.error }, decision.status)
    }

    return next()
  }
}
