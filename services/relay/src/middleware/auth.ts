import { timingSafeStringEqual } from '@fides/shared'
import type { MiddlewareHandler } from 'hono'

export const apiKeyAuth = (): MiddlewareHandler => {
  return async (c, next) => {
    const apiKey = process.env.SERVICE_API_KEY
    if (!apiKey) {
      if (process.env.NODE_ENV === 'production') {
        return c.json({ error: 'SERVICE_API_KEY is required in production for mutating endpoints' }, 503)
      }
      return next()
    }

    const providedKey = c.req.header('X-API-Key')
    if (!providedKey || !timingSafeStringEqual(providedKey, apiKey)) {
      return c.json({ error: 'Unauthorized — invalid or missing API key' }, 401)
    }

    return next()
  }
}
