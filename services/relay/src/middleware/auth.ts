import type { MiddlewareHandler } from 'hono'

export const apiKeyAuth = (): MiddlewareHandler => {
  return async (c, next) => {
    const apiKey = process.env.SERVICE_API_KEY
    if (!apiKey) {
      return next()
    }

    const providedKey = c.req.header('X-API-Key')
    if (!providedKey || providedKey !== apiKey) {
      return c.json({ error: 'Unauthorized — invalid or missing API key' }, 401)
    }

    return next()
  }
}
