/**
 * Hono middleware wrapper for content validation
 *
 * Usage: import and use with Hono apps that have @fides/sdk as a dependency
 */
import { validateRequestContent } from './content-validator.js'

export function contentValidationMiddleware() {
  return async (c: any, next: () => Promise<void>) => {
    const method = c.req.method
    if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
      try {
        const body = await c.req.text()
        const result = validateRequestContent(body)

        if (!result.safe) {
          const criticalThreats = result.threats.filter((t: any) => t.severity === 'critical')
          if (criticalThreats.length > 0) {
            return c.json(
              {
                error: 'Request blocked: potentially malicious content detected',
                threats: criticalThreats.map((t: any) => ({
                  type: t.type,
                  description: t.description,
                })),
              },
              400
            )
          }
        }
      } catch {
        // If we can't read the body, let it through for the route handler to deal with
      }
    }

    await next()
  }
}
