import type { MiddlewareHandler } from 'hono'

export const logger = (): MiddlewareHandler => {
  return async (c, next) => {
    const start = Date.now()
    const method = c.req.method
    const path = c.req.path
    const requestId = c.req.header('x-request-id') || crypto.randomUUID()

    c.header('X-Request-Id', requestId)

    await next()

    const duration = Date.now() - start
    const status = c.res.status

    const logEntry = JSON.stringify({
      timestamp: new Date().toISOString(),
      level: status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info',
      service: 'discovery',
      requestId,
      method,
      path,
      status,
      duration,
    })

    console.log(logEntry)
  }
}
