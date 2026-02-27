/**
 * Hono middleware that records request metrics.
 */
import type { MetricsCollector } from './metrics.js'

export function metricsMiddleware(collector: MetricsCollector) {
  return async (c: any, next: () => Promise<void>) => {
    const start = Date.now()
    collector.incrementConnections()

    try {
      await next()
    } finally {
      const duration = Date.now() - start
      collector.decrementConnections()
      collector.recordRequest(
        c.req.method,
        c.req.path,
        c.res.status,
        duration
      )
    }
  }
}
