import { Hono } from 'hono'
import { createRawClient } from '../db/client.js'

const startTime = Date.now()

export function createHealthRoutes() {
  const app = new Hono()

  app.get('/health', async (c) => {
    let dbHealthy = false
    const healthSql = createRawClient()
    try {
      await healthSql`SELECT 1`
      dbHealthy = true
    } catch {
      // DB not reachable
    } finally {
      await healthSql.end()
    }

    const status = dbHealthy ? 'healthy' : 'degraded'
    const statusCode = dbHealthy ? 200 : 503

    return c.json({
      status,
      service: 'trust-graph',
      version: '0.1.0',
      uptime: Math.floor((Date.now() - startTime) / 1000),
      timestamp: new Date().toISOString(),
      checks: {
        database: dbHealthy ? 'connected' : 'disconnected',
      },
    }, statusCode)
  })

  return app
}
