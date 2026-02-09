import { Hono } from 'hono'
import { sql } from '../db/client.js'

const health = new Hono()

const startTime = Date.now()

health.get('/', async (c) => {
  let dbHealthy = false
  try {
    await sql`SELECT 1`
    dbHealthy = true
  } catch {
    // DB not reachable
  }

  const status = dbHealthy ? 'healthy' : 'degraded'
  const statusCode = dbHealthy ? 200 : 503

  return c.json({
    status,
    service: 'discovery',
    version: '0.1.0',
    uptime: Math.floor((Date.now() - startTime) / 1000),
    timestamp: new Date().toISOString(),
    checks: {
      database: dbHealthy ? 'connected' : 'disconnected',
    },
  }, statusCode)
})

export default health
