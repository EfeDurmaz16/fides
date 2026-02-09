import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { cors } from 'hono/cors'
import { bodyLimit } from 'hono/body-limit'
import { createDbClient, createRawClient } from './db/client.js'
import { logger } from './middleware/logger.js'
import { securityHeaders } from './middleware/security.js'
import { errorHandler } from './middleware/error-handler.js'
import { createHealthRoutes } from './routes/health.js'
import { createTrustRoutes } from './routes/trust.js'
import { createIdentitiesRoutes } from './routes/identities.js'

export function createApp(db: ReturnType<typeof createDbClient>, discoveryUrl?: string) {
  const app = new Hono()

  // Global middleware
  app.use('*', logger())
  app.use('*', securityHeaders())
  app.use('*', cors({
    origin: process.env.CORS_ORIGIN || '*',
    exposeHeaders: ['Signature', 'Signature-Input', 'X-Request-Id'],
  }))
  app.use('*', bodyLimit({ maxSize: 1024 * 1024 })) // 1MB

  // Global error handler
  app.onError(errorHandler)

  // Routes
  app.route('/', createHealthRoutes())
  app.route('/', createTrustRoutes(db, discoveryUrl))
  app.route('/', createIdentitiesRoutes(db))

  return app
}

// Start server if running directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const db = createDbClient()
  const rawSql = createRawClient()
  const port = parseInt(process.env.TRUST_GRAPH_PORT || process.env.PORT || '3200', 10)
  const discoveryUrl = process.env.DISCOVERY_URL || 'http://localhost:3100'
  const app = createApp(db, discoveryUrl)

  console.log(`Trust Graph Service starting on port ${port}...`)
  const server = serve({
    fetch: app.fetch,
    port,
  })

  // Graceful shutdown
  const shutdown = async () => {
    console.log('Shutting down trust-graph service...')
    server.close()
    await rawSql.end()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}
