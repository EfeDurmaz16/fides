import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { cors } from 'hono/cors'
import { bodyLimit } from 'hono/body-limit'
import healthRouter from './routes/health.js'
import identitiesRouter from './routes/identities.js'
import wellKnownRouter from './routes/well-known.js'
import { logger } from './middleware/logger.js'
import { securityHeaders } from './middleware/security.js'
import { errorHandler } from './middleware/error-handler.js'
import { sql } from './db/client.js'

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

// Register routes
app.route('/health', healthRouter)
app.route('/identities', identitiesRouter)
app.route('/.well-known', wellKnownRouter)

// Export app for testing
export { app }

// Start server only when not imported as module
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.DISCOVERY_PORT || process.env.PORT || '3100', 10)

  console.log(`Discovery service starting on port ${port}`)

  const server = serve({
    fetch: app.fetch,
    port,
  })

  // Graceful shutdown
  const shutdown = async () => {
    console.log('Shutting down discovery service...')
    server.close()
    await sql.end()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}
