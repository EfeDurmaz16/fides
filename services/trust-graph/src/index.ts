import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { cors } from 'hono/cors'
import { bodyLimit } from 'hono/body-limit'
import { rateLimitMiddleware, MetricsCollector, metricsMiddleware } from '@fides/sdk'
import { createDbClient, createRawClient } from './db/client.js'
import { logger } from './middleware/logger.js'
import { securityHeaders } from './middleware/security.js'
import { errorHandler } from './middleware/error-handler.js'
import { createHealthRoutes } from './routes/health.js'
import { createTrustRoutes } from './routes/trust.js'
import { createIdentitiesRoutes } from './routes/identities.js'

function getCorsOrigin(): string {
  const corsOrigin = process.env.CORS_ORIGIN
  if (process.env.NODE_ENV === 'production') {
    if (!corsOrigin) {
      console.warn('CORS_ORIGIN not set in production — using restrictive default')
    }
    return corsOrigin || 'https://localhost'
  }
  return corsOrigin || '*'
}

export function createApp(db: ReturnType<typeof createDbClient>, discoveryUrl?: string) {
  const app = new Hono()
  const collector = new MetricsCollector()

  // Global middleware — metrics first for accurate timing
  app.use('*', metricsMiddleware(collector))
  app.use('*', logger())
  app.use('*', securityHeaders())
  app.use('*', cors({
    origin: getCorsOrigin(),
    exposeHeaders: ['Signature', 'Signature-Input', 'X-Request-Id'],
  }))
  // Rate limiting: writes 100/min, reads 300/min
  app.post('*', rateLimitMiddleware({ maxRequests: 100, windowMs: 60_000 }))
  app.get('*', rateLimitMiddleware({ maxRequests: 300, windowMs: 60_000 }))
  app.use('*', bodyLimit({ maxSize: 1024 * 1024 })) // 1MB

  // Global error handler
  app.onError(errorHandler)

  // Metrics endpoint
  app.get('/metrics', (c) => {
    return c.text(collector.toPrometheus(), 200, { 'Content-Type': 'text/plain; version=0.0.4' })
  })

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

  // In-flight request tracking for graceful shutdown
  let inFlightRequests = 0
  let isShuttingDown = false

  const originalFetch = app.fetch
  const wrappedFetch: typeof originalFetch = async (req, ...args) => {
    if (isShuttingDown) {
      return new Response(JSON.stringify({ error: 'Service shutting down' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    inFlightRequests++
    try {
      return await originalFetch.call(app, req, ...args)
    } finally {
      inFlightRequests--
    }
  }

  console.log(`Trust Graph Service starting on port ${port}...`)
  const server = serve({
    fetch: wrappedFetch,
    port,
  })

  // Graceful shutdown with in-flight drain
  const shutdown = async () => {
    if (isShuttingDown) return
    isShuttingDown = true
    console.log('Shutting down trust-graph service...')

    // Wait up to 10s for in-flight requests to drain
    const deadline = Date.now() + 10_000
    while (inFlightRequests > 0 && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 100))
    }

    if (inFlightRequests > 0) {
      console.warn(`Force closing with ${inFlightRequests} in-flight requests`)
    }

    server.close()
    await rawSql.end()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}
