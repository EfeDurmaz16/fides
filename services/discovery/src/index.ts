import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { cors } from 'hono/cors'
import { bodyLimit } from 'hono/body-limit'
import { rateLimitMiddleware, MetricsCollector, metricsMiddleware } from '@fides/sdk'
import healthRouter from './routes/health.js'
import identitiesRouter from './routes/identities.js'
import wellKnownRouter from './routes/well-known.js'
import { logger } from './middleware/logger.js'
import { securityHeaders } from './middleware/security.js'
import { errorHandler } from './middleware/error-handler.js'
import { sql } from './db/client.js'

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

// Register routes
app.route('/health', healthRouter)
app.route('/identities', identitiesRouter)
app.route('/.well-known', wellKnownRouter)

// Export app for testing
export { app }

// Start server only when not imported as module
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.DISCOVERY_PORT || process.env.PORT || '3100', 10)

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

  console.log(`Discovery service starting on port ${port}`)

  const server = serve({
    fetch: wrappedFetch,
    port,
  })

  // Graceful shutdown with in-flight drain
  const shutdown = async () => {
    if (isShuttingDown) return
    isShuttingDown = true
    console.log('Shutting down discovery service...')

    // Wait up to 10s for in-flight requests to drain
    const deadline = Date.now() + 10_000
    while (inFlightRequests > 0 && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 100))
    }

    if (inFlightRequests > 0) {
      console.warn(`Force closing with ${inFlightRequests} in-flight requests`)
    }

    server.close()
    await sql.end()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}
