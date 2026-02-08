import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import healthRouter from './routes/health.js'
import identitiesRouter from './routes/identities.js'
import wellKnownRouter from './routes/well-known.js'

const app = new Hono()

// Register routes
app.route('/health', healthRouter)
app.route('/identities', identitiesRouter)
app.route('/.well-known', wellKnownRouter)

// Export app for testing
export { app }

// Start server only when not imported as module
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.PORT || '3001', 10)

  console.log(`Discovery service starting on port ${port}`)

  serve({
    fetch: app.fetch,
    port,
  })
}
