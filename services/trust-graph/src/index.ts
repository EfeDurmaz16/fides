import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { createDbClient } from './db/client.js'
import { logger } from './middleware/logger.js'
import { createHealthRoutes } from './routes/health.js'
import { createTrustRoutes } from './routes/trust.js'
import { createIdentitiesRoutes } from './routes/identities.js'

export function createApp(db: ReturnType<typeof createDbClient>) {
  const app = new Hono()

  // Middleware
  app.use('*', logger())

  // Routes
  app.route('/', createHealthRoutes())
  app.route('/', createTrustRoutes(db))
  app.route('/', createIdentitiesRoutes(db))

  return app
}

// Start server if running directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const db = createDbClient()
  const app = createApp(db)
  const port = parseInt(process.env.PORT || '3001', 10)

  console.log(`Trust Graph Service starting on port ${port}...`)
  serve({
    fetch: app.fetch,
    port,
  })
}
