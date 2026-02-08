import { Hono } from 'hono'

export function createHealthRoutes() {
  const app = new Hono()

  app.get('/health', (c) => {
    return c.json({
      status: 'healthy',
      service: 'trust-graph',
      timestamp: new Date().toISOString(),
    })
  })

  return app
}
