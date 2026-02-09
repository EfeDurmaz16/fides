import { Hono } from 'hono'
import type { DbClient } from '../db/client.js'
import { TrustService } from '../services/trust-service.js'
import type { CreateTrustRequest } from '../types.js'

export function createTrustRoutes(db: DbClient, discoveryUrl?: string) {
  const app = new Hono()
  const trustService = new TrustService(discoveryUrl)

  // Create trust edge
  app.post('/v1/trust', async (c) => {
    try {
      const body = await c.req.json() as CreateTrustRequest
      const id = await trustService.createTrust(db, body)
      return c.json({ id }, 201)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      return c.json({ error: message }, 400)
    }
  })

  // Get reputation score
  app.get('/v1/trust/:did/score', async (c) => {
    try {
      const did = c.req.param('did')
      const score = await trustService.getScore(db, did)
      return c.json(score)
    } catch (error) {
      return c.json({ error: 'Internal server error' }, 500)
    }
  })

  // Get trust path
  app.get('/v1/trust/:from/:to', async (c) => {
    try {
      const from = c.req.param('from')
      const to = c.req.param('to')
      const path = await trustService.getTrustPath(db, from, to)
      return c.json(path)
    } catch (error) {
      return c.json({ error: 'Internal server error' }, 500)
    }
  })

  return app
}
