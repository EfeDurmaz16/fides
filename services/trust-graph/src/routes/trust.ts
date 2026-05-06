import { Hono } from 'hono'
import type { DbClient } from '../db/client.js'
import { TrustService } from '../services/trust-service.js'
import type { CreateTrustRequest } from '../types.js'
import { apiKeyAuth, TRUST_GRAPH_API_SCOPES } from '../middleware/auth.js'

export function createTrustRoutes(db: DbClient, discoveryUrl?: string) {
  const app = new Hono()
  const trustService = new TrustService(discoveryUrl)

  // Create trust edge
  app.post('/v1/trust', apiKeyAuth(TRUST_GRAPH_API_SCOPES.edgesWrite), async (c) => {
    try {
      const body = await c.req.json() as CreateTrustRequest
      const id = await trustService.createTrust(db, body)
      c.header('Cache-Control', 'no-store')
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
      c.header('Cache-Control', 'public, max-age=300')
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
      c.header('Cache-Control', 'public, max-age=60')
      return c.json(path)
    } catch (error) {
      return c.json({ error: 'Internal server error' }, 500)
    }
  })

  // Get capability-specific score
  app.get('/v1/trust/:did/capability/:capabilityId', async (c) => {
    try {
      const did = c.req.param('did')
      const capabilityId = c.req.param('capabilityId')
      const score = await trustService.getCapabilityScore(db, did, decodeURIComponent(capabilityId))
      c.header('Cache-Control', 'public, max-age=300')
      return c.json(score)
    } catch (error) {
      return c.json({ error: 'Internal server error' }, 500)
    }
  })

  // Record capability invocation
  app.post('/v1/trust/:did/capability/:capabilityId/invoke', apiKeyAuth(TRUST_GRAPH_API_SCOPES.capabilityInvoke), async (c) => {
    try {
      const did = c.req.param('did')
      const capabilityId = c.req.param('capabilityId')
      await trustService.recordCapabilityInvocation(db, did, decodeURIComponent(capabilityId))
      return c.json({ ok: true }, 201)
    } catch (error) {
      return c.json({ error: 'Internal server error' }, 500)
    }
  })

  // Record incident
  app.post('/v1/incidents', apiKeyAuth(TRUST_GRAPH_API_SCOPES.incidentsWrite), async (c) => {
    try {
      const body = await c.req.json()
      const id = await trustService.recordIncident(db, body)
      return c.json({ id }, 201)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      return c.json({ error: message }, 400)
    }
  })

  // Record authority revocation and mark active trust edges revoked
  app.post('/v1/revocations', apiKeyAuth(TRUST_GRAPH_API_SCOPES.revocationsWrite), async (c) => {
    try {
      const body = await c.req.json()
      const result = await trustService.recordRevocation(db, body)
      return c.json(result, 201)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      return c.json({ error: message }, 400)
    }
  })

  // Get latest authority revocation for a DID
  app.get('/v1/revocations/:did', async (c) => {
    try {
      const did = c.req.param('did')
      const record = await trustService.getRevocation(db, did)
      if (!record) {
        return c.json({ did, revoked: false })
      }
      c.header('Cache-Control', 'no-store')
      return c.json({ did, revoked: true, record })
    } catch (error) {
      return c.json({ error: 'Internal server error' }, 500)
    }
  })

  // Get incidents for a DID
  app.get('/v1/incidents/:did', async (c) => {
    try {
      const did = c.req.param('did')
      const incidents = await trustService.getIncidents(db, did)
      return c.json({ incidents })
    } catch (error) {
      return c.json({ error: 'Internal server error' }, 500)
    }
  })

  return app
}
