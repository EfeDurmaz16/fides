import { Hono } from 'hono'
import { eq } from 'drizzle-orm'
import type { DbClient } from '../db/client.js'
import { identities } from '../db/schema.js'

export function createIdentitiesRoutes(db: DbClient) {
  const app = new Hono()

  // Get identity by DID
  app.get('/v1/identities/:did', async (c) => {
    try {
      const did = c.req.param('did')
      const result = await db
        .select()
        .from(identities)
        .where(eq(identities.did, did))
        .limit(1)

      if (result.length === 0) {
        return c.json({ error: 'Identity not found' }, 404)
      }

      const identity = result[0]
      return c.json({
        did: identity.did,
        publicKey: identity.publicKey.toString('hex'),
        metadata: identity.metadata,
        firstSeen: identity.firstSeen.toISOString(),
        lastSeen: identity.lastSeen.toISOString(),
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      return c.json({ error: message }, 500)
    }
  })

  return app
}
