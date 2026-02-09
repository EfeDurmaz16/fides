import { Hono } from 'hono'
import { eq } from 'drizzle-orm'
import { db } from '../db/client.js'
import { identities } from '../db/schema.js'
import { DiscoveryError, DID_PREFIX, ED25519_PUBLIC_KEY_LENGTH } from '@fides/shared'
import type { RegisterIdentityRequest, IdentityResponse } from '../types.js'
import bs58 from 'bs58'

const identitiesRouter = new Hono()

// POST /identities - Register a new identity
identitiesRouter.post('/', async (c) => {
  try {
    const body = await c.req.json<RegisterIdentityRequest>()

    // Validate required fields
    if (!body.did || !body.publicKey) {
      return c.json({ error: 'Missing required fields: did, publicKey' }, 400)
    }

    // Validate DID format (basic check - could import isValidDID but keeping minimal)
    if (!body.did.startsWith(DID_PREFIX)) {
      return c.json({ error: `Invalid DID format. Must start with ${DID_PREFIX}` }, 400)
    }

    // Validate DID contains base58 characters after prefix
    const didSuffix = body.did.slice(DID_PREFIX.length)
    if (!/^[1-9A-HJ-NP-Za-km-z]+$/.test(didSuffix) || didSuffix.length === 0) {
      return c.json({ error: 'Invalid DID format. Must contain valid base58 encoding' }, 400)
    }

    // Validate public key is hex-encoded
    if (!/^[0-9a-fA-F]+$/.test(body.publicKey)) {
      return c.json({ error: 'Public key must be hex-encoded' }, 400)
    }

    // Validate public key length (32 bytes = 64 hex chars)
    if (body.publicKey.length !== ED25519_PUBLIC_KEY_LENGTH * 2) {
      return c.json({ error: `Public key must be ${ED25519_PUBLIC_KEY_LENGTH * 2} hex characters (${ED25519_PUBLIC_KEY_LENGTH} bytes)` }, 400)
    }

    // Verify DID matches public key (prevent identity hijacking)
    try {
      const didPubKeyBytes = bs58.decode(didSuffix)
      const didPubKeyHex = Buffer.from(didPubKeyBytes).toString('hex')
      if (didPubKeyHex !== body.publicKey.toLowerCase()) {
        return c.json({ error: 'DID does not match provided public key' }, 403)
      }
    } catch {
      return c.json({ error: 'Invalid DID encoding' }, 400)
    }

    // Insert identity into database
    const [identity] = await db.insert(identities).values({
      did: body.did,
      publicKey: body.publicKey,
      metadata: body.metadata || {},
      domain: body.domain || null,
      createdAt: new Date(),
      updatedAt: new Date(),
    }).returning()

    const response: IdentityResponse = {
      did: identity.did,
      publicKey: identity.publicKey,
      metadata: identity.metadata as Record<string, unknown>,
      domain: identity.domain,
      createdAt: identity.createdAt.toISOString(),
      updatedAt: identity.updatedAt.toISOString(),
    }

    return c.json(response, 201)
  } catch (error) {
    if (error instanceof Error) {
      // Handle duplicate key error
      if (error.message.includes('duplicate key')) {
        return c.json({ error: 'Identity already exists' }, 409)
      }
      return c.json({ error: 'Internal server error' }, 500)
    }
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /identities/:did - Get identity by DID
identitiesRouter.get('/:did', async (c) => {
  try {
    const did = c.req.param('did')

    const [identity] = await db.select().from(identities).where(eq(identities.did, did))

    if (!identity) {
      return c.json({ error: 'Identity not found' }, 404)
    }

    const response: IdentityResponse = {
      did: identity.did,
      publicKey: identity.publicKey,
      metadata: identity.metadata as Record<string, unknown>,
      domain: identity.domain,
      createdAt: identity.createdAt.toISOString(),
      updatedAt: identity.updatedAt.toISOString(),
    }

    return c.json(response)
  } catch (error) {
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /identities?domain=X - Lookup by domain
identitiesRouter.get('/', async (c) => {
  try {
    const domain = c.req.query('domain')

    if (!domain) {
      return c.json({ error: 'Domain query parameter is required' }, 400)
    }

    const results = await db.select().from(identities).where(eq(identities.domain, domain))

    const response: IdentityResponse[] = results.map(identity => ({
      did: identity.did,
      publicKey: identity.publicKey,
      metadata: identity.metadata as Record<string, unknown>,
      domain: identity.domain,
      createdAt: identity.createdAt.toISOString(),
      updatedAt: identity.updatedAt.toISOString(),
    }))

    return c.json(response)
  } catch (error) {
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default identitiesRouter
