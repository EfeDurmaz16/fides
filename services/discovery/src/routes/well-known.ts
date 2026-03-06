import { Hono } from 'hono'
import { eq } from 'drizzle-orm'
import { ALGORITHM, type DiscoveryDocument, type A2AAgentCard } from '@fides/shared'
import { db } from '../db/client.js'
import { agents, identities } from '../db/schema.js'

const wellKnown = new Hono()

wellKnown.get('/fides.json', (c) => {
  const discoveryDoc: DiscoveryDocument = {
    did: process.env.SERVICE_DID || 'did:fides:discovery',
    publicKey: process.env.SERVICE_PUBLIC_KEY || '',
    algorithm: ALGORITHM,
    endpoints: {
      discovery: process.env.DISCOVERY_ENDPOINT || 'http://localhost:3100',
      trust: process.env.TRUST_ENDPOINT,
    },
    createdAt: new Date().toISOString(),
  }

  return c.json(discoveryDoc)
})

// GET /.well-known/agent.json - A2A-compatible Agent Card
// Returns the service's own agent card or a specific agent's card via ?did= query
wellKnown.get('/agent.json', async (c) => {
  const did = c.req.query('did') || process.env.SERVICE_DID

  if (!did) {
    return c.json({ error: 'No agent DID configured' }, 404)
  }

  try {
    const results = await db
      .select()
      .from(agents)
      .innerJoin(identities, eq(agents.did, identities.did))
      .where(eq(agents.did, did))

    if (results.length === 0) {
      return c.json({ error: 'Agent not found' }, 404)
    }

    const { agents: agent, identities: identity } = results[0]

    const a2aCard: A2AAgentCard = {
      id: agent.did,
      name: agent.name,
      description: agent.description || undefined,
      url: agent.url,
      version: agent.version,
      provider: agent.provider || undefined,
      capabilities: (agent.capabilities as Record<string, boolean>) || undefined,
      skills: (agent.skills as A2AAgentCard['skills']) || undefined,
      defaultInputModes: (agent.defaultInputModes as string[]) || undefined,
      defaultOutputModes: (agent.defaultOutputModes as string[]) || undefined,
      securitySchemes: {
        'fides-signature': {
          type: 'http',
          scheme: 'signature',
          description: 'FIDES Ed25519 HTTP Message Signatures (RFC 9421)',
        },
      },
      security: ['fides-signature'],
      'x-fides-did': agent.did,
      'x-fides-publicKey': identity.publicKey,
      'x-fides-algorithm': ALGORITHM,
      'x-fides-trust-endpoint': process.env.TRUST_ENDPOINT,
    }

    c.header('Cache-Control', 'public, max-age=300')
    return c.json(a2aCard)
  } catch (error) {
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default wellKnown
