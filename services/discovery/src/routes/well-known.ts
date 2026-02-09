import { Hono } from 'hono'
import { ALGORITHM, type DiscoveryDocument } from '@fides/shared'

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

export default wellKnown
