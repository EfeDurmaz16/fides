import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTrustRoutes } from '../src/routes/trust.js'
import { createIdentitiesRoutes } from '../src/routes/identities.js'
import { createHealthRoutes } from '../src/routes/health.js'
import {
  createIncidentRecord,
  createRevocationRecord,
  signIncidentRecord,
  signRevocationRecord,
} from '@fides/core'
import * as ed from '@noble/ed25519'

const ORIGINAL_SERVICE_API_KEY = process.env.SERVICE_API_KEY
const ORIGINAL_TRUST_GRAPH_API_KEYS = process.env.TRUST_GRAPH_API_KEYS
const ORIGINAL_NODE_ENV = process.env.NODE_ENV

describe('HTTP Routes', () => {
  let mockDb: any

  beforeEach(() => {
    delete process.env.SERVICE_API_KEY
    delete process.env.TRUST_GRAPH_API_KEYS
    process.env.NODE_ENV = 'test'

    // Create mock database
    mockDb = {
      insert: vi.fn(() => ({
        values: vi.fn(() => ({
          returning: vi.fn(() => Promise.resolve([{ id: 'test-uuid-123' }])),
          onConflictDoUpdate: vi.fn(() => Promise.resolve()),
        })),
      })),
      select: vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            limit: vi.fn(() => Promise.resolve([])),
          })),
        })),
      })),
      update: vi.fn(() => ({
        set: vi.fn(() => ({
          where: vi.fn(() => Promise.resolve()),
        })),
      })),
    }
  })

  afterEach(() => {
    restoreEnv('SERVICE_API_KEY', ORIGINAL_SERVICE_API_KEY)
    restoreEnv('TRUST_GRAPH_API_KEYS', ORIGINAL_TRUST_GRAPH_API_KEYS)
    restoreEnv('NODE_ENV', ORIGINAL_NODE_ENV)
    vi.unstubAllGlobals()
  })

  function mockIdentity(publicKey: Uint8Array) {
    mockDb.select = vi.fn(() => ({
      from: vi.fn(() => ({
        where: vi.fn(() => ({
          limit: vi.fn(() => Promise.resolve([{ publicKey: Buffer.from(publicKey) }])),
        })),
      })),
    }))
  }

  async function signedRevocationRecord() {
    const privateKey = ed.utils.randomPrivateKey()
    const publicKey = await ed.getPublicKeyAsync(privateKey)
    mockIdentity(publicKey)
    return signRevocationRecord(createRevocationRecord({
      did: 'did:fides:agent',
      reason: 'principal revoked authority',
      revokedBy: 'did:fides:principal',
    }), privateKey)
  }

  async function signedIncidentRecord() {
    const privateKey = ed.utils.randomPrivateKey()
    const publicKey = await ed.getPublicKeyAsync(privateKey)
    mockIdentity(publicKey)
    return signIncidentRecord(createIncidentRecord({
      actor: 'did:fides:agent',
      reportedBy: 'did:fides:principal',
      type: 'policy_violation',
      severity: 'high',
      description: 'Unauthorized payment attempt',
    }), privateKey)
  }

  async function signedAgentdIncidentRecord() {
    const privateKey = ed.utils.randomPrivateKey()
    const publicKey = await ed.getPublicKeyAsync(privateKey)
    mockIdentity(publicKey)
    return signIncidentRecord(createIncidentRecord({
      actor: 'did:fides:agent',
      reportedBy: 'did:fides:principal',
      type: 'policy_violation',
      severity: 'high',
      description: 'agentd propagated incident',
      evidenceRefs: ['event-1'],
      trustPenalty: 0.35,
      reputationPenalty: 0.7,
      capabilitiesRevoked: ['payments.execute'],
    }), privateKey)
  }

  describe('Health Routes', () => {
    it('GET /health should return health status', async () => {
      const app = createHealthRoutes()
      const res = await app.request('/health')
      const json = await res.json()

      // Without a real DB, health check returns degraded/503
      expect(json.service).toBe('trust-graph')
      expect(json.timestamp).toBeDefined()
      expect(json.checks).toBeDefined()
    })
  })

  describe('Trust Routes', () => {
    it('requires an API key for trust writes in production', async () => {
      process.env.NODE_ENV = 'production'
      delete process.env.SERVICE_API_KEY

      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/trust', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          issuerDid: 'did:fides:alice',
          subjectDid: 'did:fides:bob',
          trustLevel: 80,
          signature: 'deadbeef',
          payload: '{}',
        }),
      })

      expect(res.status).toBe(503)
      expect((await res.json()).error).toContain('SERVICE_API_KEY is required in production')
    })

    it('enforces scoped trust-graph API keys when configured', async () => {
      process.env.TRUST_GRAPH_API_KEYS = JSON.stringify([
        { key: 'trust-key', scopes: ['trust:edges:write'] },
        { key: 'incident-key', scopes: ['trust:incidents:write'] },
      ])

      const app = createTrustRoutes(mockDb)
      const trustRes = await app.request('/v1/trust', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'incident-key' },
        body: JSON.stringify({
          issuerDid: 'did:fides:alice',
          subjectDid: 'did:fides:bob',
          trustLevel: 80,
          signature: 'deadbeef',
          payload: '{}',
        }),
      })

      expect(trustRes.status).toBe(403)
      expect((await trustRes.json()).error).toContain('trust:edges:write')

      const record = await signedIncidentRecord()
      const incidentRes = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'incident-key' },
        body: JSON.stringify({ actorDid: record.actor, record }),
      })

      expect(incidentRes.status).toBe(201)
    })

    it('fails closed when scoped trust-graph API keys are malformed', async () => {
      process.env.TRUST_GRAPH_API_KEYS = '{bad-json'

      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'incident-key' },
        body: JSON.stringify({ actorDid: 'did:fides:agent' }),
      })

      expect(res.status).toBe(503)
      expect((await res.json()).error).toContain('TRUST_GRAPH_API_KEYS must be a JSON array')
    })

    it('allows capability invocation with the capability invoke scope', async () => {
      process.env.TRUST_GRAPH_API_KEYS = JSON.stringify([
        { key: 'invoke-key', scopes: ['trust:capability:invoke'] },
      ])
      mockIdentity(new Uint8Array(32).fill(1))

      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/trust/did:fides:agent/capability/payments.execute/invoke', {
        method: 'POST',
        headers: { 'X-API-Key': 'invoke-key' },
      })

      expect(res.status).toBe(201)
      expect(await res.json()).toEqual({ ok: true })
    })

    it('returns 404 for capability invocation when identity is absent from discovery', async () => {
      process.env.TRUST_GRAPH_API_KEYS = JSON.stringify([
        { key: 'invoke-key', scopes: ['trust:capability:invoke'] },
      ])
      vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response('not found', { status: 404 }))))

      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            limit: vi.fn(() => Promise.resolve([])),
          })),
        })),
      }))

      const app = createTrustRoutes(mockDb, 'http://discovery.test')
      const res = await app.request('/v1/trust/did:fides:missing/capability/payments.execute/invoke', {
        method: 'POST',
        headers: { 'X-API-Key': 'invoke-key' },
      })

      expect(res.status).toBe(404)
      expect((await res.json()).error).toContain('Identity not found: did:fides:missing')
    })

    it('returns 503 for capability invocation when discovery is unavailable', async () => {
      process.env.TRUST_GRAPH_API_KEYS = JSON.stringify([
        { key: 'invoke-key', scopes: ['trust:capability:invoke'] },
      ])
      vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response('unavailable', { status: 503 }))))

      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            limit: vi.fn(() => Promise.resolve([])),
          })),
        })),
      }))

      const app = createTrustRoutes(mockDb, 'http://discovery.test')
      const res = await app.request('/v1/trust/did:fides:missing/capability/payments.execute/invoke', {
        method: 'POST',
        headers: { 'X-API-Key': 'invoke-key' },
      })

      expect(res.status).toBe(503)
      expect((await res.json()).error).toContain('Discovery service unavailable')
    })

    it('allows revocation writes with the revocations write scope', async () => {
      process.env.TRUST_GRAPH_API_KEYS = JSON.stringify([
        { key: 'revocation-key', scopes: ['trust:revocations:write'] },
      ])

      const app = createTrustRoutes(mockDb)
      const record = await signedRevocationRecord()
      const res = await app.request('/v1/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'revocation-key' },
        body: JSON.stringify({ record }),
      })

      expect(res.status).toBe(201)
      expect(await res.json()).toEqual({ id: 'test-uuid-123', revokedEdges: 0 })
    })

    it('POST /v1/trust should reject missing payload', async () => {
      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/trust', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          issuerDid: 'did:fides:alice',
          subjectDid: 'did:fides:bob',
          trustLevel: 80,
          signature: 'deadbeef',
        }),
      })

      expect(res.status).toBe(400)
      const json = await res.json()
      expect(json.error).toContain('Payload is required')
    })

    it('POST /v1/trust should reject invalid trust level', async () => {
      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/trust', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          issuerDid: 'did:fides:alice',
          subjectDid: 'did:fides:bob',
          trustLevel: 150,
          signature: 'deadbeef',
          payload: '{}',
        }),
      })

      expect(res.status).toBe(400)
      const json = await res.json()
      expect(json.error).toContain('Trust level')
    })

    it('GET /v1/trust/:did/score should return reputation score', async () => {
      let selectCallCount = 0
      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => {
            selectCallCount++
            if (selectCallCount === 1) {
              // First call: identity lookup
              return {
                limit: vi.fn(() => Promise.resolve([{ publicKey: Buffer.from('01'.repeat(32), 'hex') }])),
              }
            }
            if (selectCallCount === 2) {
              // Second call: cache check (empty = cache miss)
              return {
                limit: vi.fn(() => Promise.resolve([])),
              }
            }
            // Third call: edges query (no limit, returns array directly)
            return Promise.resolve([])
          }),
        })),
      }))

      // Mock insert for cache upsert
      mockDb.insert = vi.fn(() => ({
        values: vi.fn(() => ({
          onConflictDoUpdate: vi.fn(() => Promise.resolve()),
        })),
      }))

      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/trust/did:fides:alice/score')

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.score).toBeDefined()
      expect(json.directTrusters).toBeDefined()
      expect(json.transitiveTrusters).toBeDefined()
    })

    it('GET /v1/trust/:did/score should return 404 when identity is absent from discovery', async () => {
      vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response('not found', { status: 404 }))))

      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            limit: vi.fn(() => Promise.resolve([])),
          })),
        })),
      }))

      const app = createTrustRoutes(mockDb, 'http://discovery.test')
      const res = await app.request('/v1/trust/did:fides:missing/score')

      expect(res.status).toBe(404)
      expect((await res.json()).error).toContain('Identity not found: did:fides:missing')
    })

    it('GET /v1/trust/:did/score should return 503 when discovery is unavailable', async () => {
      vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response('unavailable', { status: 503 }))))

      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            limit: vi.fn(() => Promise.resolve([])),
          })),
        })),
      }))

      const app = createTrustRoutes(mockDb, 'http://discovery.test')
      const res = await app.request('/v1/trust/did:fides:missing/score')

      expect(res.status).toBe(503)
      expect((await res.json()).error).toContain('Discovery service unavailable')
    })

    it('GET /v1/trust/:did/capability/:capabilityId should return 404 when identity is absent from discovery', async () => {
      vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response('not found', { status: 404 }))))

      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            limit: vi.fn(() => Promise.resolve([])),
          })),
        })),
      }))

      const app = createTrustRoutes(mockDb, 'http://discovery.test')
      const res = await app.request('/v1/trust/did:fides:missing/capability/payments.execute')

      expect(res.status).toBe(404)
      expect((await res.json()).error).toContain('Identity not found: did:fides:missing')
    })

    it('GET /v1/trust/:from/:to should return trust path', async () => {
      // Mock edges query
      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => Promise.resolve([
            {
              sourceDid: 'did:fides:alice',
              targetDid: 'did:fides:bob',
              trustLevel: 80,
              revokedAt: null,
              expiresAt: null,
            },
          ])),
        })),
      }))

      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/trust/did:fides:alice/did:fides:bob')

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.from).toBe('did:fides:alice')
      expect(json.to).toBe('did:fides:bob')
      expect(json.found).toBe(true)
    })

    it('POST /v1/revocations should record revocation and revoke matching edges', async () => {
      const app = createTrustRoutes(mockDb)
      const record = await signedRevocationRecord()
      const res = await app.request('/v1/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ record }),
      })

      expect(res.status).toBe(201)
      const json = await res.json()
      expect(json.id).toBe('test-uuid-123')
      expect(mockDb.insert).toHaveBeenCalled()
      expect(mockDb.update).toHaveBeenCalled()
    })

    it('POST /v1/revocations should reject invalid payloads', async () => {
      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ did: 'did:fides:agent' }),
      })

      expect(res.status).toBe(400)
      const json = await res.json()
      expect(json.error).toContain('signed revocation record')
    })

    it('GET /v1/revocations/:did should return latest revocation state', async () => {
      const record = await signedRevocationRecord()
      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            orderBy: vi.fn(() => ({
              limit: vi.fn(() => Promise.resolve([{ record }])),
            })),
          })),
        })),
      }))

      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/revocations/did:fides:agent')

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.revoked).toBe(true)
      expect(json.record.did).toBe('did:fides:agent')
    })

    it('GET /v1/revocations/:did should return not revoked when absent', async () => {
      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            orderBy: vi.fn(() => ({
              limit: vi.fn(() => Promise.resolve([])),
            })),
          })),
        })),
      }))

      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/revocations/did:fides:agent')

      expect(res.status).toBe(200)
      expect(await res.json()).toEqual({
        did: 'did:fides:agent',
        revoked: false,
      })
    })

    it('POST /v1/incidents should record signed incidents', async () => {
      const app = createTrustRoutes(mockDb)
      const record = await signedIncidentRecord()
      const res = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ actorDid: record.actor, record }),
      })

      expect(res.status).toBe(201)
      const json = await res.json()
      expect(json.id).toBe('test-uuid-123')
    })

    it('POST /v1/incidents should reject invalid payloads', async () => {
      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ actorDid: 'did:fides:agent' }),
      })

      expect(res.status).toBe(400)
      const json = await res.json()
      expect(json.error).toContain('signed incident record')
    })

    it('POST /v1/incidents should accept agentd incident payloads', async () => {
      const app = createTrustRoutes(mockDb)
      const record = await signedAgentdIncidentRecord()
      const res = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: record.actor,
          reportedBy: record.reportedBy,
          record,
        }),
      })

      expect(res.status).toBe(201)
      const json = await res.json()
      expect(json.id).toBe('test-uuid-123')
      const values = mockDb.insert.mock.results[0].value.values.mock.calls[0][0]
      expect(values.actorDid).toBe('did:fides:agent')
      expect(values.trustPenalty).toBe(0.35)
      expect(values.capabilitiesRevoked).toEqual(['payments.execute'])
    })

    it('POST /v1/incidents should reject invalid payloads', async () => {
      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'policy_violation' }),
      })

      expect(res.status).toBe(400)
      const json = await res.json()
      expect(json.error).toContain('signed incident record')
    })
  })

  describe('Identity Routes', () => {
    it('GET /v1/identities/:did should return identity', async () => {
      // Mock identity lookup
      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            limit: vi.fn(() => Promise.resolve([
              {
                did: 'did:fides:alice',
                publicKey: Buffer.from('deadbeef', 'hex'),
                metadata: { name: 'Alice' },
                firstSeen: new Date('2024-01-01'),
                lastSeen: new Date('2024-01-02'),
              },
            ])),
          })),
        })),
      }))

      const app = createIdentitiesRoutes(mockDb)
      const res = await app.request('/v1/identities/did:fides:alice')

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.did).toBe('did:fides:alice')
      expect(json.publicKey).toBe('deadbeef')
      expect(json.metadata).toEqual({ name: 'Alice' })
    })

    it('GET /v1/identities/:did should return 404 for unknown identity', async () => {
      // Mock empty result
      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            limit: vi.fn(() => Promise.resolve([])),
          })),
        })),
      }))

      const app = createIdentitiesRoutes(mockDb)
      const res = await app.request('/v1/identities/did:fides:unknown')

      expect(res.status).toBe(404)
      const json = await res.json()
      expect(json.error).toBe('Identity not found')
    })
  })
})

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name]
  } else {
    process.env[name] = value
  }
}
