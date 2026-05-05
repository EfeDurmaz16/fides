import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTrustRoutes } from '../src/routes/trust.js'
import { createIdentitiesRoutes } from '../src/routes/identities.js'
import { createHealthRoutes } from '../src/routes/health.js'

describe('HTTP Routes', () => {
  let mockDb: any

  beforeEach(() => {
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
              // First call: cache check (empty = cache miss)
              return {
                limit: vi.fn(() => Promise.resolve([])),
              }
            }
            // Second call: edges query (no limit, returns array directly)
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
      const res = await app.request('/v1/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          did: 'did:fides:agent',
          reason: 'principal revoked authority',
          revokedBy: 'did:fides:principal',
        }),
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
      expect(json.error).toContain('did, reason, and revokedBy')
    })

    it('POST /v1/incidents should accept agentd incident payloads', async () => {
      const app = createTrustRoutes(mockDb)
      const res = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: 'did:fides:agent',
          type: 'policy_violation',
          severity: 'high',
          description: 'agentd propagated incident',
          evidenceRefs: ['event-1'],
          impact: {
            trustPenalty: 0.35,
            reputationPenalty: 0.7,
            capabilitiesRevoked: ['payments.execute'],
          },
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
      expect(json.error).toContain('actorDid, type, severity, and description')
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
