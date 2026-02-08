import { describe, it, expect, vi, beforeEach } from 'vitest'
import { app } from '../src/index.js'

// Mock the database module
vi.mock('../src/db/client.js', () => {
  const mockDb = {
    insert: vi.fn().mockReturnValue({
      values: vi.fn().mockReturnValue({
        returning: vi.fn().mockResolvedValue([{
          did: 'did:fides:test123',
          publicKey: 'abcdef1234567890',
          metadata: {},
          domain: null,
          createdAt: new Date('2024-01-01T00:00:00.000Z'),
          updatedAt: new Date('2024-01-01T00:00:00.000Z'),
        }]),
      }),
    }),
    select: vi.fn().mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockResolvedValue([{
          did: 'did:fides:test123',
          publicKey: 'abcdef1234567890',
          metadata: {},
          domain: null,
          createdAt: new Date('2024-01-01T00:00:00.000Z'),
          updatedAt: new Date('2024-01-01T00:00:00.000Z'),
        }]),
      }),
    }),
  }

  return {
    db: mockDb,
    sql: {},
  }
})

describe('Discovery Service Routes', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('POST /identities', () => {
    it('should register a new identity and return 201', async () => {
      const req = new Request('http://localhost/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          did: 'did:fides:test123',
          publicKey: 'abcdef1234567890',
          metadata: { name: 'Test Agent' },
        }),
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(201)
      const data = await res.json()
      expect(data).toMatchObject({
        did: 'did:fides:test123',
        publicKey: 'abcdef1234567890',
        metadata: {},
      })
    })

    it('should return 400 for invalid payload', async () => {
      const req = new Request('http://localhost/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          did: 'did:fides:test123',
          // missing publicKey
        }),
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('Missing required fields')
    })

    it('should return 400 for invalid DID format', async () => {
      const req = new Request('http://localhost/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          did: 'invalid:did:format',
          publicKey: 'abcdef1234567890',
        }),
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('Invalid DID format')
    })

    it('should return 400 for non-hex public key', async () => {
      const req = new Request('http://localhost/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          did: 'did:fides:test123',
          publicKey: 'not-hex-zzz',
        }),
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('hex-encoded')
    })
  })

  describe('GET /identities/:did', () => {
    it('should return identity by DID', async () => {
      const req = new Request('http://localhost/identities/did:fides:test123', {
        method: 'GET',
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data).toMatchObject({
        did: 'did:fides:test123',
        publicKey: 'abcdef1234567890',
      })
    })

    it('should return 404 for non-existent DID', async () => {
      // Mock empty result
      const { db } = await import('../src/db/client.js')
      vi.mocked(db.select).mockReturnValueOnce({
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockResolvedValue([]),
        }),
      } as any)

      const req = new Request('http://localhost/identities/did:fides:nonexistent', {
        method: 'GET',
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(404)
      const data = await res.json()
      expect(data.error).toContain('not found')
    })
  })

  describe('GET /.well-known/fides.json', () => {
    it('should return valid discovery document', async () => {
      const req = new Request('http://localhost/.well-known/fides.json', {
        method: 'GET',
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data).toHaveProperty('did')
      expect(data).toHaveProperty('publicKey')
      expect(data).toHaveProperty('algorithm')
      expect(data).toHaveProperty('endpoints')
      expect(data).toHaveProperty('createdAt')
      expect(data.algorithm).toBe('ed25519')
    })
  })

  describe('GET /health', () => {
    it('should return 200 with health status', async () => {
      const req = new Request('http://localhost/health', {
        method: 'GET',
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data).toMatchObject({
        status: 'healthy',
        service: 'discovery',
      })
      expect(data).toHaveProperty('timestamp')
    })
  })
})
