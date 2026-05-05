import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const ORIGINAL_SERVICE_API_KEY = process.env.SERVICE_API_KEY

beforeEach(() => {
  delete process.env.SERVICE_API_KEY
})

afterEach(() => {
  if (ORIGINAL_SERVICE_API_KEY) {
    process.env.SERVICE_API_KEY = ORIGINAL_SERVICE_API_KEY
  } else {
    delete process.env.SERVICE_API_KEY
  }
})

vi.mock('node:os', () => ({
  homedir: vi.fn(() => '/tmp/fides-test-registry'),
}))

vi.mock('node:fs', () => {
  const store = new Map<string, string>()
  return {
    existsSync: vi.fn((path: string) => store.has(path as string)),
    mkdirSync: vi.fn(),
    readFileSync: vi.fn((path: string, _enc?: string) => {
      const val = store.get(path as string)
      if (!val) throw new Error('ENOENT')
      return val
    }),
    writeFileSync: vi.fn((path: string, content: string) => {
      store.set(path as string, content)
    }),
  }
})

import { app } from '../src/index.js'

describe('Registry Service Routes', () => {
  const TEST_DID = 'did:fides:test-agent-01'
  const TEST_CARD = {
    id: TEST_DID,
    name: 'Test Agent',
    description: 'A test agent card',
    version: '1.0.0',
    capabilities: [{ id: 'web:search', name: 'Web Search' }],
    protocols: ['mcp'],
    endpoints: [{ url: 'https://example.com/api', protocol: 'mcp', capabilities: ['web:search'] }],
    security: { authentication: ['api-key'], encryption: ['tls1.3'] },
    metadata: {},
  }

  describe('GET /health', () => {
    it('returns 200 with health status', async () => {
      const res = await app.request('/health')
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.service).toBe('registry')
      expect(data.timestamp).toBeDefined()
      expect(data.checks).toBeDefined()
      expect(data.status).toBe('healthy')
    })
  })

  describe('POST /v1/cards', () => {
    it('registers a new card and returns 201', async () => {
      const res = await app.request('/v1/cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(TEST_CARD),
      })
      expect(res.status).toBe(201)
      const data = await res.json()
      expect(data.success).toBe(true)
      expect(data.did).toBe(TEST_DID)
      expect(data.registeredAt).toBeDefined()
    })

    it('returns 400 when id is missing', async () => {
      const res = await app.request('/v1/cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'No ID Card' }),
      })
      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('id is required')
    })
  })

  describe('GET /v1/cards/:did', () => {
    it('returns card by DID', async () => {
      await app.request('/v1/cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(TEST_CARD),
      })

      const res = await app.request(`/v1/cards/${TEST_DID}`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.id || data.payload?.id).toBe(TEST_DID)
    })

    it('returns 404 for non-existent DID', async () => {
      const res = await app.request('/v1/cards/did:fides:nonexistent')
      expect(res.status).toBe(404)
      const data = await res.json()
      expect(data.error).toBe('Not found')
    })
  })

  describe('DELETE /v1/cards/:did', () => {
    it('deletes an existing card', async () => {
      await app.request('/v1/cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(TEST_CARD),
      })

      const res = await app.request(`/v1/cards/${TEST_DID}`, { method: 'DELETE' })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.success).toBe(true)

      const getRes = await app.request(`/v1/cards/${TEST_DID}`)
      expect(getRes.status).toBe(404)
    })

    it('returns 404 when deleting non-existent card', async () => {
      const res = await app.request('/v1/cards/did:fides:ghost', { method: 'DELETE' })
      expect(res.status).toBe(404)
    })
  })

  describe('POST /v1/cards/:did/mode', () => {
    it('toggles card to private mode', async () => {
      await app.request('/v1/cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(TEST_CARD),
      })

      const res = await app.request(`/v1/cards/${TEST_DID}/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'private' }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.success).toBe(true)
      expect(data.mode).toBe('private')

      const getRes = await app.request(`/v1/cards/${TEST_DID}`)
      expect(getRes.status).toBe(403)
    })

    it('toggles card back to public mode', async () => {
      await app.request('/v1/cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(TEST_CARD),
      })
      await app.request(`/v1/cards/${TEST_DID}/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'private' }),
      })

      const res = await app.request(`/v1/cards/${TEST_DID}/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'public' }),
      })
      expect(res.status).toBe(200)
      expect((await res.json()).mode).toBe('public')
    })

    it('returns 400 for invalid mode', async () => {
      await app.request('/v1/cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(TEST_CARD),
      })

      const res = await app.request(`/v1/cards/${TEST_DID}/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'invalid' }),
      })
      expect(res.status).toBe(400)
    })
  })

  describe('GET /v1/search', () => {
    it('searches cards by name', async () => {
      await app.request('/v1/cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(TEST_CARD),
      })

      const res = await app.request('/v1/search?q=Test%20Agent')
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.results).toHaveLength(1)
      expect(data.results[0].did).toBe(TEST_DID)
    })

    it('returns empty results for no matches', async () => {
      const res = await app.request('/v1/search?q=zzz_nonexistent')
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.results).toHaveLength(0)
    })
  })

  describe('GET /v1/stats', () => {
    it('returns registry statistics', async () => {
      await app.request('/v1/cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(TEST_CARD),
      })

      const res = await app.request('/v1/stats')
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.total).toBeGreaterThanOrEqual(1)
      expect(data.public).toBeGreaterThanOrEqual(1)
      expect(typeof data.private).toBe('number')
    })
  })

  describe('API Key Authentication', () => {
    it('returns 401 when API key is required but not provided', async () => {
      process.env.SERVICE_API_KEY = 'test-api-key-for-registry'

      const res = await app.request('/v1/cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(TEST_CARD),
      })
      expect(res.status).toBe(401)
      const data = await res.json()
      expect(data.error).toContain('Unauthorized')
    })

    it('allows mutation with valid API key', async () => {
      process.env.SERVICE_API_KEY = 'test-api-key-for-registry'

      const res = await app.request('/v1/cards', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'test-api-key-for-registry',
        },
        body: JSON.stringify(TEST_CARD),
      })
      expect(res.status).toBe(201)
    })
  })
})
