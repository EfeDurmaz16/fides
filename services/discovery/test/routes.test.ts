import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { app } from '../src/index.js'
import { DISCOVERY_API_SCOPES, discoveryScopeForRequest } from '../src/middleware/auth.js'

// Valid test identity: 32 bytes of 0xaa
const TEST_PUBLIC_KEY = 'aa'.repeat(32)
const TEST_DID = 'did:fides:CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB'
const ORIGINAL_SERVICE_API_KEY = process.env.SERVICE_API_KEY
const ORIGINAL_DISCOVERY_API_KEYS = process.env.DISCOVERY_API_KEYS
const ORIGINAL_NODE_ENV = process.env.NODE_ENV

// Mock the database module
vi.mock('../src/db/client.js', () => {
  const baseIdentity = {
    did: 'did:fides:CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB',
    publicKey: 'aa'.repeat(32),
    metadata: {},
    domain: null,
    domainVerified: false,
    domainVerifiedAt: null,
    verificationMethod: null,
    organizationDomain: null,
    organizationDomainVerified: false,
    organizationDomainVerifiedAt: null,
    organizationVerificationMethod: null,
    createdAt: new Date('2024-01-01T00:00:00.000Z'),
    updatedAt: new Date('2024-01-01T00:00:00.000Z'),
  }
  const mockDb = {
    insert: vi.fn().mockReturnValue({
      values: vi.fn().mockReturnValue({
        returning: vi.fn().mockResolvedValue([baseIdentity]),
      }),
    }),
    select: vi.fn().mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockResolvedValue([baseIdentity]),
      }),
    }),
    update: vi.fn().mockReturnValue({
      set: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({
          returning: vi.fn().mockResolvedValue([{
            ...baseIdentity,
            domain: 'example.com',
            domainVerified: true,
            domainVerifiedAt: new Date('2024-01-02T00:00:00.000Z'),
            verificationMethod: 'dns',
            organizationDomain: 'example.com',
            organizationDomainVerified: true,
            organizationDomainVerifiedAt: new Date('2024-01-02T00:00:00.000Z'),
            organizationVerificationMethod: 'dns',
            updatedAt: new Date('2024-01-02T00:00:00.000Z'),
          }]),
        }),
      }),
    }),
  }

  // Create a mock sql that supports template literal calls (e.g., sql`SELECT 1`)
  const mockSql = Object.assign(
    vi.fn().mockResolvedValue([{ '?column?': 1 }]),
    { end: vi.fn().mockResolvedValue(undefined) }
  )

  return {
    db: mockDb,
    sql: mockSql,
  }
})

vi.mock('node:dns/promises', () => ({
  resolveTxt: vi.fn(),
}))

describe('Discovery Service Routes', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    delete process.env.SERVICE_API_KEY
    delete process.env.DISCOVERY_API_KEYS
    process.env.NODE_ENV = 'test'
  })

  afterEach(() => {
    restoreEnv('SERVICE_API_KEY', ORIGINAL_SERVICE_API_KEY)
    restoreEnv('DISCOVERY_API_KEYS', ORIGINAL_DISCOVERY_API_KEYS)
    restoreEnv('NODE_ENV', ORIGINAL_NODE_ENV)
  })

  describe('API key authentication', () => {
    it('maps discovery write routes to least-privilege scopes', () => {
      expect(discoveryScopeForRequest('POST', '/identities')).toBe(DISCOVERY_API_SCOPES.identitiesRegister)
      expect(discoveryScopeForRequest('POST', '/identities/did%3Afides%3Aagent/domain/verify')).toBe(DISCOVERY_API_SCOPES.identitiesDomainVerify)
      expect(discoveryScopeForRequest('POST', '/identities/did%3Afides%3Aagent/organization-domain/verify')).toBe(DISCOVERY_API_SCOPES.identitiesOrganizationDomainVerify)
      expect(discoveryScopeForRequest('POST', '/agents')).toBe(DISCOVERY_API_SCOPES.agentsRegister)
      expect(discoveryScopeForRequest('PUT', '/agents/did%3Afides%3Aagent')).toBe(DISCOVERY_API_SCOPES.agentsUpdate)
      expect(discoveryScopeForRequest('PUT', '/agents/did%3Afides%3Aagent/heartbeat')).toBe(DISCOVERY_API_SCOPES.agentsHeartbeat)
      expect(discoveryScopeForRequest('DELETE', '/agents/did%3Afides%3Aagent')).toBe(DISCOVERY_API_SCOPES.agentsDelete)
      expect(discoveryScopeForRequest('POST', '/unknown')).toBe(DISCOVERY_API_SCOPES.write)
    })

    it('fails closed for discovery writes in production when API key is not configured', async () => {
      process.env.NODE_ENV = 'production'
      delete process.env.SERVICE_API_KEY

      const req = new Request('http://localhost/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          did: TEST_DID,
          publicKey: TEST_PUBLIC_KEY,
        }),
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(503)
      expect((await res.json()).error).toContain('SERVICE_API_KEY is required in production')
    })

    it('enforces scoped discovery API keys when configured', async () => {
      process.env.DISCOVERY_API_KEYS = JSON.stringify([
        { key: 'identity-key', scopes: ['discovery:identities:register'] },
        { key: 'heartbeat-key', scopes: ['discovery:agents:heartbeat'] },
      ])

      const deniedReq = new Request(`http://localhost/agents/${encodeURIComponent(TEST_DID)}/heartbeat`, {
        method: 'PUT',
        headers: { 'X-API-Key': 'identity-key' },
      })

      const deniedRes = await app.fetch(deniedReq)
      expect(deniedRes.status).toBe(403)
      expect((await deniedRes.json()).error).toContain('discovery:agents:heartbeat')

      const allowedReq = new Request(`http://localhost/agents/${encodeURIComponent(TEST_DID)}/heartbeat`, {
        method: 'PUT',
        headers: { 'X-API-Key': 'heartbeat-key' },
      })

      const allowedRes = await app.fetch(allowedReq)
      expect(allowedRes.status).toBe(200)
      expect(await allowedRes.json()).toMatchObject({ status: 'online' })
    })

    it('fails closed when scoped discovery API keys are malformed', async () => {
      process.env.DISCOVERY_API_KEYS = '{bad-json'

      const req = new Request('http://localhost/agents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'agent-key' },
        body: JSON.stringify({
          did: TEST_DID,
          name: 'Test Agent',
          url: 'https://agent.example.com',
        }),
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(503)
      expect((await res.json()).error).toContain('DISCOVERY_API_KEYS must be a JSON array')
    })
  })

  describe('POST /identities', () => {
    it('should register a new identity and return 201', async () => {
      const req = new Request('http://localhost/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          did: TEST_DID,
          publicKey: TEST_PUBLIC_KEY,
          metadata: { name: 'Test Agent' },
        }),
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(201)
      const data = await res.json()
      expect(data).toMatchObject({
        did: TEST_DID,
        publicKey: TEST_PUBLIC_KEY,
        metadata: {},
        domainVerified: false,
        organizationDomainVerified: false,
      })
    })

    it('should return 400 for invalid payload', async () => {
      const req = new Request('http://localhost/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          did: TEST_DID,
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
          publicKey: TEST_PUBLIC_KEY,
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
          did: TEST_DID,
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
      const req = new Request(`http://localhost/identities/${TEST_DID}`, {
        method: 'GET',
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data).toMatchObject({
        did: TEST_DID,
        publicKey: TEST_PUBLIC_KEY,
        domainVerified: false,
        organizationDomainVerified: false,
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

  describe('POST /identities/:did/domain/verify', () => {
    it('verifies and persists domain ownership', async () => {
      const dns = await import('node:dns/promises')
      vi.mocked(dns.resolveTxt).mockResolvedValue([['fides-did=', TEST_DID]])

      const req = new Request(`http://localhost/identities/${encodeURIComponent(TEST_DID)}/domain/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: 'Example.COM.' }),
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(200)
      expect(dns.resolveTxt).toHaveBeenCalledWith('_fides.example.com')
      const data = await res.json()
      expect(data).toMatchObject({
        did: TEST_DID,
        domain: 'example.com',
        domainVerified: true,
        verificationMethod: 'dns',
        verification: {
          domain: 'example.com',
          did: TEST_DID,
          recordName: '_fides.example.com',
          verified: true,
        },
      })
    })

    it('does not persist when DNS verification fails', async () => {
      const dns = await import('node:dns/promises')
      vi.mocked(dns.resolveTxt).mockResolvedValue(['other=value'])

      const req = new Request(`http://localhost/identities/${encodeURIComponent(TEST_DID)}/domain/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: 'example.com' }),
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(422)
      const data = await res.json()
      expect(data).toMatchObject({
        domain: 'example.com',
        did: TEST_DID,
        verified: false,
        reason: 'record-not-found',
        persisted: false,
      })

      const { db } = await import('../src/db/client.js')
      expect(db.update).not.toHaveBeenCalled()
    })
  })

  describe('POST /identities/:did/organization-domain/verify', () => {
    it('verifies and persists organization domain ownership', async () => {
      const dns = await import('node:dns/promises')
      vi.mocked(dns.resolveTxt).mockResolvedValue([['fides-org-did=', TEST_DID]])

      const req = new Request(`http://localhost/identities/${encodeURIComponent(TEST_DID)}/organization-domain/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: 'Example.COM.' }),
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(200)
      expect(dns.resolveTxt).toHaveBeenCalledWith('_fides-org.example.com')
      const data = await res.json()
      expect(data).toMatchObject({
        did: TEST_DID,
        organizationDomain: 'example.com',
        organizationDomainVerified: true,
        organizationVerificationMethod: 'dns',
        verification: {
          domain: 'example.com',
          did: TEST_DID,
          recordName: '_fides-org.example.com',
          verified: true,
        },
      })
    })

    it('does not persist when organization DNS verification fails', async () => {
      const dns = await import('node:dns/promises')
      vi.mocked(dns.resolveTxt).mockResolvedValue(['fides-did=' + TEST_DID])

      const req = new Request(`http://localhost/identities/${encodeURIComponent(TEST_DID)}/organization-domain/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: 'example.com' }),
      })

      const res = await app.fetch(req)

      expect(res.status).toBe(422)
      const data = await res.json()
      expect(data).toMatchObject({
        domain: 'example.com',
        did: TEST_DID,
        verified: false,
        reason: 'record-not-found',
        persisted: false,
      })

      const { db } = await import('../src/db/client.js')
      expect(db.update).not.toHaveBeenCalled()
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

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name]
  } else {
    process.env[name] = value
  }
}
