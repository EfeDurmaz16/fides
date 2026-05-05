import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const ORIGINAL_SERVICE_API_KEY = process.env.SERVICE_API_KEY

beforeEach(() => {
  delete process.env.SERVICE_API_KEY
  vi.restoreAllMocks()
})

afterEach(() => {
  if (ORIGINAL_SERVICE_API_KEY) {
    process.env.SERVICE_API_KEY = ORIGINAL_SERVICE_API_KEY
  } else {
    delete process.env.SERVICE_API_KEY
  }
})

vi.stubGlobal('fetch', vi.fn())

import { app } from '../src/index.js'
import { createDelegationToken } from '@fides/core'

const mockFetch = fetch as ReturnType<typeof vi.fn>

describe('Agentd Service Routes', () => {
  const TEST_DID = 'did:fides:agentd-test-01'

  function makeDelegationToken(overrides: Record<string, unknown> = {}) {
    return {
      ...createDelegationToken({
        delegator: 'did:fides:principal',
        delegatee: TEST_DID,
        capabilities: ['payments.execute', 'files.read'],
        constraints: {},
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        audience: ['agentd'],
      }),
      signature: '00'.repeat(64),
      ...overrides,
    }
  }

  function createMockResponse(body: unknown, status = 200) {
    const bodyStr = JSON.stringify(body)
    return Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(bodyStr),
      headers: new Headers(),
    })
  }

  describe('GET /health', () => {
    it('returns health status with checks for all upstream services', async () => {
      mockFetch.mockImplementation((url: string) => {
        if (url.includes('health')) {
          return createMockResponse({ status: 'healthy' })
        }
        return Promise.reject(new Error('unreachable'))
      })

      const res = await app.request('/health')
      const data = await res.json()

      expect(data.service).toBe('agentd')
      expect(data.timestamp).toBeDefined()
      expect(data.checks).toBeDefined()
      expect(data.checks.discovery).toBe('connected')
      expect(data.checks.trustGraph).toBe('connected')
      expect(data.checks.registry).toBe('connected')
      expect(data.status).toBe('healthy')
    })

    it('returns degraded when upstream services are unreachable', async () => {
      mockFetch.mockRejectedValue(new Error('connection refused'))

      const res = await app.request('/health')
      const data = await res.json()

      expect(data.status).toBe('degraded')
      expect(data.checks.discovery).toBe('unreachable')
      expect(data.checks.trustGraph).toBe('unreachable')
      expect(data.checks.registry).toBe('unreachable')
    })
  })

  describe('GET /v1/identities/:did', () => {
    it('resolves identity via discovery proxy', async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse({
          did: TEST_DID,
          publicKey: 'aa'.repeat(32),
          metadata: { name: 'Test Agent' },
        })
      )

      const res = await app.request(`/v1/identities/${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.did).toBe(TEST_DID)
      expect(data.status).toBe('resolved')
      expect(data.data).toBeDefined()
    })

    it('returns 404 when identity not found upstream', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: 'Not found' }),
        text: () => Promise.resolve(''),
        headers: new Headers(),
      } as any)

      const res = await app.request(`/v1/identities/${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(404)
      const data = await res.json()
      expect(data.status).toBe('not-found')
    })

    it('returns 502 when discovery is unreachable', async () => {
      mockFetch.mockRejectedValue(new Error('ECONNREFUSED'))

      const res = await app.request(`/v1/identities/${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(502)
      const data = await res.json()
      expect(data.status).toBe('unreachable')
    })
  })

  describe('GET /v1/cards/:did', () => {
    it('returns agent card from registry', async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse({ id: TEST_DID, name: 'Test Card', version: '1.0' })
      )

      const res = await app.request(`/v1/cards/${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.did).toBe(TEST_DID)
      expect(data.card).toBeDefined()
      expect(data.card.id).toBe(TEST_DID)
    })

    it('returns 404 when card not found in registry', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: 'Not found' }),
        text: () => Promise.resolve(''),
        headers: new Headers(),
      } as any)

      const res = await app.request(`/v1/cards/${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(404)
      const data = await res.json()
      expect(data.error).toBe('not found')
    })
  })

  describe('GET /v1/trust/:did/score', () => {
    it('returns trust score from trust-graph', async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse({ score: 0.85, directTrusters: 5, transitiveTrusters: 12 })
      )

      const res = await app.request(`/v1/trust/${encodeURIComponent(TEST_DID)}/score`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.did).toBe(TEST_DID)
      expect(data.score).toBe(0.85)
      expect(data.directTrusters).toBe(5)
    })

    it('returns fallback score when trust-graph is unreachable', async () => {
      mockFetch.mockRejectedValue(new Error('ECONNREFUSED'))

      const res = await app.request(`/v1/trust/${encodeURIComponent(TEST_DID)}/score`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.did).toBe(TEST_DID)
      expect(data.score).toBe(0.5)
      expect(data.source).toBe('fallback')
    })
  })

  describe('POST /v1/policy/evaluate', () => {
    it('evaluates policy and returns decision', async () => {
      const res = await app.request('/v1/policy/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: TEST_DID,
          capabilityId: 'web:search',
          policy: {
            id: 'policy-1',
            version: '1.0',
            rules: [],
            defaultAction: 'allow',
          },
          context: {},
        }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.decision).toBe('allow')
    })

    it('denies when a policy deny rule matches', async () => {
      const res = await app.request('/v1/policy/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: TEST_DID,
          capabilityId: 'payments:transfer',
          policy: {
            id: 'policy-2',
            version: '1.0',
            rules: [
              {
                id: 'deny-critical-capability',
                condition: { operator: 'eq', field: 'capabilityId', value: 'payments:transfer' },
                action: 'deny',
                explanation: 'Critical payment transfer requires a separate approval flow',
              },
            ],
            defaultAction: 'allow',
          },
          context: {},
        }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.decision).toBe('deny')
      expect(data.matchedRules).toEqual(['deny-critical-capability'])
    })

    it('returns default allow when no policy provided', async () => {
      const res = await app.request('/v1/policy/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: TEST_DID,
          capabilityId: 'web:search',
        }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.decision).toBe('allow')
      expect(data.explanation.decision).toContain('No policy provided')
    })
  })

  describe('Evidence Ledger', () => {
    it('submits evidence and returns 201', async () => {
      const did = `evidence-${Date.now()}`
      const res = await app.request('/v1/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: did,
          action: 'capability:invoke',
          type: 'execution',
          payload: { capability: 'web:search', params: { q: 'test' } },
        }),
      })
      expect(res.status).toBe(201)
      const data = await res.json()
      expect(data.accepted).toBe(true)
      expect(data.id).toBeDefined()
    })

    it('returns 400 when actor is missing', async () => {
      const res = await app.request('/v1/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'log',
          payload: {},
        }),
      })
      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('actor')
    })

    it('retrieves evidence chain for a DID', async () => {
      const did = `evidence-chain-${Date.now()}`
      await app.request('/v1/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: did,
          action: 'event1',
          payload: {},
        }),
      })
      await app.request('/v1/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: did,
          action: 'event2',
          payload: {},
        }),
      })

      const res = await app.request(`/v1/evidence/${encodeURIComponent(did)}`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.did).toBe(did)
      expect(data.events).toHaveLength(2)
      expect(data.valid).toBe(true)
      expect(data.merkleRoot).toBeDefined()
      expect(data.count).toBe(2)
    })

    it('returns empty chain for unknown DID', async () => {
      const did = `empty-chain-${Date.now()}`
      const res = await app.request(`/v1/evidence/${encodeURIComponent(did)}`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.events).toHaveLength(0)
      expect(data.valid).toBe(true)
    })
  })

  describe('Delegation Sessions and Authorization', () => {
    it('creates a session from a delegated capability', async () => {
      const res = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: makeDelegationToken({ delegatee: `${TEST_DID}:session-create` }),
          capabilityId: 'payments.execute',
          audience: 'agentd',
        }),
      })

      expect(res.status).toBe(201)
      const data = await res.json()
      expect(data.authorized).toBe(true)
      expect(data.session.id).toBeDefined()
      expect(data.session.sessionKey).toBe('redacted')
    })

    it('rejects replayed delegation nonces', async () => {
      const token = makeDelegationToken({ delegatee: `${TEST_DID}:session-replay` })

      await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, capabilityId: 'payments.execute', audience: 'agentd' }),
      })
      const res = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, capabilityId: 'payments.execute', audience: 'agentd' }),
      })

      expect(res.status).toBe(409)
      const data = await res.json()
      expect(data.errors).toContain('DelegationToken nonce has already been used')
    })

    it('rejects sessions for missing capabilities and audience mismatches', async () => {
      const missingCapability = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: makeDelegationToken({ delegatee: `${TEST_DID}:missing-capability` }),
          capabilityId: 'wallets.sign',
          audience: 'agentd',
        }),
      })
      expect(missingCapability.status).toBe(409)

      const audienceMismatch = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: makeDelegationToken({ delegatee: `${TEST_DID}:audience-mismatch` }),
          capabilityId: 'payments.execute',
          audience: 'registry',
        }),
      })
      expect(audienceMismatch.status).toBe(409)
    })

    it('authorizes an allowed session invocation and appends evidence', async () => {
      const did = `did:fides:authorize-${Date.now()}`
      const sessionRes = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: makeDelegationToken({ delegatee: did }),
          capabilityId: 'payments.execute',
          audience: 'agentd',
        }),
      })
      const { session } = await sessionRes.json()

      const res = await app.request('/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: did,
          capabilityId: 'payments.execute',
          sessionId: session.id,
          audience: 'agentd',
        }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.decision).toBe('allow')

      const evidenceRes = await app.request(`/v1/evidence/${encodeURIComponent(did)}`)
      const evidence = await evidenceRes.json()
      expect(evidence.count).toBe(1)
      expect(evidence.events[0].action).toBe('authorization.allow')
    })

    it('denies authorization after session revocation', async () => {
      const did = `did:fides:session-revoked-${Date.now()}`
      const sessionRes = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: makeDelegationToken({ delegatee: did }),
          capabilityId: 'payments.execute',
          audience: 'agentd',
        }),
      })
      const { session } = await sessionRes.json()

      await app.request(`/v1/sessions/${session.id}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'manual revoke' }),
      })

      const res = await app.request('/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: did,
          capabilityId: 'payments.execute',
          sessionId: session.id,
          audience: 'agentd',
        }),
      })

      expect(res.status).toBe(403)
      const data = await res.json()
      expect(data.explanation).toContain('SessionGrant is revoked')
    })

    it('records revocations and denies future authorization', async () => {
      const did = `did:fides:revoked-${Date.now()}`
      mockFetch.mockResolvedValueOnce(createMockResponse({ id: 'trust-graph-revocation' }, 201))
      const revokeRes = await app.request('/v1/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          did,
          reason: 'principal revoked delegation',
          revokedBy: 'did:fides:principal',
        }),
      })
      expect(revokeRes.status).toBe(201)
      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3200/v1/revocations', expect.objectContaining({ method: 'POST' }))

      const statusRes = await app.request(`/v1/revocations/${encodeURIComponent(did)}`)
      const status = await statusRes.json()
      expect(status.revoked).toBe(true)

      const authRes = await app.request('/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: did,
          capabilityId: 'payments.execute',
        }),
      })
      expect(authRes.status).toBe(403)
      const auth = await authRes.json()
      expect(auth.decision).toBe('deny')
      expect(auth.explanation).toContain('Agent authority revoked')
    })

    it('records incidents and uses their impact in authorization', async () => {
      const did = `did:fides:incident-${Date.now()}`
      mockFetch.mockResolvedValueOnce(createMockResponse({ id: 'trust-graph-incident' }, 201))
      const incidentRes = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: did,
          type: 'policy_violation',
          severity: 'critical',
          description: 'Repeated unauthorized payment attempts',
          capabilitiesRevoked: ['payments.execute'],
        }),
      })
      expect(incidentRes.status).toBe(201)
      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3200/v1/incidents', expect.objectContaining({ method: 'POST' }))

      const listRes = await app.request(`/v1/incidents/${encodeURIComponent(did)}`)
      const list = await listRes.json()
      expect(list.impact.incidentCount).toBe(1)
      expect(list.impact.allRevokedCapabilities).toContain('payments.execute')

      const authRes = await app.request('/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: did,
          capabilityId: 'payments.execute',
          requiresApproval: true,
        }),
      })
      expect(authRes.status).toBe(200)
      const auth = await authRes.json()
      expect(auth.decision).toBe('approve-required')
    })
  })

  describe('Kill Switch', () => {
    it('returns kill switch status', async () => {
      const res = await app.request('/v1/killswitch/status')
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data).toHaveProperty('global')
    })

    it('engages global kill switch', async () => {
      const res = await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ global: true }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.engaged).toBe(true)
      expect(data.scope).toBe('global')
    })

    it('engages agent-specific kill switch', async () => {
      const res = await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ did: TEST_DID }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.engaged).toBe(true)
      expect(data.scope).toBe('agent')
      expect(data.did).toBe(TEST_DID)
    })

    it('engages capability-specific kill switch', async () => {
      const res = await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capabilityId: 'payment:charge' }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.engaged).toBe(true)
      expect(data.scope).toBe('capability')
      expect(data.id).toBe('payment:charge')
    })

    it('disengages kill switch', async () => {
      await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ global: true }),
      })

      const res = await app.request('/v1/killswitch/disengage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ global: true }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.engaged).toBe(false)
      expect(data.scope).toBe('global')
    })

    it('disengages all kill switches when no scope specified', async () => {
      await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ global: true }),
      })

      const res = await app.request('/v1/killswitch/disengage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.engaged).toBe(false)
      expect(data.scope).toBe('all')
    })
  })

  describe('POST /v1/attest', () => {
    it('creates runtime attestation', async () => {
      const res = await app.request('/v1/attest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ did: TEST_DID }),
      })
      expect(res.status).toBe(201)
      const data = await res.json()
      expect(data.agentDid).toBe(TEST_DID)
      expect(data.provider).toBe('mock-tee')
      expect(data.measurement).toBeDefined()
      expect(data.signature).toBe('mock-signature')
    })

    it('returns 400 when did is missing', async () => {
      const res = await app.request('/v1/attest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('did')
    })
  })
})
