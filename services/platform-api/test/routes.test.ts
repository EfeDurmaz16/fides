import { describe, expect, it } from 'vitest'
import { app } from '../src/index.js'

describe('platform-api service', () => {
  it('returns health status', async () => {
    const res = await app.request('/health')

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.status).toBe('healthy')
    expect(data.service).toBe('platform-api')
    expect(data.timestamp).toBeDefined()
  })

  it('returns version metadata', async () => {
    const res = await app.request('/v1/version')

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data).toMatchObject({
      service: 'platform-api',
      version: '0.1.0',
      protocol: 'fides-v2',
    })
  })

  it('exposes Prometheus metrics', async () => {
    await app.request('/health')

    const res = await app.request('/metrics')

    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toContain('text/plain')
    const body = await res.text()
    expect(body).toContain('http_requests_total')
    expect(body).toContain('path="/health"')
  })

  it('returns default service topology', async () => {
    const res = await app.request('/v1/topology')

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.components).toMatchObject({
      discovery: 'http://localhost:3100',
      trustGraph: 'http://localhost:3200',
      policyEngine: 'http://localhost:3300',
      registry: 'http://localhost:7346',
      relay: 'http://localhost:7347',
      agentd: 'http://localhost:7345',
    })
  })

  it('requires an API key for topology metadata in production', async () => {
    const previousNodeEnv = process.env.NODE_ENV
    const previousApiKey = process.env.SERVICE_API_KEY
    process.env.NODE_ENV = 'production'
    delete process.env.SERVICE_API_KEY

    try {
      const res = await app.request('/v1/topology')

      expect(res.status).toBe(503)
      const data = await res.json()
      expect(data.error).toContain('SERVICE_API_KEY is required')
    } finally {
      restoreEnv('NODE_ENV', previousNodeEnv)
      restoreEnv('SERVICE_API_KEY', previousApiKey)
    }
  })

  it('rejects invalid API keys when topology auth is configured', async () => {
    const previousApiKey = process.env.SERVICE_API_KEY
    process.env.SERVICE_API_KEY = 'expected-key'

    try {
      const res = await app.request('/v1/topology', {
        headers: { 'X-API-Key': 'wrong-key' },
      })

      expect(res.status).toBe(401)
    } finally {
      restoreEnv('SERVICE_API_KEY', previousApiKey)
    }
  })

  it('accepts valid API keys when topology auth is configured', async () => {
    const previousApiKey = process.env.SERVICE_API_KEY
    process.env.SERVICE_API_KEY = 'expected-key'

    try {
      const res = await app.request('/v1/topology', {
        headers: { 'X-API-Key': 'expected-key' },
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.components.agentd).toBe('http://localhost:7345')
    } finally {
      restoreEnv('SERVICE_API_KEY', previousApiKey)
    }
  })

  it('enforces scoped platform API keys when configured', async () => {
    const previousApiKey = process.env.SERVICE_API_KEY
    const previousScopedKeys = process.env.PLATFORM_API_KEYS
    delete process.env.SERVICE_API_KEY
    process.env.PLATFORM_API_KEYS = JSON.stringify([
      { key: 'passkey-key', scopes: ['platform:passkeys:write', 'platform:passkeys:read'] },
      { key: 'trust-key', scopes: ['platform:trust-anchors:write', 'platform:trust-anchors:read'] },
    ])

    try {
      const passkeyRes = await app.request('/v1/passkeys/principals/did%3Afides%3Aprincipal/credentials', {
        headers: { 'X-API-Key': 'passkey-key' },
      })
      expect(passkeyRes.status).toBe(200)

      const trustAnchorRes = await app.request('/v1/trust-anchors', {
        headers: { 'X-API-Key': 'passkey-key' },
      })
      expect(trustAnchorRes.status).toBe(403)
      expect((await trustAnchorRes.json()).error).toContain('platform:trust-anchors:read')
    } finally {
      restoreEnv('SERVICE_API_KEY', previousApiKey)
      restoreEnv('PLATFORM_API_KEYS', previousScopedKeys)
    }
  })

  it('fails closed when scoped platform API keys are malformed', async () => {
    const previousApiKey = process.env.SERVICE_API_KEY
    const previousScopedKeys = process.env.PLATFORM_API_KEYS
    delete process.env.SERVICE_API_KEY
    process.env.PLATFORM_API_KEYS = '{bad-json'

    try {
      const res = await app.request('/v1/trust-anchors', {
        headers: { 'X-API-Key': 'trust-key' },
      })

      expect(res.status).toBe(503)
      expect((await res.json()).error).toContain('PLATFORM_API_KEYS must be a JSON array')
    } finally {
      restoreEnv('SERVICE_API_KEY', previousApiKey)
      restoreEnv('PLATFORM_API_KEYS', previousScopedKeys)
    }
  })

  it('creates, lists, reads, updates, and deletes passkey credential bindings', async () => {
    const binding = {
      principalDid: 'did:fides:principal-passkey-01',
      credentialId: 'credential-passkey-01',
      publicKey: 'public-key-material',
      relyingPartyId: 'Example.COM',
      signCount: 1,
      transports: ['internal'],
      backedUp: true,
      createdAt: '2026-01-01T00:00:00.000Z',
    }

    const createRes = await app.request('/v1/passkeys/bindings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(binding),
    })
    expect(createRes.status).toBe(201)
    const created = await createRes.json()
    expect(created.binding).toMatchObject({
      principalDid: binding.principalDid,
      credentialId: binding.credentialId,
      relyingPartyId: 'example.com',
      signCount: 1,
    })
    expect(created.binding.lastVerifiedAt).toBeDefined()

    const listRes = await app.request(`/v1/passkeys/principals/${encodeURIComponent(binding.principalDid)}/credentials`)
    expect(listRes.status).toBe(200)
    const list = await listRes.json()
    expect(list).toMatchObject({ principalDid: binding.principalDid, count: 1 })
    expect(list.credentials[0]).toMatchObject({
      credentialId: binding.credentialId,
      relyingPartyId: 'example.com',
      signCount: 1,
    })

    const getRes = await app.request(`/v1/passkeys/credentials/${binding.credentialId}`)
    expect(getRes.status).toBe(200)
    expect((await getRes.json()).binding.publicKey).toBe(binding.publicKey)

    const updateRes = await app.request('/v1/passkeys/bindings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...binding, signCount: 2 }),
    })
    expect(updateRes.status).toBe(200)
    expect((await updateRes.json()).binding.signCount).toBe(2)

    const deleteRes = await app.request(`/v1/passkeys/credentials/${binding.credentialId}`, { method: 'DELETE' })
    expect(deleteRes.status).toBe(200)

    const missingRes = await app.request(`/v1/passkeys/credentials/${binding.credentialId}`)
    expect(missingRes.status).toBe(404)
  })

  it('rejects passkey binding takeover and signCount rollback', async () => {
    const binding = {
      principalDid: 'did:fides:principal-passkey-02',
      credentialId: 'credential-passkey-02',
      publicKey: 'public-key-material',
      relyingPartyId: 'example.com',
      signCount: 5,
      createdAt: '2026-01-01T00:00:00.000Z',
    }

    await app.request('/v1/passkeys/bindings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(binding),
    })

    const rollbackRes = await app.request('/v1/passkeys/bindings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...binding, signCount: 4 }),
    })
    expect(rollbackRes.status).toBe(409)
    expect((await rollbackRes.json()).error).toContain('cannot move backwards')

    const takeoverRes = await app.request('/v1/passkeys/bindings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...binding, principalDid: 'did:fides:other-principal', signCount: 6 }),
    })
    expect(takeoverRes.status).toBe(409)
    expect((await takeoverRes.json()).error).toContain('different principal')
  })

  it('validates passkey credential binding input', async () => {
    const res = await app.request('/v1/passkeys/bindings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        principalDid: 'did:other:principal',
        credentialId: '',
        publicKey: 'key',
        relyingPartyId: 'example.com',
        signCount: 0,
        createdAt: '2026-01-01T00:00:00.000Z',
      }),
    })

    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('principalDid')
  })

  it('validates optional passkey credential metadata', async () => {
    const baseBinding = {
      principalDid: 'did:fides:principal-passkey-metadata',
      credentialId: 'credential-passkey-metadata',
      publicKey: 'public-key-material',
      relyingPartyId: 'example.com',
      signCount: 0,
      createdAt: '2026-01-01T00:00:00.000Z',
    }

    const invalidCases = [
      {
        body: { ...baseBinding, transports: ['internal', 'serial'] },
        error: 'transports',
      },
      {
        body: { ...baseBinding, backedUp: 'yes' },
        error: 'backedUp',
      },
      {
        body: { ...baseBinding, lastVerifiedAt: 'not-a-date' },
        error: 'lastVerifiedAt',
      },
    ]

    for (const testCase of invalidCases) {
      const res = await app.request('/v1/passkeys/bindings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(testCase.body),
      })

      expect(res.status).toBe(400)
      expect((await res.json()).error).toContain(testCase.error)
    }
  })

  it('normalizes optional passkey transports deterministically', async () => {
    const res = await app.request('/v1/passkeys/bindings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        principalDid: 'did:fides:principal-passkey-transports',
        credentialId: 'credential-passkey-transports',
        publicKey: 'public-key-material',
        relyingPartyId: 'example.com',
        signCount: 0,
        transports: ['usb', 'internal', 'usb'],
        createdAt: '2026-01-01T00:00:00.000Z',
      }),
    })

    expect(res.status).toBe(201)
    expect((await res.json()).binding.transports).toEqual(['internal', 'usb'])
  })

  it('requires API key for passkey bindings in production', async () => {
    const previousNodeEnv = process.env.NODE_ENV
    const previousApiKey = process.env.SERVICE_API_KEY
    process.env.NODE_ENV = 'production'
    delete process.env.SERVICE_API_KEY

    try {
      const res = await app.request('/v1/passkeys/principals/did%3Afides%3Aprincipal/credentials')

      expect(res.status).toBe(503)
      expect((await res.json()).error).toBe('SERVICE_API_KEY is required in production for passkey credential bindings')
    } finally {
      restoreEnv('NODE_ENV', previousNodeEnv)
      restoreEnv('SERVICE_API_KEY', previousApiKey)
    }
  })

  it('creates, lists, distributes, revokes, and deletes governed trust anchors', async () => {
    const anchor = {
      did: 'did:fides:anchor-platform-01',
      name: 'Platform Root Anchor',
      publicKey: '11'.repeat(32),
      attestation: {
        payload: { did: 'did:fides:anchor-platform-01' },
        proof: {
          type: 'Ed25519Signature2024',
          created: '2026-01-01T00:00:00.000Z',
          verificationMethod: 'did:fides:issuer-platform-01#key-1',
          proofPurpose: 'assertionMethod',
          canonicalizationAlgorithm: 'https://fides.dev/canonical-json/v1',
          proofValue: 'signature',
        },
      },
      status: 'active',
      scopes: ['identity.organization', 'publisher.organization'],
      issuerDid: 'did:fides:issuer-platform-01',
      createdAt: '2026-01-01T00:00:00.000Z',
    }
    const suspendedAnchor = {
      ...anchor,
      did: 'did:fides:anchor-platform-02',
      publicKey: '22'.repeat(32),
      status: 'suspended',
      reason: 'manual review',
    }

    const createRes = await app.request('/v1/trust-anchors', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(anchor),
    })
    expect(createRes.status).toBe(201)
    const created = await createRes.json()
    expect(created.anchor).toMatchObject({
      did: anchor.did,
      publicKey: anchor.publicKey,
      status: 'active',
      scopes: ['identity.organization', 'publisher.organization'],
    })
    expect(created.anchor.updatedAt).toBeDefined()

    const suspendedRes = await app.request('/v1/trust-anchors', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(suspendedAnchor),
    })
    expect(suspendedRes.status).toBe(201)

    const listRes = await app.request('/v1/trust-anchors?status=active')
    expect(listRes.status).toBe(200)
    const list = await listRes.json()
    expect(list.anchors.map((entry: { did: string }) => entry.did)).toContain(anchor.did)
    expect(list.anchors.map((entry: { did: string }) => entry.did)).not.toContain(suspendedAnchor.did)

    const getRes = await app.request(`/v1/trust-anchors/${encodeURIComponent(anchor.did)}`)
    expect(getRes.status).toBe(200)
    expect((await getRes.json()).anchor.name).toBe(anchor.name)

    const distributionRes = await app.request('/v1/trust-anchors/distribution?requiredScope=identity.organization&trustedIssuerDids=did%3Afides%3Aissuer-platform-01')
    expect(distributionRes.status).toBe(200)
    const distribution = await distributionRes.json()
    expect(distribution.distribution.version).toBe('fides.trust-anchors.v1')
    expect(distribution.distribution.anchors.map((entry: { did: string }) => entry.did)).toContain(anchor.did)
    expect(distribution.distribution.anchors.map((entry: { did: string }) => entry.did)).not.toContain(suspendedAnchor.did)

    const revokeRes = await app.request(`/v1/trust-anchors/${encodeURIComponent(anchor.did)}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'revoked', reason: 'key compromise' }),
    })
    expect(revokeRes.status).toBe(200)
    const revoked = await revokeRes.json()
    expect(revoked.anchor).toMatchObject({ status: 'revoked', reason: 'key compromise' })
    expect(revoked.anchor.revokedAt).toBeDefined()

    const deleteRes = await app.request(`/v1/trust-anchors/${encodeURIComponent(suspendedAnchor.did)}`, { method: 'DELETE' })
    expect(deleteRes.status).toBe(200)
  })

  it('validates governed trust anchor input', async () => {
    const res = await app.request('/v1/trust-anchors', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        did: 'did:other:anchor',
        name: '',
        publicKey: 'not-hex',
        attestation: {},
        status: 'active',
        scopes: [],
        createdAt: '2026-01-01T00:00:00.000Z',
      }),
    })

    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('did')
  })

  it('validates governed trust anchor status filters', async () => {
    const res = await app.request('/v1/trust-anchors?status=unknown')

    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('status')
  })

  it('requires API key for trust-anchor governance in production', async () => {
    const previousNodeEnv = process.env.NODE_ENV
    const previousApiKey = process.env.SERVICE_API_KEY
    process.env.NODE_ENV = 'production'
    delete process.env.SERVICE_API_KEY

    try {
      const res = await app.request('/v1/trust-anchors')

      expect(res.status).toBe(503)
      expect((await res.json()).error).toBe('SERVICE_API_KEY is required in production for trust-anchor governance')
    } finally {
      restoreEnv('NODE_ENV', previousNodeEnv)
      restoreEnv('SERVICE_API_KEY', previousApiKey)
    }
  })
})

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name]
  } else {
    process.env[name] = value
  }
}
