import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AgentdClient, AgentdError } from '../src/agentd/client.js'

describe('AgentdClient', () => {
  const mockFetch = vi.fn()
  let client: AgentdClient
  const privateKeyHex = '01'.repeat(32)
  const token = {
    id: 'tok-1',
    delegator: 'did:fides:principal',
    delegatee: 'did:fides:agent',
    capabilities: ['payments.execute'],
    constraints: {},
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2026-01-01T01:00:00.000Z',
    nonce: 'nonce-1',
    signature: 'aa',
    audience: ['agentd'],
  }
  const revocation = {
    id: 'rev-1',
    did: 'did:fides:agent',
    reason: 'disabled',
    revokedAt: '2026-01-01T00:00:00.000Z',
    revokedBy: 'did:fides:principal',
    signature: 'bb',
    propagatedTo: [],
  }
  const incident = {
    id: 'inc-1',
    type: 'policy_violation' as const,
    severity: 'high' as const,
    actor: 'did:fides:agent',
    reportedBy: 'did:fides:principal',
    description: 'policy bypass',
    evidenceRefs: [],
    reportedAt: '2026-01-01T00:00:00.000Z',
    impact: {
      trustPenalty: 0.35,
      reputationPenalty: 0.7,
      capabilitiesRevoked: ['payments.execute'],
    },
    signature: 'cc',
  }

  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch)
    mockFetch.mockReset()
    client = new AgentdClient({ baseUrl: 'http://localhost:7345/', apiKey: 'sdk-key' })
  })

  it('reads agentd health including local state store status', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => JSON.stringify({
        status: 'healthy',
        service: 'agentd',
        checks: {
          authorityStore: 'ready',
          localStateStore: 'ready',
        },
        authorityStore: {
          kind: 'memory',
          ok: true,
        },
        localStateStore: {
          kind: 'sqlite',
          ok: true,
          path: '/tmp/fides.sqlite',
        },
      }),
    })

    await expect(client.health()).resolves.toMatchObject({
      status: 'healthy',
      localStateStore: {
        kind: 'sqlite',
        ok: true,
        path: '/tmp/fides.sqlite',
      },
    })

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:7345/health',
      expect.objectContaining({ method: 'GET' })
    )
  })

  it('creates and reads delegated sessions', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ authorized: true, session: { id: 'sess-1', token, sessionKey: 'redacted', expiresAt: token.expiresAt } }),
      })
      .mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ session: { id: 'sess-1', token, sessionKey: 'redacted', expiresAt: token.expiresAt } }),
      })

    await expect(client.createSession({
      token,
      capabilityId: 'payments.execute',
      audience: 'agentd',
      delegatorPublicKey: '11'.repeat(32),
    })).resolves.toMatchObject({ authorized: true })
    await expect(client.getSession('sess-1')).resolves.toMatchObject({ session: { id: 'sess-1' } })

    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      'http://localhost:7345/v1/sessions',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          token,
          capabilityId: 'payments.execute',
          audience: 'agentd',
          delegatorPublicKey: '11'.repeat(32),
        }),
      })
    )
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      'http://localhost:7345/v1/sessions/sess-1',
      expect.objectContaining({ method: 'GET' })
    )
  })

  it('revokes delegated sessions', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => JSON.stringify({ revoked: true, session: { id: 'sess-1', token, sessionKey: 'redacted', expiresAt: token.expiresAt, revoked: true } }),
    })

    await expect(client.revokeSession('sess-1', 'operator disabled')).resolves.toMatchObject({ revoked: true })
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:7345/v1/sessions/sess-1/revoke',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ reason: 'operator disabled' }),
      })
    )
  })

  it('reads registry cards through agentd', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => JSON.stringify({
        did: 'did:fides:agent',
        card: {
          id: 'did:fides:agent',
          name: 'Payment Agent',
          version: '1.0.0',
        },
      }),
    })

    await expect(client.getCard('did:fides:agent')).resolves.toMatchObject({
      did: 'did:fides:agent',
      card: {
        id: 'did:fides:agent',
        name: 'Payment Agent',
      },
    })

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:7345/v1/cards/did%3Afides%3Aagent',
      expect.objectContaining({ method: 'GET' })
    )
    const [, init] = mockFetch.mock.calls[0]
    expect((init.headers as Headers).get('X-API-Key')).toBe('sdk-key')
  })

  it('verifies domain bindings through agentd', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => JSON.stringify({
        domain: 'example.com',
        did: 'did:fides:agent',
        recordName: '_fides.example.com',
        verified: true,
      }),
    })

    await expect(client.verifyDomain('example.com', 'did:fides:agent')).resolves.toMatchObject({
      domain: 'example.com',
      did: 'did:fides:agent',
      verified: true,
    })

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:7345/v1/identities/domain/verify?domain=example.com&did=did%3Afides%3Aagent',
      expect.objectContaining({ method: 'GET' })
    )
  })

  it('preserves private and missing registry card errors', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: false,
        status: 403,
        text: async () => JSON.stringify({
          did: 'did:fides:private',
          card: null,
          error: 'private card - access denied',
        }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 404,
        text: async () => JSON.stringify({
          did: 'did:fides:missing',
          card: null,
          error: 'not found',
        }),
      })

    await expect(client.getCard('did:fides:private')).rejects.toMatchObject({
      name: 'AgentdError',
      status: 403,
      payload: {
        did: 'did:fides:private',
        card: null,
        error: 'private card - access denied',
      },
    } satisfies Partial<AgentdError>)
    await expect(client.getCard('did:fides:missing')).rejects.toMatchObject({
      name: 'AgentdError',
      status: 404,
      payload: {
        did: 'did:fides:missing',
        card: null,
        error: 'not found',
      },
    } satisfies Partial<AgentdError>)
  })

  it('creates signed sessions from authority inputs', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => JSON.stringify({ authorized: true, session: { id: 'sess-1', token, sessionKey: 'redacted', expiresAt: token.expiresAt } }),
    })

    await expect(client.createSignedSession({
      delegator: 'did:fides:principal',
      delegatee: 'did:fides:agent',
      capabilities: ['payments.execute'],
      privateKey: privateKeyHex,
      capabilityId: 'payments.execute',
      tokenExpiresAt: '2026-01-01T01:00:00.000Z',
    })).resolves.toMatchObject({ authorized: true })

    const [, init] = mockFetch.mock.calls[0]
    const body = JSON.parse(init.body as string)
    expect(body.capabilityId).toBe('payments.execute')
    expect(body.audience).toBe('agentd')
    expect(body.delegatorPublicKey).toMatch(/^[0-9a-f]{64}$/)
    expect(body.token).toMatchObject({
      delegator: 'did:fides:principal',
      delegatee: 'did:fides:agent',
      capabilities: ['payments.execute'],
      expiresAt: '2026-01-01T01:00:00.000Z',
      audience: ['agentd'],
    })
    expect(body.token.signature).toMatch(/^[0-9a-f]{128}$/)
  })

  it('records and reads authority revocations', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ revoked: true, record: revocation }),
      })
      .mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ did: revocation.did, revoked: true, record: revocation }),
      })

    await expect(client.recordRevocation({
      record: revocation,
      revokerPublicKey: '22'.repeat(32),
    })).resolves.toMatchObject({ revoked: true })
    await expect(client.getRevocation(revocation.did)).resolves.toMatchObject({ revoked: true })

    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      'http://localhost:7345/v1/revocations',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ record: revocation, revokerPublicKey: '22'.repeat(32) }),
      })
    )
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      'http://localhost:7345/v1/revocations/did%3Afides%3Aagent',
      expect.objectContaining({ method: 'GET' })
    )
  })

  it('records signed authority revocations from revocation inputs', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => JSON.stringify({ revoked: true, record: revocation }),
    })

    await expect(client.recordSignedRevocation({
      did: 'did:fides:agent',
      reason: 'disabled',
      revokedBy: 'did:fides:principal',
      privateKey: privateKeyHex,
    })).resolves.toMatchObject({ revoked: true })

    const [, init] = mockFetch.mock.calls[0]
    const body = JSON.parse(init.body as string)
    expect(body.revokerPublicKey).toMatch(/^[0-9a-f]{64}$/)
    expect(body.record).toMatchObject({
      did: 'did:fides:agent',
      reason: 'disabled',
      revokedBy: 'did:fides:principal',
      propagatedTo: [],
    })
    expect(body.record.signature).toMatch(/^[0-9a-f]{128}$/)
  })

  it('records and lists authority incidents', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ recorded: true, record: incident, impact: { incidentCount: 1 } }),
      })
      .mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ did: incident.actor, incidents: [incident], impact: { incidentCount: 1 } }),
      })

    await expect(client.recordIncident({
      record: incident,
      reporterPublicKey: '33'.repeat(32),
    })).resolves.toMatchObject({ recorded: true })
    await expect(client.listIncidents(incident.actor)).resolves.toMatchObject({ incidents: [{ id: 'inc-1' }] })

    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      'http://localhost:7345/v1/incidents',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ record: incident, reporterPublicKey: '33'.repeat(32) }),
      })
    )
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      'http://localhost:7345/v1/incidents/did%3Afides%3Aagent',
      expect.objectContaining({ method: 'GET' })
    )
  })

  it('records signed authority incidents from incident inputs', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => JSON.stringify({ recorded: true, record: incident, impact: { incidentCount: 1 } }),
    })

    await expect(client.recordSignedIncident({
      actor: 'did:fides:agent',
      reportedBy: 'did:fides:principal',
      type: 'policy_violation',
      severity: 'high',
      description: 'policy bypass',
      evidenceRefs: ['ev-1'],
      capabilitiesRevoked: ['payments.execute'],
      privateKey: privateKeyHex,
    })).resolves.toMatchObject({ recorded: true })

    const [, init] = mockFetch.mock.calls[0]
    const body = JSON.parse(init.body as string)
    expect(body.reporterPublicKey).toMatch(/^[0-9a-f]{64}$/)
    expect(body.record).toMatchObject({
      actor: 'did:fides:agent',
      reportedBy: 'did:fides:principal',
      type: 'policy_violation',
      severity: 'high',
      description: 'policy bypass',
      evidenceRefs: ['ev-1'],
      impact: expect.objectContaining({
        capabilitiesRevoked: ['payments.execute'],
      }),
    })
    expect(body.record.signature).toMatch(/^[0-9a-f]{128}$/)
  })

  it('posts authorization checks with API key auth', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => JSON.stringify({ decision: 'allow', explanation: 'allowed' }),
    })

    const result = await client.authorize({
      agentDid: 'did:fides:agent',
      capabilityId: 'payments.execute',
      sessionId: 'sess-1',
      audience: 'agentd',
      context: { amount: '12.00' },
      requiresApproval: true,
      approvalGranted: true,
    })

    expect(result.decision).toBe('allow')
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:7345/v1/authorize',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          agentDid: 'did:fides:agent',
          capabilityId: 'payments.execute',
          sessionId: 'sess-1',
          audience: 'agentd',
          context: { amount: '12.00' },
          requiresApproval: true,
          approvalGranted: true,
        }),
      })
    )
    const [, init] = mockFetch.mock.calls[0]
    expect((init.headers as Headers).get('Content-Type')).toBe('application/json')
    expect((init.headers as Headers).get('X-API-Key')).toBe('sdk-key')
  })

  it('lists pending authority propagations', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => JSON.stringify({ count: 1, propagations: [{ id: 'prop-1' }] }),
    })

    const result = await client.listPendingPropagations(5)

    expect(result.count).toBe(1)
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:7345/v1/authority/propagations/pending?limit=5',
      expect.objectContaining({ method: 'GET' })
    )
  })

  it('retries due authority propagations', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => JSON.stringify({
        attempted: 1,
        results: [{ id: 'prop-1', ok: true, status: 200, outboxStatus: 'confirmed' }],
      }),
    })

    const result = await client.retryPropagations(3)

    expect(result.attempted).toBe(1)
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:7345/v1/authority/propagations/retry',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ limit: 3 }),
      })
    )
  })

  it('throws typed errors with status and payload', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      text: async () => JSON.stringify({ error: 'denied' }),
    })

    await expect(client.authorize({
      agentDid: 'did:fides:agent',
      capabilityId: 'payments.execute',
    })).rejects.toMatchObject({
      name: 'AgentdError',
      status: 403,
      payload: { error: 'denied' },
    } satisfies Partial<AgentdError>)
  })
})
