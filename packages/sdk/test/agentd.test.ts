import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AgentdClient, AgentdError } from '../src/agentd/client.js'

describe('AgentdClient', () => {
  const mockFetch = vi.fn()
  let client: AgentdClient

  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch)
    mockFetch.mockReset()
    client = new AgentdClient({ baseUrl: 'http://localhost:7345/', apiKey: 'sdk-key' })
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
