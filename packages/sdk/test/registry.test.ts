import { beforeEach, describe, expect, it, vi } from 'vitest'
import { RegistryClient, RegistryError } from '../src/registry/client.js'

describe('RegistryClient', () => {
  const mockFetch = vi.fn()
  let client: RegistryClient
  const card = {
    id: 'did:fides:agent',
    name: 'Registry Agent',
    version: '1.0.0',
    capabilities: [{ id: 'payments.execute', name: 'Payments' }],
    protocols: ['mcp'],
    endpoints: [],
    security: { authentication: ['api-key'], encryption: ['tls1.3'] },
    metadata: {},
  }

  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch)
    mockFetch.mockReset()
    client = new RegistryClient({ baseUrl: 'http://localhost:7346/', apiKey: 'registry-key' })
  })

  it('registers cards with API key auth', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 201,
      text: async () => JSON.stringify({ success: true, did: card.id, registeredAt: '2026-01-01T00:00:00.000Z' }),
    })

    await expect(client.register(card)).resolves.toMatchObject({ success: true, did: card.id })

    expect(mockFetch).toHaveBeenCalledWith('http://localhost:7346/v1/cards', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify(card),
      headers: expect.any(Headers),
    }))
    const headers = mockFetch.mock.calls[0][1].headers as Headers
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(headers.get('X-API-Key')).toBe('registry-key')
  })

  it('reads cards and returns null for missing DID', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify(card),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 404,
        text: async () => JSON.stringify({ error: 'Not found' }),
      })

    await expect(client.getCard(card.id)).resolves.toEqual(card)
    await expect(client.getCard('did:fides:missing')).resolves.toBeNull()

    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      'http://localhost:7346/v1/cards/did%3Afides%3Aagent',
      expect.objectContaining({ method: 'GET' })
    )
  })

  it('searches cards with encoded query terms', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({
        results: [{ did: card.id, name: card.name, capabilities: ['payments.execute'] }],
        count: 1,
        query: 'Registry Agent',
      }),
    })

    await expect(client.search('Registry Agent')).resolves.toMatchObject({ count: 1 })
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:7346/v1/search?q=Registry%20Agent',
      expect.objectContaining({ method: 'GET' })
    )
  })

  it('updates mode, metadata, delete, and stats endpoints', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ success: true, mode: 'private' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ success: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ total: 1, public: 0, private: 1 }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ success: true }),
      })

    await expect(client.setMode(card.id, 'private')).resolves.toMatchObject({ mode: 'private' })
    await expect(client.updateMetadata(card.id, { owner: 'ops' })).resolves.toMatchObject({ success: true })
    await expect(client.stats()).resolves.toEqual({ total: 1, public: 0, private: 1 })
    await expect(client.deleteCard(card.id)).resolves.toMatchObject({ success: true })

    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      'http://localhost:7346/v1/cards/did%3Afides%3Aagent/mode',
      expect.objectContaining({ method: 'POST', body: JSON.stringify({ mode: 'private' }) })
    )
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      'http://localhost:7346/v1/cards/did%3Afides%3Aagent/metadata',
      expect.objectContaining({ method: 'PATCH', body: JSON.stringify({ owner: 'ops' }) })
    )
    expect(mockFetch).toHaveBeenNthCalledWith(
      3,
      'http://localhost:7346/v1/stats',
      expect.objectContaining({ method: 'GET' })
    )
    expect(mockFetch).toHaveBeenNthCalledWith(
      4,
      'http://localhost:7346/v1/cards/did%3Afides%3Aagent',
      expect.objectContaining({ method: 'DELETE' })
    )
  })

  it('throws RegistryError with status and payload on API failures', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      text: async () => JSON.stringify({ error: 'Private card - access denied' }),
    })

    await expect(client.getCard(card.id)).rejects.toMatchObject({
      name: 'RegistryError',
      status: 403,
      payload: { error: 'Private card - access denied' },
    } satisfies Partial<RegistryError>)
  })
})
