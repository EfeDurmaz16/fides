import { beforeEach, describe, expect, it, vi } from 'vitest'
import { RelayClient, RelayError } from '../src/relay/client.js'

describe('RelayClient', () => {
  const mockFetch = vi.fn()
  let client: RelayClient
  const message = {
    id: 'relay-1',
    to: 'did:fides:receiver',
    from: 'did:fides:sender',
    payload: { hello: 'world' },
    status: 'pending' as const,
    createdAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2026-01-01T00:05:00.000Z',
  }

  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch)
    mockFetch.mockReset()
    client = new RelayClient({ baseUrl: 'http://localhost:7347/', apiKey: 'relay-key' })
  })

  it('sends messages with API key auth', async () => {
    const request = {
      to: message.to,
      from: message.from,
      payload: message.payload,
      ttlMs: 60_000,
    }
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 201,
      text: async () => JSON.stringify({ accepted: true, relayId: message.id, expiresAt: message.expiresAt }),
    })

    await expect(client.send(request)).resolves.toMatchObject({ accepted: true, relayId: message.id })

    expect(mockFetch).toHaveBeenCalledWith('http://localhost:7347/v1/relay', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify(request),
      headers: expect.any(Headers),
    }))
    const headers = mockFetch.mock.calls[0][1].headers as Headers
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(headers.get('X-API-Key')).toBe('relay-key')
  })

  it('polls queued messages and reads message status', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ messages: [message], count: 1 }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify(message),
      })

    await expect(client.poll(message.to)).resolves.toMatchObject({ count: 1 })
    await expect(client.getMessage(message.id)).resolves.toEqual(message)

    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      'http://localhost:7347/v1/relay/did%3Afides%3Areceiver/messages',
      expect.objectContaining({ method: 'GET' })
    )
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      'http://localhost:7347/v1/relay/relay-1',
      expect.objectContaining({ method: 'GET' })
    )
  })

  it('deletes messages and reads stats', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ deleted: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ total: 1, pending: 0, delivered: 1, expired: 0, queues: 0 }),
      })

    await expect(client.deleteMessage(message.id)).resolves.toEqual({ deleted: true })
    await expect(client.stats()).resolves.toMatchObject({ total: 1, delivered: 1 })

    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      'http://localhost:7347/v1/relay/relay-1',
      expect.objectContaining({ method: 'DELETE' })
    )
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      'http://localhost:7347/v1/relay/stats',
      expect.objectContaining({ method: 'GET' })
    )
  })

  it('throws RelayError with status and payload on API failures', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      text: async () => JSON.stringify({ error: 'Missing or invalid API key' }),
    })

    await expect(client.send({
      to: message.to,
      payload: message.payload,
    })).rejects.toMatchObject({
      name: 'RelayError',
      status: 401,
      payload: { error: 'Missing or invalid API key' },
    } satisfies Partial<RelayError>)
  })
})
