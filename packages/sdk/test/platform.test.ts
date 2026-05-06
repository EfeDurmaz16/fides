import { beforeEach, describe, expect, it, vi } from 'vitest'
import { PlatformClient, PlatformError } from '../src/platform/client.js'

describe('PlatformClient', () => {
  const mockFetch = vi.fn()
  let client: PlatformClient
  const binding = {
    principalDid: 'did:fides:principal-platform-01',
    credentialId: 'credential-platform-01',
    publicKey: 'public-key-material',
    relyingPartyId: 'example.com',
    signCount: 1,
    transports: ['internal'] as const,
    backedUp: true,
    createdAt: '2026-01-01T00:00:00.000Z',
  }

  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch)
    mockFetch.mockReset()
    client = new PlatformClient({ baseUrl: 'http://localhost:3600/', apiKey: 'platform-key' })
  })

  it('reads platform topology with API key auth', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({
        service: 'platform-api',
        components: {
          discovery: 'http://localhost:3100',
          trustGraph: 'http://localhost:3200',
          policyEngine: 'http://localhost:3300',
          registry: 'http://localhost:7346',
          relay: 'http://localhost:7347',
          agentd: 'http://localhost:7345',
        },
      }),
    })

    await expect(client.topology()).resolves.toMatchObject({
      service: 'platform-api',
      components: { agentd: 'http://localhost:7345' },
    })
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:3600/v1/topology',
      expect.objectContaining({ method: 'GET', headers: expect.any(Headers) })
    )
    const headers = mockFetch.mock.calls[0][1].headers as Headers
    expect(headers.get('X-API-Key')).toBe('platform-key')
  })

  it('stores, lists, reads, and deletes passkey bindings', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 201,
        text: async () => JSON.stringify({ binding }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          principalDid: binding.principalDid,
          credentials: [{ credentialId: binding.credentialId, relyingPartyId: binding.relyingPartyId, signCount: 1, createdAt: binding.createdAt }],
          count: 1,
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ binding }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ success: true }),
      })

    await expect(client.storePasskeyBinding(binding)).resolves.toMatchObject({ binding })
    await expect(client.listPasskeyCredentials(binding.principalDid)).resolves.toMatchObject({ count: 1 })
    await expect(client.getPasskeyBinding(binding.credentialId)).resolves.toMatchObject(binding)
    await expect(client.deletePasskeyBinding(binding.credentialId)).resolves.toEqual({ success: true })

    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      'http://localhost:3600/v1/passkeys/bindings',
      expect.objectContaining({ method: 'POST', body: JSON.stringify(binding) })
    )
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      'http://localhost:3600/v1/passkeys/principals/did%3Afides%3Aprincipal-platform-01/credentials',
      expect.objectContaining({ method: 'GET' })
    )
    expect(mockFetch).toHaveBeenNthCalledWith(
      3,
      'http://localhost:3600/v1/passkeys/credentials/credential-platform-01',
      expect.objectContaining({ method: 'GET' })
    )
    expect(mockFetch).toHaveBeenNthCalledWith(
      4,
      'http://localhost:3600/v1/passkeys/credentials/credential-platform-01',
      expect.objectContaining({ method: 'DELETE' })
    )
  })

  it('returns null when a passkey binding is missing', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      text: async () => JSON.stringify({ error: 'passkey credential binding not found' }),
    })

    await expect(client.getPasskeyBinding('missing')).resolves.toBeNull()
  })

  it('throws PlatformError with status and payload on API failures', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 409,
      text: async () => JSON.stringify({ error: 'credential is already bound to a different principal' }),
    })

    await expect(client.storePasskeyBinding(binding)).rejects.toMatchObject({
      name: 'PlatformError',
      status: 409,
      payload: { error: 'credential is already bound to a different principal' },
    } satisfies Partial<PlatformError>)
  })
})
