import { describe, it, expect, beforeEach, vi } from 'vitest'
import { DiscoveryClient } from '../src/discovery/client.js'
import { IdentityResolver } from '../src/discovery/resolver.js'
import type { AgentIdentity, DiscoveryDocument } from '@fides/shared'
import { DiscoveryError } from '@fides/shared'

describe('DiscoveryClient', () => {
  let client: DiscoveryClient
  const mockFetch = vi.fn()

  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch)
    mockFetch.mockReset()
    client = new DiscoveryClient({ baseUrl: 'http://localhost:3000' })
  })

  it('should register an identity', async () => {
    const identity = {
      did: 'did:fides:abc123',
      publicKey: 'deadbeef',
      metadata: { name: 'Test Agent' },
    }

    const response: AgentIdentity = {
      ...identity,
      algorithm: 'ed25519',
      createdAt: '2024-01-01T00:00:00Z',
    }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => response,
    })

    const result = await client.register(identity)

    expect(mockFetch).toHaveBeenCalledWith('http://localhost:3000/identities', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(identity),
    })
    expect(result).toEqual(response)
  })

  it('should throw error on registration failure', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      text: async () => 'Bad request',
    })

    await expect(
      client.register({
        did: 'did:fides:abc123',
        publicKey: 'deadbeef',
      })
    ).rejects.toThrow(DiscoveryError)
  })

  it('should resolve an identity', async () => {
    const identity: AgentIdentity = {
      did: 'did:fides:abc123',
      publicKey: 'deadbeef',
      algorithm: 'ed25519',
      createdAt: '2024-01-01T00:00:00Z',
    }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => identity,
    })

    const result = await client.resolve('did:fides:abc123')

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:3000/identities/did%3Afides%3Aabc123'
    )
    expect(result).toEqual(identity)
  })

  it('should return null for 404 on resolve', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
    })

    const result = await client.resolve('did:fides:nonexistent')
    expect(result).toBeNull()
  })

  it('should throw error on resolve failure', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      text: async () => 'Server error',
    })

    await expect(client.resolve('did:fides:abc123')).rejects.toThrow(
      DiscoveryError
    )
  })

  it('should resolve from well-known endpoint', async () => {
    const document: DiscoveryDocument = {
      did: 'did:fides:abc123',
      publicKey: 'deadbeef',
      algorithm: 'ed25519',
      endpoints: {
        discovery: 'http://localhost:3000',
      },
      createdAt: '2024-01-01T00:00:00Z',
    }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => document,
    })

    const result = await client.resolveFromWellKnown('example.com')

    expect(mockFetch).toHaveBeenCalledWith(
      'https://example.com/.well-known/fides.json'
    )
    expect(result).toEqual(document)
  })

  it('should return null for 404 on well-known', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
    })

    const result = await client.resolveFromWellKnown('example.com')
    expect(result).toBeNull()
  })
})

describe('IdentityResolver', () => {
  let resolver: IdentityResolver
  const mockFetch = vi.fn()

  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch)
    mockFetch.mockReset()
    resolver = new IdentityResolver({
      discoveryUrl: 'http://localhost:3000',
      cacheTtlMs: 1000, // 1 second for testing
    })
  })

  it('should resolve DID via discovery service', async () => {
    const identity: AgentIdentity = {
      did: 'did:fides:abc123',
      publicKey: 'deadbeef',
      algorithm: 'ed25519',
      createdAt: '2024-01-01T00:00:00Z',
    }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => identity,
    })

    const result = await resolver.resolve('did:fides:abc123')

    expect(result).toEqual(identity)
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:3000/identities/did%3Afides%3Aabc123'
    )
  })

  it('should resolve domain via well-known', async () => {
    const document: DiscoveryDocument = {
      did: 'did:fides:abc123',
      publicKey: 'deadbeef',
      algorithm: 'ed25519',
      endpoints: {
        discovery: 'http://localhost:3000',
      },
      createdAt: '2024-01-01T00:00:00Z',
    }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => document,
    })

    const result = await resolver.resolve('example.com')

    expect(mockFetch).toHaveBeenCalledWith(
      'https://example.com/.well-known/fides.json'
    )
    expect(result).toMatchObject({
      did: document.did,
      publicKey: document.publicKey,
    })
  })

  it('should fallback to discovery service if well-known fails', async () => {
    const identity: AgentIdentity = {
      did: 'example.com',
      publicKey: 'deadbeef',
      algorithm: 'ed25519',
      createdAt: '2024-01-01T00:00:00Z',
    }

    // Well-known returns 404
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
    })

    // Discovery service returns identity
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => identity,
    })

    const result = await resolver.resolve('example.com')

    expect(result).toEqual(identity)
    expect(mockFetch).toHaveBeenCalledTimes(2)
  })

  it('should cache resolved identities', async () => {
    const identity: AgentIdentity = {
      did: 'did:fides:abc123',
      publicKey: 'deadbeef',
      algorithm: 'ed25519',
      createdAt: '2024-01-01T00:00:00Z',
    }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => identity,
    })

    // First call
    const result1 = await resolver.resolve('did:fides:abc123')
    expect(result1).toEqual(identity)
    expect(mockFetch).toHaveBeenCalledTimes(1)

    // Second call should use cache
    const result2 = await resolver.resolve('did:fides:abc123')
    expect(result2).toEqual(identity)
    expect(mockFetch).toHaveBeenCalledTimes(1) // Still only 1 call
  })

  it('should expire cache after TTL', async () => {
    const identity: AgentIdentity = {
      did: 'did:fides:abc123',
      publicKey: 'deadbeef',
      algorithm: 'ed25519',
      createdAt: '2024-01-01T00:00:00Z',
    }

    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => identity,
    })

    // First call
    await resolver.resolve('did:fides:abc123')
    expect(mockFetch).toHaveBeenCalledTimes(1)

    // Wait for cache to expire
    await new Promise((resolve) => setTimeout(resolve, 1100))

    // Second call should fetch again
    await resolver.resolve('did:fides:abc123')
    expect(mockFetch).toHaveBeenCalledTimes(2)
  })

  it('should clear cache', async () => {
    const identity: AgentIdentity = {
      did: 'did:fides:abc123',
      publicKey: 'deadbeef',
      algorithm: 'ed25519',
      createdAt: '2024-01-01T00:00:00Z',
    }

    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => identity,
    })

    // First call
    await resolver.resolve('did:fides:abc123')
    expect(mockFetch).toHaveBeenCalledTimes(1)

    // Clear cache
    resolver.clearCache()

    // Second call should fetch again
    await resolver.resolve('did:fides:abc123')
    expect(mockFetch).toHaveBeenCalledTimes(2)
  })
})
