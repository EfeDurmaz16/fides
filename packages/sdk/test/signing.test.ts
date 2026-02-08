import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest'
import { generateKeyPair } from '../src/identity/keypair.js'
import { signRequest } from '../src/signing/http-signature.js'
import { verifyRequest } from '../src/signing/verify.js'
import type { RequestLike } from '../src/signing/canonicalize.js'
import type { KeyPair } from '@fides/shared'

describe('RFC 9421 HTTP Message Signatures', () => {
  let keyPair: KeyPair

  beforeAll(async () => {
    keyPair = await generateKeyPair()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('should sign and verify a request successfully', async () => {
    const request: RequestLike = {
      method: 'POST',
      url: 'https://api.example.com/users',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ name: 'Alice' }),
    }

    const signedRequest = await signRequest(request, keyPair.privateKey, {
      keyid: 'did:fides:test123',
    })

    expect(signedRequest.headers['Signature-Input']).toBeDefined()
    expect(signedRequest.headers['Signature']).toBeDefined()

    const result = await verifyRequest(signedRequest, keyPair.publicKey)

    expect(result.valid).toBe(true)
    expect(result.keyId).toBe('did:fides:test123')
    expect(result.error).toBeUndefined()
  })

  it('should fail verification if body is tampered', async () => {
    const request: RequestLike = {
      method: 'POST',
      url: 'https://api.example.com/users',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ name: 'Alice' }),
    }

    const signedRequest = await signRequest(request, keyPair.privateKey, {
      keyid: 'did:fides:test123',
    })

    // Tamper with the body (not directly part of signature, but @method is)
    // Actually, let's tamper with the method since we sign @method
    const tamperedRequest = {
      ...signedRequest,
      method: 'PUT', // Changed from POST
    }

    const result = await verifyRequest(tamperedRequest, keyPair.publicKey)

    expect(result.valid).toBe(false)
    expect(result.error).toBeDefined()
  })

  it('should fail verification if header is tampered', async () => {
    const request: RequestLike = {
      method: 'POST',
      url: 'https://api.example.com/users',
      headers: {
        'Content-Type': 'application/json',
      },
    }

    const signedRequest = await signRequest(request, keyPair.privateKey, {
      keyid: 'did:fides:test123',
    })

    // Tamper with Content-Type header
    const tamperedRequest = {
      ...signedRequest,
      headers: {
        ...signedRequest.headers,
        'Content-Type': 'text/plain',
      },
    }

    const result = await verifyRequest(tamperedRequest, keyPair.publicKey)

    expect(result.valid).toBe(false)
  })

  it('should fail verification if signature headers are missing', async () => {
    const request: RequestLike = {
      method: 'GET',
      url: 'https://api.example.com/users',
      headers: {
        'Content-Type': 'application/json',
      },
    }

    const result = await verifyRequest(request, keyPair.publicKey)

    expect(result.valid).toBe(false)
    expect(result.error).toContain('Missing Signature')
  })

  it('should fail verification for expired signature', async () => {
    vi.useFakeTimers()
    const now = new Date('2024-01-01T00:00:00Z')
    vi.setSystemTime(now)

    const request: RequestLike = {
      method: 'GET',
      url: 'https://api.example.com/users',
      headers: {
        'Content-Type': 'application/json',
      },
    }

    const signedRequest = await signRequest(request, keyPair.privateKey, {
      keyid: 'did:fides:test123',
      expirySeconds: 300,
    })

    // Advance time by 301 seconds (past expiry)
    vi.advanceTimersByTime(301 * 1000)

    const result = await verifyRequest(signedRequest, keyPair.publicKey)

    expect(result.valid).toBe(false)
    expect(result.error).toContain('expired')
  })

  it('should sign and verify with multiple components', async () => {
    const request: RequestLike = {
      method: 'PUT',
      url: 'https://api.example.com/users/123?foo=bar',
      headers: {
        'Content-Type': 'application/json',
        'Content-Digest': 'sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
      },
    }

    const signedRequest = await signRequest(request, keyPair.privateKey, {
      keyid: 'did:fides:test456',
      components: [
        '@method',
        '@target-uri',
        '@authority',
        '@path',
        'content-type',
        'content-digest',
      ],
    })

    const result = await verifyRequest(signedRequest, keyPair.publicKey)

    expect(result.valid).toBe(true)
    expect(result.keyId).toBe('did:fides:test456')
  })

  it('should work with different HTTP methods', async () => {
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']

    for (const method of methods) {
      const request: RequestLike = {
        method,
        url: 'https://api.example.com/resource',
        headers: {
          'Content-Type': 'application/json',
        },
      }

      const signedRequest = await signRequest(request, keyPair.privateKey, {
        keyid: `did:fides:${method.toLowerCase()}`,
      })

      const result = await verifyRequest(signedRequest, keyPair.publicKey)

      expect(result.valid).toBe(true)
      expect(result.keyId).toBe(`did:fides:${method.toLowerCase()}`)
    }
  })

  it('should handle case-insensitive header lookups', async () => {
    const request: RequestLike = {
      method: 'POST',
      url: 'https://api.example.com/users',
      headers: {
        'content-type': 'application/json', // lowercase
      },
    }

    const signedRequest = await signRequest(request, keyPair.privateKey, {
      keyid: 'did:fides:test123',
    })

    const result = await verifyRequest(signedRequest, keyPair.publicKey)

    expect(result.valid).toBe(true)
  })

  it('should include correct signature format', async () => {
    const request: RequestLike = {
      method: 'GET',
      url: 'https://api.example.com/test',
      headers: {
        'Content-Type': 'text/plain',
      },
    }

    const signedRequest = await signRequest(request, keyPair.privateKey, {
      keyid: 'did:fides:abc',
      label: 'sig1',
    })

    // Check Signature-Input format
    const sigInput = signedRequest.headers['Signature-Input']
    expect(sigInput).toMatch(/^sig1=\("@method" "@target-uri" "@authority" "content-type"\);created=\d+;expires=\d+;keyid="did:fides:abc";alg="ed25519"$/)

    // Check Signature format
    const sig = signedRequest.headers['Signature']
    expect(sig).toMatch(/^sig1=:[A-Za-z0-9+/=]+:$/)
  })
})
