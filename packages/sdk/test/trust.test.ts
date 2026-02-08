import { describe, it, expect, beforeEach, vi } from 'vitest'
import { generateKeyPair } from '../src/identity/keypair.js'
import { generateDID } from '../src/identity/did.js'
import { createAttestation, verifyAttestation } from '../src/trust/attestation.js'
import { TrustClient } from '../src/trust/client.js'
import { TrustLevel } from '../src/trust/types.js'
import type { TrustScore, TrustPath } from '@fides/shared'
import { TrustError } from '@fides/shared'

describe('Trust Attestation', () => {
  it('should create a valid attestation', async () => {
    const issuerKeyPair = await generateKeyPair()
    const subjectKeyPair = await generateKeyPair()
    const issuerDid = generateDID(issuerKeyPair.publicKey)
    const subjectDid = generateDID(subjectKeyPair.publicKey)

    const attestation = await createAttestation(
      issuerDid,
      subjectDid,
      TrustLevel.HIGH,
      issuerKeyPair.privateKey
    )

    expect(attestation.issuerDid).toBe(issuerDid)
    expect(attestation.subjectDid).toBe(subjectDid)
    expect(attestation.trustLevel).toBe(TrustLevel.HIGH)
    expect(attestation.id).toBeTruthy()
    expect(attestation.issuedAt).toBeTruthy()
    expect(attestation.signature).toBeTruthy()
    expect(attestation.payload).toBeTruthy()
  })

  it('should verify attestation with correct key', async () => {
    const issuerKeyPair = await generateKeyPair()
    const subjectKeyPair = await generateKeyPair()
    const issuerDid = generateDID(issuerKeyPair.publicKey)
    const subjectDid = generateDID(subjectKeyPair.publicKey)

    const attestation = await createAttestation(
      issuerDid,
      subjectDid,
      TrustLevel.MEDIUM,
      issuerKeyPair.privateKey
    )

    const valid = await verifyAttestation(attestation, issuerKeyPair.publicKey)
    expect(valid).toBe(true)
  })

  it('should fail verification with wrong key', async () => {
    const issuerKeyPair = await generateKeyPair()
    const wrongKeyPair = await generateKeyPair()
    const subjectKeyPair = await generateKeyPair()
    const issuerDid = generateDID(issuerKeyPair.publicKey)
    const subjectDid = generateDID(subjectKeyPair.publicKey)

    const attestation = await createAttestation(
      issuerDid,
      subjectDid,
      TrustLevel.LOW,
      issuerKeyPair.privateKey
    )

    const valid = await verifyAttestation(attestation, wrongKeyPair.publicKey)
    expect(valid).toBe(false)
  })

  it('should detect tampered attestation', async () => {
    const issuerKeyPair = await generateKeyPair()
    const subjectKeyPair = await generateKeyPair()
    const issuerDid = generateDID(issuerKeyPair.publicKey)
    const subjectDid = generateDID(subjectKeyPair.publicKey)

    const attestation = await createAttestation(
      issuerDid,
      subjectDid,
      TrustLevel.HIGH,
      issuerKeyPair.privateKey
    )

    // Tamper with the payload
    const tamperedAttestation = {
      ...attestation,
      payload: attestation.payload.replace(
        `"trustLevel":${TrustLevel.HIGH}`,
        `"trustLevel":${TrustLevel.ABSOLUTE}`
      ),
    }

    const valid = await verifyAttestation(
      tamperedAttestation,
      issuerKeyPair.publicKey
    )
    expect(valid).toBe(false)
  })

  it('should create attestation with all trust levels', async () => {
    const issuerKeyPair = await generateKeyPair()
    const subjectKeyPair = await generateKeyPair()
    const issuerDid = generateDID(issuerKeyPair.publicKey)
    const subjectDid = generateDID(subjectKeyPair.publicKey)

    for (const level of [
      TrustLevel.NONE,
      TrustLevel.LOW,
      TrustLevel.MEDIUM,
      TrustLevel.HIGH,
      TrustLevel.ABSOLUTE,
    ]) {
      const attestation = await createAttestation(
        issuerDid,
        subjectDid,
        level,
        issuerKeyPair.privateKey
      )

      expect(attestation.trustLevel).toBe(level)

      const valid = await verifyAttestation(attestation, issuerKeyPair.publicKey)
      expect(valid).toBe(true)
    }
  })

  it('should create unique attestation IDs', async () => {
    const issuerKeyPair = await generateKeyPair()
    const subjectKeyPair = await generateKeyPair()
    const issuerDid = generateDID(issuerKeyPair.publicKey)
    const subjectDid = generateDID(subjectKeyPair.publicKey)

    const attestation1 = await createAttestation(
      issuerDid,
      subjectDid,
      TrustLevel.MEDIUM,
      issuerKeyPair.privateKey
    )

    const attestation2 = await createAttestation(
      issuerDid,
      subjectDid,
      TrustLevel.MEDIUM,
      issuerKeyPair.privateKey
    )

    expect(attestation1.id).not.toBe(attestation2.id)
  })
})

describe('TrustClient', () => {
  let client: TrustClient
  const mockFetch = vi.fn()

  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch)
    mockFetch.mockReset()
    client = new TrustClient({ baseUrl: 'http://localhost:3001' })
  })

  it('should submit attestation', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
    })

    await client.attest(
      'did:fides:issuer123',
      'did:fides:subject456',
      TrustLevel.HIGH,
      'deadbeef'
    )

    expect(mockFetch).toHaveBeenCalledWith('http://localhost:3001/v1/trust', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        issuerDid: 'did:fides:issuer123',
        subjectDid: 'did:fides:subject456',
        trustLevel: TrustLevel.HIGH,
        signature: 'deadbeef',
      }),
    })
  })

  it('should throw error on attestation failure', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      text: async () => 'Invalid attestation',
    })

    await expect(
      client.attest(
        'did:fides:issuer123',
        'did:fides:subject456',
        TrustLevel.HIGH,
        'deadbeef'
      )
    ).rejects.toThrow(TrustError)
  })

  it('should get trust score', async () => {
    const score: TrustScore = {
      did: 'did:fides:abc123',
      score: 0.75,
      directTrusters: 5,
      transitiveTrusters: 12,
      lastComputed: '2024-01-01T00:00:00Z',
    }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => score,
    })

    const result = await client.getScore('did:fides:abc123')

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:3001/v1/trust/did%3Afides%3Aabc123/score'
    )
    expect(result).toEqual(score)
  })

  it('should throw error on score failure', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      text: async () => 'Not found',
    })

    await expect(client.getScore('did:fides:nonexistent')).rejects.toThrow(
      TrustError
    )
  })

  it('should get trust path', async () => {
    const path: TrustPath = {
      from: 'did:fides:alice',
      to: 'did:fides:bob',
      found: true,
      path: ['did:fides:alice', 'did:fides:charlie', 'did:fides:bob'],
      cumulativeTrust: 0.64,
      hops: 2,
    }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => path,
    })

    const result = await client.getPath('did:fides:alice', 'did:fides:bob')

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:3001/v1/trust/did%3Afides%3Aalice/did%3Afides%3Abob'
    )
    expect(result).toEqual(path)
  })

  it('should throw error on path failure', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      text: async () => 'Server error',
    })

    await expect(
      client.getPath('did:fides:alice', 'did:fides:bob')
    ).rejects.toThrow(TrustError)
  })
})
