import { describe, expect, it } from 'vitest'
import {
  createDomainVerificationChallenge,
  normalizeTxtRecords,
  publisherFromDomainVerification,
  verifyDomainDid,
} from '../src/domain-verifier.js'

describe('domain DID verifier', () => {
  it('creates a DNS TXT challenge for a FIDES DID', () => {
    const challenge = createDomainVerificationChallenge('Example.COM.', 'did:fides:agent123')

    expect(challenge).toEqual({
      domain: 'example.com',
      did: 'did:fides:agent123',
      recordName: '_fides.example.com',
      recordValue: 'fides-did=did:fides:agent123',
    })
  })

  it('rejects invalid challenge inputs', () => {
    expect(() => createDomainVerificationChallenge('https://example.com', 'did:fides:agent123')).toThrow('Invalid domain')
    expect(() => createDomainVerificationChallenge('example.com', 'did:web:example.com')).toThrow('Invalid FIDES DID')
  })

  it('verifies a DID when the expected TXT token is present', async () => {
    const result = await verifyDomainDid({
      domain: 'example.com',
      did: 'did:fides:agent123',
      resolver: async (recordName) => {
        expect(recordName).toBe('_fides.example.com')
        return [['fides-did=', 'did:fides:agent123']]
      },
    })

    expect(result).toEqual({
      domain: 'example.com',
      did: 'did:fides:agent123',
      recordName: '_fides.example.com',
      verified: true,
    })
  })

  it('returns record-not-found when the TXT token is missing', async () => {
    const result = await verifyDomainDid({
      domain: 'example.com',
      did: 'did:fides:agent123',
      resolver: async () => ['other=value'],
    })

    expect(result).toEqual({
      domain: 'example.com',
      did: 'did:fides:agent123',
      recordName: '_fides.example.com',
      verified: false,
      reason: 'record-not-found',
    })
  })

  it('returns typed failures for invalid domains and DIDs', async () => {
    const invalidDomain = await verifyDomainDid({
      domain: 'https://example.com',
      did: 'did:fides:agent123',
      resolver: async () => ['fides-did=did:fides:agent123'],
    })
    expect(invalidDomain.reason).toBe('invalid-domain')

    const invalidDid = await verifyDomainDid({
      domain: 'example.com',
      did: 'did:web:example.com',
      resolver: async () => ['fides-did=did:web:example.com'],
    })
    expect(invalidDid.reason).toBe('invalid-did')
  })

  it('returns resolver-error when TXT resolution fails', async () => {
    const result = await verifyDomainDid({
      domain: 'example.com',
      did: 'did:fides:agent123',
      resolver: async () => {
        throw new Error('dns unavailable')
      },
    })

    expect(result).toEqual({
      domain: 'example.com',
      did: 'did:fides:agent123',
      recordName: '_fides.example.com',
      verified: false,
      reason: 'resolver-error',
    })
  })

  it('creates a DNS-verified publisher identity from verification result', async () => {
    const result = await verifyDomainDid({
      domain: 'example.com',
      did: 'did:fides:publisher1',
      resolver: async () => ['fides-did=did:fides:publisher1'],
    })

    expect(publisherFromDomainVerification(result, {
      did: 'did:fides:publisher1',
      name: 'Example Inc',
    })).toEqual({
      did: 'did:fides:publisher1',
      name: 'Example Inc',
      domain: 'example.com',
      verified: true,
      verificationMethod: 'dns',
    })
  })

  it('rejects publisher identity creation when DIDs do not match', async () => {
    const result = await verifyDomainDid({
      domain: 'example.com',
      did: 'did:fides:publisher1',
      resolver: async () => ['fides-did=did:fides:publisher1'],
    })

    expect(() => publisherFromDomainVerification(result, {
      did: 'did:fides:publisher2',
      name: 'Example Inc',
    })).toThrow('Publisher DID does not match verified DID')
  })

  it('normalizes Node-style and runtime-neutral TXT record shapes', () => {
    expect(normalizeTxtRecords([['fides-did=', 'did:fides:agent123'], ' other=value '])).toEqual([
      'fides-did=did:fides:agent123',
      'other=value',
    ])
  })
})
