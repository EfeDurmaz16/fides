import { describe, expect, it } from 'vitest'
import {
  createOrganizationDomainVerificationChallenge,
  createDomainVerificationChallenge,
  normalizeTxtRecords,
  organizationPrincipalFromDomainVerification,
  publisherFromDomainVerification,
  verifyDomainDid,
  verifyOrganizationDomainDid,
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

  it('creates a DNS TXT challenge for an organization principal DID', () => {
    const challenge = createOrganizationDomainVerificationChallenge('Example.COM.', 'did:fides:org123')

    expect(challenge).toEqual({
      domain: 'example.com',
      did: 'did:fides:org123',
      recordName: '_fides-org.example.com',
      recordValue: 'fides-org-did=did:fides:org123',
    })
  })

  it('rejects invalid organization challenge inputs', () => {
    expect(() => createOrganizationDomainVerificationChallenge('https://example.com', 'did:fides:org123'))
      .toThrow('Invalid organization domain')
    expect(() => createOrganizationDomainVerificationChallenge('example.com', 'did:web:example.com'))
      .toThrow('Invalid FIDES DID')
  })

  it('verifies an organization principal DID when the expected TXT token is present', async () => {
    const result = await verifyOrganizationDomainDid({
      domain: 'example.com',
      did: 'did:fides:org123',
      resolver: async (recordName) => {
        expect(recordName).toBe('_fides-org.example.com')
        return [['fides-org-did=', 'did:fides:org123']]
      },
    })

    expect(result).toEqual({
      domain: 'example.com',
      did: 'did:fides:org123',
      recordName: '_fides-org.example.com',
      verified: true,
    })
  })

  it('returns typed organization verification failures', async () => {
    const missing = await verifyOrganizationDomainDid({
      domain: 'example.com',
      did: 'did:fides:org123',
      resolver: async () => ['fides-did=did:fides:org123'],
    })
    expect(missing.reason).toBe('record-not-found')

    const invalidDomain = await verifyOrganizationDomainDid({
      domain: 'https://example.com',
      did: 'did:fides:org123',
      resolver: async () => ['fides-org-did=did:fides:org123'],
    })
    expect(invalidDomain.reason).toBe('invalid-domain')

    const invalidDid = await verifyOrganizationDomainDid({
      domain: 'example.com',
      did: 'did:web:example.com',
      resolver: async () => ['fides-org-did=did:web:example.com'],
    })
    expect(invalidDid.reason).toBe('invalid-did')
  })

  it('creates a DNS-verified organization principal from verification result', async () => {
    const result = await verifyOrganizationDomainDid({
      domain: 'example.com',
      did: 'did:fides:org123',
      resolver: async () => ['fides-org-did=did:fides:org123'],
    })

    expect(organizationPrincipalFromDomainVerification(result, {
      did: 'did:fides:org123',
      displayName: 'Example Inc',
    })).toEqual({
      did: 'did:fides:org123',
      type: 'organization',
      displayName: 'Example Inc',
      domain: 'example.com',
      verified: true,
      verificationMethod: 'dns',
    })
  })

  it('rejects organization principal creation when DIDs do not match', async () => {
    const result = await verifyOrganizationDomainDid({
      domain: 'example.com',
      did: 'did:fides:org123',
      resolver: async () => ['fides-org-did=did:fides:org123'],
    })

    expect(() => organizationPrincipalFromDomainVerification(result, {
      did: 'did:fides:other',
      displayName: 'Example Inc',
    })).toThrow('Principal DID does not match verified organization DID')
  })
})
