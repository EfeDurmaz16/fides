import { describe, expect, it } from 'vitest'
import {
  createTrustAnchorDistribution,
  validateTrustAnchor,
  type GovernedTrustAnchor,
} from '../src/trust-anchor.js'

const baseAnchor: GovernedTrustAnchor = {
  did: 'did:fides:anchor-01',
  name: 'Example Trust Anchor',
  publicKey: new Uint8Array(32).fill(7),
  attestation: {
    payload: { issuerDid: 'did:fides:root' },
    proof: {
      type: 'Ed25519Signature2024',
      created: '2026-01-01T00:00:00.000Z',
      verificationMethod: 'did:fides:root#key-1',
      proofPurpose: 'assertionMethod',
      canonicalizationAlgorithm: 'https://fides.dev/canonical-json/v1',
      proofValue: 'sig',
    },
  },
  status: 'active',
  scopes: ['identity.organization', 'publisher.domain'],
  issuerDid: 'did:fides:root',
  createdAt: '2026-01-01T00:00:00.000Z',
}

describe('trust anchor governance', () => {
  it('accepts active anchors that satisfy scope and issuer policy', () => {
    const result = validateTrustAnchor(baseAnchor, {
      requiredScope: 'identity.organization',
      trustedIssuerDids: ['did:fides:root'],
      now: '2026-01-02T00:00:00.000Z',
    })

    expect(result).toEqual({ valid: true, errors: [] })
  })

  it('rejects suspended, expired, or out-of-scope anchors', () => {
    const result = validateTrustAnchor({
      ...baseAnchor,
      status: 'suspended',
      scopes: ['publisher.domain'],
      expiresAt: '2026-01-01T12:00:00.000Z',
      reason: 'incident review',
    }, {
      requiredScope: 'identity.organization',
      now: '2026-01-02T00:00:00.000Z',
    })

    expect(result.valid).toBe(false)
    expect(result.errors).toContain('trust anchor is suspended')
    expect(result.errors).toContain('trust anchor has expired')
    expect(result.errors).toContain('trust anchor is not authorized for scope identity.organization')
  })

  it('requires revoked anchors to carry revocation time', () => {
    const result = validateTrustAnchor({
      ...baseAnchor,
      status: 'revoked',
      reason: 'key compromise',
    })

    expect(result.valid).toBe(false)
    expect(result.errors).toContain('revoked trust anchors must include revokedAt')
    expect(result.errors).toContain('trust anchor is revoked')
  })

  it('creates deterministic distributions from valid active anchors only', () => {
    const distribution = createTrustAnchorDistribution([
      {
        ...baseAnchor,
        did: 'did:fides:anchor-b',
        publicKey: new Uint8Array(32).fill(11),
        scopes: ['publisher.domain', 'identity.organization'],
      },
      {
        ...baseAnchor,
        did: 'did:fides:anchor-a',
        publicKey: new Uint8Array(32).fill(10),
        scopes: ['identity.organization'],
      },
      {
        ...baseAnchor,
        did: 'did:fides:anchor-revoked',
        status: 'revoked',
        revokedAt: '2026-01-02T00:00:00.000Z',
      },
    ], {
      issuerDid: 'did:fides:root',
      generatedAt: '2026-01-03T00:00:00.000Z',
      policy: { requiredScope: 'identity.organization' },
    })

    expect(distribution).toMatchObject({
      version: 'fides.trust-anchors.v1',
      generatedAt: '2026-01-03T00:00:00.000Z',
      issuerDid: 'did:fides:root',
    })
    expect(distribution.anchors.map(anchor => anchor.did)).toEqual([
      'did:fides:anchor-a',
      'did:fides:anchor-b',
    ])
    expect(distribution.anchors[0].publicKey).toBe('0a'.repeat(32))
    expect(distribution.anchors[1].scopes).toEqual(['identity.organization', 'publisher.domain'])
  })
})
