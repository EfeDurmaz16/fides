import { describe, it, expect } from 'vitest'
import {
  createSessionGrant,
  validateSessionGrant,
  deriveEd25519PublicKeyHex,
  deriveSessionPublicKey,
  revokeSession,
  createDelegationToken,
  createDelegationTokenV2,
  signDelegationToken,
  signDelegationTokenV2,
  validateDelegationTokenV2,
  verifySignedDelegationTokenV2,
  verifySignedDelegationTokenV2Issuer,
} from '../src/delegation.js'
import * as ed from '@noble/ed25519'
import bs58 from 'bs58'

function makeValidToken(overrides: Record<string, unknown> = {}) {
  const token = createDelegationToken({
    delegator: 'did:fides:delegator',
    delegatee: 'did:fides:delegatee',
    capabilities: ['read', 'write'],
    constraints: {},
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    ...overrides,
  })
  return token
}

describe('SessionGrant', () => {
  describe('DelegationTokenV2', () => {
    it('creates canonical delegation token payloads with issuer-bound signatures', async () => {
      const privateKey = ed.utils.randomPrivateKey()
      const publicKey = await ed.getPublicKeyAsync(privateKey)
      const delegator = `did:fides:${bs58.encode(publicKey)}`

      const token = createDelegationTokenV2({
        delegator,
        delegatee: 'did:fides:delegatee',
        capabilities: ['invoice.reconcile'],
        constraints: { maxActions: 3 },
        audience: ['did:fides:delegatee'],
        issuedAt: '2026-05-30T00:00:00.000Z',
        expiresAt: '2026-05-31T00:00:00.000Z',
        nonce: 'nonce_123',
      })

      expect(token).toMatchObject({
        schema_version: 'fides.delegation_token.v1',
        issuer: delegator,
        subject: 'did:fides:delegatee',
        delegator,
        delegatee: 'did:fides:delegatee',
        capabilities: ['invoice.reconcile'],
        audience: ['did:fides:delegatee'],
        nonce: 'nonce_123',
      })
      expect(token.payload_hash).toMatch(/^sha256:[0-9a-f]{64}$/)
      expect(validateDelegationTokenV2(token, new Date('2026-05-30T00:00:01.000Z'))).toEqual({
        valid: true,
        errors: [],
      })

      const signed = await signDelegationTokenV2(token, privateKey, delegator)
      expect(signed.proof.proofPurpose).toBe('delegation')
      await expect(verifySignedDelegationTokenV2(signed)).resolves.toBe(true)
      await expect(verifySignedDelegationTokenV2Issuer(signed)).resolves.toBe(true)
    })

    it('rejects mutated delegation token v2 hashes and issuer mismatches', async () => {
      const privateKey = ed.utils.randomPrivateKey()
      const publicKey = await ed.getPublicKeyAsync(privateKey)
      const delegator = `did:fides:${bs58.encode(publicKey)}`
      const token = createDelegationTokenV2({
        delegator,
        delegatee: 'did:fides:delegatee',
        capabilities: ['calendar.schedule'],
        expiresAt: '2026-05-31T00:00:00.000Z',
      })

      const mutated = {
        ...token,
        capabilities: ['payments.execute'],
      }
      expect(validateDelegationTokenV2(mutated, new Date('2026-05-30T00:00:01.000Z'))).toMatchObject({
        valid: false,
        errors: ['DelegationToken.payload_hash mismatch'],
      })

      const otherPrivateKey = ed.utils.randomPrivateKey()
      const otherPublicKey = await ed.getPublicKeyAsync(otherPrivateKey)
      const signedByWrongIssuer = await signDelegationTokenV2(token, otherPrivateKey, `did:fides:${bs58.encode(otherPublicKey)}`)
      await expect(verifySignedDelegationTokenV2(signedByWrongIssuer)).resolves.toBe(true)
      await expect(verifySignedDelegationTokenV2Issuer(signedByWrongIssuer)).resolves.toBe(false)
    })
  })

  describe('createSessionGrant', () => {
    it('creates a valid session with default TTL (1 hour)', () => {
      const token = makeValidToken()
      const session = createSessionGrant({ token })

      expect(session.id).toBeDefined()
      expect(session.token).toBe(token)
      expect(session.sessionKey).toBeDefined()
      expect(session.sessionKey.length).toBe(64) // 32 bytes = 64 hex chars
      expect(session.expiresAt).toBeDefined()

      const expiresAt = new Date(session.expiresAt)
      const now = new Date()
      const diff = expiresAt.getTime() - now.getTime()
      expect(diff).toBeGreaterThan(3500_000)
      expect(diff).toBeLessThan(3700_000)
    })

    it('creates a session with custom TTL', () => {
      const token = makeValidToken()
      const ttlMs = 60_000
      const session = createSessionGrant({ token, ttlMs })

      const expiresAt = new Date(session.expiresAt)
      const now = new Date()
      const diff = expiresAt.getTime() - now.getTime()
      expect(diff).toBeGreaterThan(50_000)
      expect(diff).toBeLessThan(70_000)
    })

    it('includes boundTo when provided', () => {
      const token = makeValidToken()
      const session = createSessionGrant({ token, boundTo: 'did:fides:bound' })
      expect(session.boundTo).toBe('did:fides:bound')
    })
  })

  describe('validateSessionGrant', () => {
    it('returns valid for a correct session', async () => {
      const privateKey = ed.utils.randomPrivateKey()
      const publicKey = await ed.getPublicKeyAsync(privateKey)
      const token = makeValidToken({
        delegator: `did:fides:${Buffer.from(publicKey).toString('hex')}`,
      })
      const signed = await signDelegationToken(token, privateKey)
      const session = createSessionGrant({ token: signed })

      const result = validateSessionGrant(session)
      expect(result.valid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('catches expired sessions', () => {
      const token = makeValidToken()
      const session = createSessionGrant({ token, ttlMs: -1000 })

      const result = validateSessionGrant(session)
      expect(result.valid).toBe(false)
      expect(result.errors).toContain('SessionGrant is expired')
    })

    it('catches invalid embedded tokens', () => {
      const invalidToken = {
        id: '',
        delegator: '',
        delegatee: '',
        capabilities: [],
        constraints: {},
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        nonce: '',
        signature: '',
      }
      const session = createSessionGrant({ token: invalidToken as any })

      const result = validateSessionGrant(session)
      expect(result.valid).toBe(false)
      expect(result.errors.some(e => e.includes('DelegationToken.id is required'))).toBe(true)
      expect(result.errors.some(e => e.includes('DelegationToken.capabilities must not be empty'))).toBe(true)
      expect(result.errors.some(e => e.includes('DelegationToken.signature is required'))).toBe(true)
    })
  })

  describe('deriveSessionPublicKey', () => {
    it('derives correct public key from private key', async () => {
      const privateKey = ed.utils.randomPrivateKey()
      const expectedPublicKey = await ed.getPublicKeyAsync(privateKey)
      const expectedHex = Buffer.from(expectedPublicKey).toString('hex')

      const sessionKeyHex = Buffer.from(privateKey).toString('hex')
      const derivedPublicKey = await deriveSessionPublicKey(sessionKeyHex)

      expect(derivedPublicKey).toBe(expectedHex)
    })

    it('exposes a generic Ed25519 public key derivation helper', async () => {
      const privateKey = ed.utils.randomPrivateKey()
      const expectedPublicKey = await ed.getPublicKeyAsync(privateKey)

      await expect(deriveEd25519PublicKeyHex(Buffer.from(privateKey).toString('hex')))
        .resolves.toBe(Buffer.from(expectedPublicKey).toString('hex'))
    })
  })

  describe('revokeSession', () => {
    it('marks session as revoked', () => {
      const token = makeValidToken()
      const session = createSessionGrant({ token })

      const revoked = revokeSession(session)

      expect(revoked.revoked).toBe(true)
      expect(revoked.revokedAt).toBeDefined()
      expect(new Date(revoked.revokedAt).getTime()).toBeGreaterThan(0)
      expect(revoked.id).toBe(session.id)
      expect(revoked.sessionKey).toBe(session.sessionKey)
    })
  })
})
