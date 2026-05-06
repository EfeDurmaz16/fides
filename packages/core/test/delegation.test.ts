import { describe, it, expect } from 'vitest'
import {
  createSessionGrant,
  validateSessionGrant,
  deriveEd25519PublicKeyHex,
  deriveSessionPublicKey,
  revokeSession,
  createDelegationToken,
  signDelegationToken,
} from '../src/delegation.js'
import * as ed from '@noble/ed25519'

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
