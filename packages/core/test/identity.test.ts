import { describe, it, expect } from 'vitest'
import {
  createAgentIdentity,
  createIdentity,
  createPrincipalIdentity,
  createPublisherIdentity,
  didFromPublicKey,
  identityDisplayName,
  isValidFidesDid,
  publicKeyFromDid,
  validateIdentityKeyBinding,
} from '../src/identity.js'
import type { AgentIdentity, PrincipalIdentity, PublisherIdentity } from '../src/identity.js'

describe('Identity v2', () => {
  describe('isValidFidesDid', () => {
    it('should accept valid did:fides', () => {
      expect(isValidFidesDid('did:fides:abc123')).toBe(true)
    })

    it('should reject invalid DID', () => {
      expect(isValidFidesDid('did:other:abc')).toBe(false)
      expect(isValidFidesDid('')).toBe(false)
    })
  })

  describe('cryptographic issuance', () => {
    it('creates an agent identity whose DID is bound to the Ed25519 public key', async () => {
      const issued = await createAgentIdentity({
        trustAnchors: [
          { type: 'github', value: 'EfeDurmaz16', verified: true, verifiedAt: '2026-05-29T00:00:00.000Z' },
        ],
      })

      expect(issued.privateKey).toBeInstanceOf(Uint8Array)
      expect(issued.privateKey.length).toBe(32)
      expect(issued.publicKey.length).toBe(32)
      expect(issued.identity.did).toBe(didFromPublicKey(issued.publicKey))
      expect(validateIdentityKeyBinding(issued.identity)).toBe(true)
      expect(issued.identity.trustAnchors?.[0]).toMatchObject({ type: 'github', verified: true })
    })

    it('round-trips public keys through did:fides identifiers', async () => {
      const issued = await createAgentIdentity()

      expect(publicKeyFromDid(issued.identity.did)).toEqual(issued.identity.publicKey)
    })

    it('creates publisher identities with explicit publisher type', async () => {
      const issued = await createPublisherIdentity({
        name: 'Example Publisher',
        publisherType: 'domain_verified',
        verificationMethod: 'dns',
        verified: true,
        domain: 'example.com',
      })

      expect(issued.identity.publisherType).toBe('domain_verified')
      expect(issued.identity.verificationMethod).toBe('dns')
      expect(issued.identity.domain).toBe('example.com')
      expect(isValidFidesDid(issued.identity.did)).toBe(true)
    })

    it('creates domainless principal identities', async () => {
      const issued = await createPrincipalIdentity({
        type: 'individual',
        displayName: 'Alice',
        verificationMethod: 'self_signed',
      })

      expect(issued.identity.displayName).toBe('Alice')
      expect(issued.identity.domain).toBeUndefined()
      expect(issued.identity.verificationMethod).toBe('self_signed')
      expect(isValidFidesDid(issued.identity.did)).toBe(true)
    })

    it('keeps deprecated createIdentity compatible while decoding real did keys', async () => {
      const issued = await createAgentIdentity()
      const identity = createIdentity(issued.identity.did, 'agent')

      expect(identity.publicKey).toEqual(issued.identity.publicKey)
      expect(validateIdentityKeyBinding(identity)).toBe(true)
    })

    it('rejects deprecated createIdentity calls when the DID cannot bind to a public key', () => {
      expect(() => createIdentity('did:fides:not-a-valid-key', 'agent')).toThrow(
        'Invalid FIDES DID public key encoding'
      )
    })
  })

  describe('identityDisplayName', () => {
    it('should return displayName for principal', () => {
      const principal: PrincipalIdentity = {
        did: 'did:fides:p1',
        type: 'individual',
        displayName: 'Alice',
      }
      expect(identityDisplayName(principal)).toBe('Alice')
    })

    it('should support verified organization principals', () => {
      const principal: PrincipalIdentity = {
        did: 'did:fides:org1',
        type: 'organization',
        displayName: 'Example Inc',
        domain: 'example.com',
        verified: true,
        verificationMethod: 'dns',
      }
      expect(identityDisplayName(principal)).toBe('Example Inc')
    })

    it('should return name for publisher', () => {
      const publisher: PublisherIdentity = {
        did: 'did:fides:pub1',
        name: 'Acme Corp',
        verified: false,
        verificationMethod: 'manual',
      }
      expect(identityDisplayName(publisher)).toBe('Acme Corp')
    })

    it('should fallback to truncated DID for agent', () => {
      const agent: AgentIdentity = {
        did: 'did:fides:abcdefghijklmnopqrstuvwxyz',
        publicKey: new Uint8Array(32),
        keyType: 'Ed25519',
        createdAt: new Date().toISOString(),
      }
      expect(identityDisplayName(agent)).toContain('...')
    })
  })
})
