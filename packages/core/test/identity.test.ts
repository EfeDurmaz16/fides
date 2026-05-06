import { describe, it, expect } from 'vitest'
import { isValidFidesDid, identityDisplayName } from '../src/identity.js'
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
