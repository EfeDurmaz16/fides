import { describe, it, expect } from 'vitest'
import { canonicalJson, canonicalDigest, signObject, verifyObject } from '../src/canonical-signer.js'
import * as ed from '@noble/ed25519'
import bs58 from 'bs58'

describe('Canonical Signer', () => {
  describe('canonicalJson', () => {
    it('should produce deterministic JSON', () => {
      const obj = { b: 2, a: 1 }
      expect(canonicalJson(obj)).toBe('{"a":1,"b":2}')
    })

    it('should preserve nulls', () => {
      const obj = { a: null, b: 'value' }
      expect(canonicalJson(obj)).toBe('{"a":null,"b":"value"}')
    })

    it('should sort nested keys', () => {
      const obj = { z: { b: 1, a: 2 } }
      expect(canonicalJson(obj)).toBe('{"z":{"a":2,"b":1}}')
    })
  })

  describe('canonicalDigest', () => {
    it('should produce a 32-byte digest', () => {
      const digest = canonicalDigest({ test: true })
      expect(digest).toBeInstanceOf(Uint8Array)
      expect(digest.length).toBe(32)
    })

    it('should be deterministic', () => {
      const d1 = canonicalDigest({ a: 1, b: 2 })
      const d2 = canonicalDigest({ b: 2, a: 1 })
      expect(d1).toEqual(d2)
    })
  })

  describe('signObject / verifyObject', () => {
    it('should sign and verify a payload', async () => {
      const privKey = ed.utils.randomPrivateKey()
      const pubKey = await ed.getPublicKeyAsync(privKey)
      const did = `did:fides:${bs58.encode(pubKey)}`

      const payload = { message: 'hello' }
      const signed = await signObject(payload, privKey, {
        verificationMethod: did,
        proofPurpose: 'assertionMethod',
      })

      expect(signed.payload).toEqual(payload)
      expect(signed.proof.verificationMethod).toBe(did)

      const valid = await verifyObject(signed)
      expect(valid).toBe(true)
    })

    it('should reject tampered payload', async () => {
      const privKey = ed.utils.randomPrivateKey()
      const pubKey = await ed.getPublicKeyAsync(privKey)
      const did = `did:fides:${bs58.encode(pubKey)}`

      const signed = await signObject({ message: 'hello' }, privKey, {
        verificationMethod: did,
      })

      signed.payload = { message: 'tampered' } as any
      const valid = await verifyObject(signed)
      expect(valid).toBe(false)
    })
  })
})
