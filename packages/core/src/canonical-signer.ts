/**
 * Canonical Object Signing Model
 *
 * All signed protocol objects in FIDES v2 use this canonical signing model:
 * 1. Deterministic JSON canonicalization (sorted keys, no whitespace, explicit nulls)
 * 2. SHA-256 digest of canonical JSON
 * 3. Ed25519 signature of the digest
 *
 * This ensures that signatures are verifiable regardless of JSON serialization
 * differences between implementations.
 */

import * as ed from '@noble/ed25519'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'
import bs58 from 'bs58'

export interface SignedObject<T> {
  payload: T
  proof: {
    type: 'Ed25519Signature2024'
    created: string
    verificationMethod: string
    proofPurpose: 'assertionMethod' | 'authentication' | 'delegation' | 'capabilityInvocation'
    canonicalizationAlgorithm: 'https://fides.dev/canonical-json/v1'
    proofValue: string
  }
}

/**
 * Deterministic JSON canonicalization.
 * - Object keys are sorted lexicographically
 * - No insignificant whitespace
 * - null values are preserved
 * - Arrays preserve order
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(value, sortReplacer)
}

function sortReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const sorted: Record<string, unknown> = {}
    for (const k of Object.keys(value).sort()) {
      sorted[k] = (value as Record<string, unknown>)[k]
    }
    return sorted
  }
  return value
}

/**
 * Create the SHA-256 digest of canonical JSON.
 */
export function canonicalDigest(value: unknown): Uint8Array {
  const json = canonicalJson(value)
  return sha256(new TextEncoder().encode(json))
}

/**
 * Sign a payload using the canonical signing model.
 */
export async function signObject<T>(
  payload: T,
  privateKey: Uint8Array,
  options: {
    verificationMethod: string
    proofPurpose?: SignedObject<T>['proof']['proofPurpose']
  }
): Promise<SignedObject<T>> {
  const digest = canonicalDigest(payload)
  const signature = await ed.signAsync(digest, privateKey)

  return {
    payload,
    proof: {
      type: 'Ed25519Signature2024',
      created: new Date().toISOString(),
      verificationMethod: options.verificationMethod,
      proofPurpose: options.proofPurpose ?? 'assertionMethod',
      canonicalizationAlgorithm: 'https://fides.dev/canonical-json/v1',
      proofValue: bs58.encode(signature),
    },
  }
}

/**
 * Verify a signed object.
 */
export async function verifyObject<T>(signed: SignedObject<T>): Promise<boolean> {
  const { payload, proof } = signed
  const digest = canonicalDigest(payload)

  // Extract public key from verificationMethod (did:fides:<pubkey>)
  const did = proof.verificationMethod
  if (!did.startsWith('did:fides:')) {
    return false
  }
  const pubkeyBase58 = did.slice('did:fides:'.length)
  const publicKey = bs58.decode(pubkeyBase58)

  const signature = bs58.decode(proof.proofValue)
  return ed.verifyAsync(signature, digest, publicKey)
}
