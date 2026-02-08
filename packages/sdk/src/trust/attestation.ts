import type { TrustAttestation } from '@fides/shared'
import { sign, verify } from '../identity/keypair.js'
import { randomUUID, timingSafeEqual } from 'crypto'
import { isValidDID } from '../identity/did.js'
import { MIN_TRUST_LEVEL, MAX_TRUST_LEVEL } from '@fides/shared'

interface AttestationPayload {
  id: string
  issuerDid: string
  subjectDid: string
  trustLevel: number
  issuedAt: string
}

/**
 * Create a trust attestation
 */
export async function createAttestation(
  issuerDid: string,
  subjectDid: string,
  level: number,
  privateKey: Uint8Array
): Promise<TrustAttestation> {
  // Validate DIDs
  if (!isValidDID(issuerDid)) {
    throw new Error('Invalid issuer DID format')
  }
  if (!isValidDID(subjectDid)) {
    throw new Error('Invalid subject DID format')
  }

  // Validate trust level
  if (!Number.isInteger(level) || level < MIN_TRUST_LEVEL || level > MAX_TRUST_LEVEL) {
    throw new Error(`Trust level must be an integer between ${MIN_TRUST_LEVEL} and ${MAX_TRUST_LEVEL}`)
  }

  const payload: AttestationPayload = {
    id: randomUUID(),
    issuerDid,
    subjectDid,
    trustLevel: level,
    issuedAt: new Date().toISOString(),
  }

  const payloadString = JSON.stringify(payload)
  const payloadBytes = new TextEncoder().encode(payloadString)
  const signature = await sign(payloadBytes, privateKey)

  return {
    id: payload.id,
    issuerDid,
    subjectDid,
    trustLevel: level,
    issuedAt: payload.issuedAt,
    signature: Buffer.from(signature).toString('hex'),
    payload: payloadString,
  }
}

/**
 * Timing-safe string comparison
 */
function timingSafeStringEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false
  }
  const bufA = Buffer.from(a, 'utf8')
  const bufB = Buffer.from(b, 'utf8')
  return timingSafeEqual(bufA, bufB)
}

/**
 * Verify a trust attestation signature and field integrity
 */
export async function verifyAttestation(
  attestation: TrustAttestation,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    // 1. Verify the cryptographic signature over the original payload
    const payloadBytes = new TextEncoder().encode(attestation.payload)
    const signatureBytes = Buffer.from(attestation.signature, 'hex')
    const signatureValid = await verify(payloadBytes, signatureBytes, publicKey)
    if (!signatureValid) return false

    // 2. Verify outer fields match the signed payload (anti-tampering)
    // Use timing-safe comparisons for security-sensitive fields
    const parsed: AttestationPayload = JSON.parse(attestation.payload)
    if (!timingSafeStringEqual(parsed.id, attestation.id)) return false
    if (!timingSafeStringEqual(parsed.issuerDid, attestation.issuerDid)) return false
    if (!timingSafeStringEqual(parsed.subjectDid, attestation.subjectDid)) return false
    if (parsed.trustLevel !== attestation.trustLevel) return false
    if (!timingSafeStringEqual(parsed.issuedAt, attestation.issuedAt)) return false

    return true
  } catch {
    return false
  }
}
