import type { TrustAttestation } from '@fides/shared'
import { sign, verify } from '../identity/keypair.js'
import { randomUUID } from 'crypto'

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
 * Verify a trust attestation signature
 */
export async function verifyAttestation(
  attestation: TrustAttestation,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    const payloadBytes = new TextEncoder().encode(attestation.payload)
    const signatureBytes = Buffer.from(attestation.signature, 'hex')
    return await verify(payloadBytes, signatureBytes, publicKey)
  } catch {
    return false
  }
}
