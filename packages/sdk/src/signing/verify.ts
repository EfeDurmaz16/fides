/**
 * RFC 9421 HTTP Message Signatures - Verification
 */

import { verify } from '../identity/keypair.js'
import {
  createSignatureBase,
  parseSignatureInput,
  type RequestLike,
} from './canonicalize.js'
import { ED25519_PUBLIC_KEY_LENGTH } from '@fides/shared'

export interface VerifyResult {
  valid: boolean
  keyId?: string
  error?: string
}

/**
 * Verify an HTTP request signature per RFC 9421
 *
 * Extracts Signature and Signature-Input headers, reconstructs the signature base,
 * and verifies the signature.
 */
export async function verifyRequest(
  request: RequestLike,
  publicKey: Uint8Array
): Promise<VerifyResult> {
  try {
    // Validate public key length
    if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
      return {
        valid: false,
        error: 'Invalid public key length',
      }
    }

    // Extract headers
    const signatureInput = request.headers['Signature-Input'] || request.headers['signature-input']
    const signature = request.headers['Signature'] || request.headers['signature']

    if (!signatureInput || !signature) {
      return {
        valid: false,
        error: 'Missing Signature or Signature-Input headers',
      }
    }

    // Parse Signature-Input
    const { label, params } = parseSignatureInput(signatureInput)

    // Check expiry
    const now = Math.floor(Date.now() / 1000)
    if (params.expires < now) {
      return {
        valid: false,
        keyId: params.keyid,
        error: `Signature expired at ${params.expires}, current time is ${now}`,
      }
    }

    // Extract signature bytes from Signature header
    // Format: sig1=:BASE64:
    const signatureMatch = signature.match(new RegExp(`${label}=:([^:]+):`))
    if (!signatureMatch) {
      return {
        valid: false,
        keyId: params.keyid,
        error: 'Invalid Signature header format',
      }
    }

    const signatureB64 = signatureMatch[1]
    const signatureBytes = Buffer.from(signatureB64, 'base64')

    // Reconstruct signature base
    const signatureBase = createSignatureBase(request, params)
    const signatureBaseBytes = new TextEncoder().encode(signatureBase)

    // Verify signature
    const isValid = await verify(signatureBaseBytes, signatureBytes, publicKey)

    return {
      valid: isValid,
      keyId: params.keyid,
      error: isValid ? undefined : 'Signature verification failed',
    }
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}
