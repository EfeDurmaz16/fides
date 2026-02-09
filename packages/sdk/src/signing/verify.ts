/**
 * RFC 9421 HTTP Message Signatures - Verification
 */

import { createHash } from 'node:crypto'
import { verify } from '../identity/keypair.js'
import {
  createSignatureBase,
  parseSignatureInput,
  type RequestLike,
} from './canonicalize.js'
import { ED25519_PUBLIC_KEY_LENGTH, DEFAULT_CLOCK_DRIFT_SECONDS } from '@fides/shared'
import { NonceStore } from './nonce-store.js'

export interface VerifyResult {
  valid: boolean
  keyId?: string
  error?: string
}

export interface VerifyOptions {
  nonceStore?: NonceStore
  /** Clock drift tolerance in seconds (default: 30) */
  clockDriftSeconds?: number
}

/**
 * Verify an HTTP request signature per RFC 9421
 *
 * Extracts Signature and Signature-Input headers, reconstructs the signature base,
 * and verifies the signature.
 */
export async function verifyRequest(
  request: RequestLike,
  publicKey: Uint8Array,
  options?: VerifyOptions
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

    // Enforce algorithm whitelist - prevent downgrade attacks
    if (params.alg !== 'ed25519') {
      return {
        valid: false,
        keyId: params.keyid,
        error: `Unsupported algorithm: ${params.alg}. Only ed25519 is supported.`,
      }
    }

    // Check expiry with clock drift tolerance
    const clockDrift = options?.clockDriftSeconds ?? DEFAULT_CLOCK_DRIFT_SECONDS
    const now = Math.floor(Date.now() / 1000)
    if (params.expires + clockDrift < now) {
      return {
        valid: false,
        keyId: params.keyid,
        error: `Signature expired at ${params.expires}, current time is ${now}`,
      }
    }

    // Check for replay attack
    if (options?.nonceStore && params.nonce) {
      if (!options.nonceStore.check(params.nonce)) {
        return {
          valid: false,
          keyId: params.keyid,
          error: 'Replay detected: nonce already used',
        }
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

    if (!isValid) {
      return {
        valid: false,
        keyId: params.keyid,
        error: 'Signature verification failed',
      }
    }

    // Verify Content-Digest if present (body integrity check)
    const contentDigest = request.headers['Content-Digest'] || request.headers['content-digest']
    if (contentDigest && request.body) {
      const digestMatch = contentDigest.match(/sha-256=:([^:]+):/)
      if (!digestMatch) {
        return {
          valid: false,
          keyId: params.keyid,
          error: 'Invalid Content-Digest header format',
        }
      }
      const expectedHash = digestMatch[1]
      const bodyBytes = typeof request.body === 'string'
        ? new TextEncoder().encode(request.body)
        : request.body
      const actualHash = createHash('sha256').update(bodyBytes).digest('base64')
      if (actualHash !== expectedHash) {
        return {
          valid: false,
          keyId: params.keyid,
          error: 'Content-Digest mismatch: body has been tampered with',
        }
      }
    }

    return {
      valid: true,
      keyId: params.keyid,
    }
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}
