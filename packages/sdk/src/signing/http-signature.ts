/**
 * RFC 9421 HTTP Message Signatures - Signing
 */

import { createHash } from 'node:crypto'
import { sign } from '../identity/keypair.js'
import {
  createSignatureBase,
  type RequestLike,
  type SignatureParams,
} from './canonicalize.js'
import {
  ALGORITHM,
  DEFAULT_SIGNATURE_EXPIRY_SECONDS,
  CONTENT_DIGEST_ALGORITHM,
} from '@fides/shared'

export interface SignOptions {
  /**
   * Key ID (typically a DID) to include in the signature
   */
  keyid?: string

  /**
   * Components to sign. Defaults to @method, @target-uri, @authority, content-type
   */
  components?: string[]

  /**
   * Signature expiry in seconds from now. Defaults to 300.
   */
  expirySeconds?: number

  /**
   * Signature label. Defaults to "sig1"
   */
  label?: string
}

/**
 * Sign an HTTP request per RFC 9421
 *
 * Adds Signature and Signature-Input headers to the request.
 */
export async function signRequest(
  request: RequestLike,
  privateKey: Uint8Array,
  options: SignOptions = {}
): Promise<RequestLike> {
  const {
    keyid = 'unknown',
    components = ['@method', '@target-uri', '@authority', 'content-type'],
    expirySeconds = DEFAULT_SIGNATURE_EXPIRY_SECONDS,
    label = 'sig1',
  } = options

  // If there's a body, compute Content-Digest and add it to signed components
  const updatedHeaders = { ...request.headers }
  let signedComponents = [...components]

  if (request.body) {
    const bodyBytes = typeof request.body === 'string'
      ? new TextEncoder().encode(request.body)
      : request.body
    const hash = createHash('sha256').update(bodyBytes).digest('base64')
    updatedHeaders['Content-Digest'] = `${CONTENT_DIGEST_ALGORITHM}=:${hash}:`
    if (!signedComponents.includes('content-digest')) {
      signedComponents.push('content-digest')
    }
  }

  const updatedRequest = { ...request, headers: updatedHeaders }

  // Calculate timestamps
  const created = Math.floor(Date.now() / 1000)
  const expires = created + expirySeconds

  // Generate nonce for replay protection
  const nonce = crypto.randomUUID()

  // Build signature params
  const params: SignatureParams = {
    components: signedComponents,
    created,
    expires,
    keyid,
    alg: ALGORITHM,
    nonce,
  }

  // Create signature base
  const signatureBase = createSignatureBase(updatedRequest, params)

  // Sign the base
  const signatureBaseBytes = new TextEncoder().encode(signatureBase)
  const signatureBytes = await sign(signatureBaseBytes, privateKey)

  // Base64 encode signature
  const signatureB64 = Buffer.from(signatureBytes).toString('base64')

  // Build Signature-Input header
  const componentList = signedComponents.map(c => `"${c}"`).join(' ')
  const signatureInput = `${label}=(${componentList});created=${created};expires=${expires};nonce="${nonce}";keyid="${keyid}";alg="${ALGORITHM}"`

  // Build Signature header
  const signature = `${label}=:${signatureB64}:`

  // Return request with signature headers
  return {
    ...request,
    headers: {
      ...updatedHeaders,
      'Signature-Input': signatureInput,
      'Signature': signature,
    },
  }
}
