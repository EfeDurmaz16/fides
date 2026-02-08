/**
 * RFC 9421 HTTP Message Signatures - Signing
 */

import { sign } from '../identity/keypair.js'
import {
  createSignatureBase,
  type RequestLike,
  type SignatureParams,
} from './canonicalize.js'
import {
  ALGORITHM,
  DEFAULT_SIGNATURE_EXPIRY_SECONDS,
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

  // Calculate timestamps
  const created = Math.floor(Date.now() / 1000)
  const expires = created + expirySeconds

  // Build signature params
  const params: SignatureParams = {
    components,
    created,
    expires,
    keyid,
    alg: ALGORITHM,
  }

  // Create signature base
  const signatureBase = createSignatureBase(request, params)

  // Sign the base
  const signatureBaseBytes = new TextEncoder().encode(signatureBase)
  const signatureBytes = await sign(signatureBaseBytes, privateKey)

  // Base64 encode signature
  const signatureB64 = Buffer.from(signatureBytes).toString('base64')

  // Build Signature-Input header
  const componentList = components.map(c => `"${c}"`).join(' ')
  const signatureInput = `${label}=(${componentList});created=${created};expires=${expires};keyid="${keyid}";alg="${ALGORITHM}"`

  // Build Signature header
  const signature = `${label}=:${signatureB64}:`

  // Return request with signature headers
  return {
    ...request,
    headers: {
      ...request.headers,
      'Signature-Input': signatureInput,
      'Signature': signature,
    },
  }
}
