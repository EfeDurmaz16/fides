import bs58 from 'bs58'
import { DID_PREFIX, KeyError, ED25519_PUBLIC_KEY_LENGTH } from '@fides/shared'

/**
 * Validate DID format
 * @param did - DID string to validate
 * @returns True if valid
 */
export function isValidDID(did: string): boolean {
  if (!did.startsWith(DID_PREFIX)) {
    return false
  }

  const encoded = did.slice(DID_PREFIX.length)
  if (encoded.length === 0) {
    return false
  }

  // Validate base58 encoding and length
  try {
    const decoded = bs58.decode(encoded)
    return decoded.length === ED25519_PUBLIC_KEY_LENGTH
  } catch {
    return false
  }
}

/**
 * Generate a DID from an Ed25519 public key
 * @param publicKey - 32-byte Ed25519 public key
 * @returns DID string in format did:fides:<base58-pubkey>
 */
export function generateDID(publicKey: Uint8Array): string {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new KeyError(`Public key must be ${ED25519_PUBLIC_KEY_LENGTH} bytes`)
  }

  const encoded = bs58.encode(publicKey)
  return `${DID_PREFIX}${encoded}`
}

/**
 * Parse a DID and extract the public key
 * @param did - DID string in format did:fides:<base58-pubkey>
 * @returns 32-byte Ed25519 public key
 */
export function parseDID(did: string): Uint8Array {
  if (!isValidDID(did)) {
    throw new KeyError(
      `Invalid DID format: expected ${DID_PREFIX}<valid-base58-pubkey>`
    )
  }

  const encoded = did.slice(DID_PREFIX.length)

  try {
    const publicKey = bs58.decode(encoded)

    if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
      throw new KeyError(
        `Invalid DID: decoded public key is ${publicKey.length} bytes, expected ${ED25519_PUBLIC_KEY_LENGTH}`
      )
    }

    return publicKey
  } catch (error) {
    if (error instanceof KeyError) {
      throw error
    }
    throw new KeyError(
      `Failed to decode DID: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}
