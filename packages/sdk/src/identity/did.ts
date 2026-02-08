import bs58 from 'bs58'
import { DID_PREFIX, KeyError } from '@fides/shared'

/**
 * Generate a DID from an Ed25519 public key
 * @param publicKey - 32-byte Ed25519 public key
 * @returns DID string in format did:fides:<base58-pubkey>
 */
export function generateDID(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new KeyError('Public key must be 32 bytes')
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
  if (!did.startsWith(DID_PREFIX)) {
    throw new KeyError(
      `Invalid DID format: expected ${DID_PREFIX} prefix, got ${did}`
    )
  }

  const encoded = did.slice(DID_PREFIX.length)

  try {
    const publicKey = bs58.decode(encoded)

    if (publicKey.length !== 32) {
      throw new KeyError(
        `Invalid DID: decoded public key is ${publicKey.length} bytes, expected 32`
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
