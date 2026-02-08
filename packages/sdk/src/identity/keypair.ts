import * as ed25519 from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'
import type { KeyPair } from '@fides/shared'
import { KeyError } from '@fides/shared'

// Set the SHA-512 implementation for @noble/ed25519
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m))

/**
 * Generate a new Ed25519 keypair
 * @returns KeyPair with 32-byte public and private keys
 */
export async function generateKeyPair(): Promise<KeyPair> {
  try {
    // Generate 32 random bytes for the private key
    const privateKey = ed25519.utils.randomPrivateKey()

    // Derive the public key from the private key
    const publicKey = await ed25519.getPublicKeyAsync(privateKey)

    return {
      publicKey,
      privateKey,
    }
  } catch (error) {
    throw new KeyError(
      `Failed to generate keypair: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

/**
 * Sign a message with an Ed25519 private key
 * @param message - Message to sign
 * @param privateKey - 32-byte Ed25519 private key
 * @returns Signature as Uint8Array
 */
export async function sign(
  message: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  try {
    if (privateKey.length !== 32) {
      throw new KeyError('Private key must be 32 bytes')
    }

    return await ed25519.signAsync(message, privateKey)
  } catch (error) {
    throw new KeyError(
      `Failed to sign message: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

/**
 * Verify an Ed25519 signature
 * @param message - Original message
 * @param signature - Signature to verify
 * @param publicKey - 32-byte Ed25519 public key
 * @returns True if signature is valid
 */
export async function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    if (publicKey.length !== 32) {
      throw new KeyError('Public key must be 32 bytes')
    }

    return await ed25519.verifyAsync(signature, message, publicKey)
  } catch (error) {
    throw new KeyError(
      `Failed to verify signature: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}
