/**
 * Key rotation support for FIDES identities
 * Allows agents to rotate their keypair while maintaining DID history
 */

import { generateKeyPair } from './keypair.js'
import { generateDID } from './did.js'
import type { KeyStore } from './keystore.js'
import type { KeyPair } from '@fides/shared'

export interface RotationRecord {
  oldDid: string
  newDid: string
  rotatedAt: string
  reason?: string
}

export interface KeyRotationResult {
  newDid: string
  newPublicKey: string
  rotation: RotationRecord
}

/**
 * Rotate an agent's keypair
 * Generates a new keypair and DID, stores it, and returns the rotation record
 */
export async function rotateKey(
  currentDid: string,
  keyStore: KeyStore,
  options?: { reason?: string }
): Promise<KeyRotationResult> {
  // Verify current key exists
  await keyStore.load(currentDid)

  // Generate new keypair
  const newKeyPair = await generateKeyPair()
  const newDid = generateDID(newKeyPair.publicKey)

  // Store new keypair
  await keyStore.save(newDid, newKeyPair)

  const rotation: RotationRecord = {
    oldDid: currentDid,
    newDid,
    rotatedAt: new Date().toISOString(),
    reason: options?.reason,
  }

  return {
    newDid,
    newPublicKey: Buffer.from(newKeyPair.publicKey).toString('hex'),
    rotation,
  }
}

/**
 * Revocation record for a compromised key
 */
export interface RevocationRecord {
  did: string
  revokedAt: string
  reason: string
  revokedBy?: string // DID of the revoker (for delegated revocation)
}

/**
 * Create a signed revocation record
 */
export function createRevocation(
  did: string,
  reason: string,
  revokedBy?: string
): RevocationRecord {
  return {
    did,
    revokedAt: new Date().toISOString(),
    reason,
    revokedBy,
  }
}
