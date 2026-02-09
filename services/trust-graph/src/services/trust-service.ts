import { eq, and, isNull, or, gt } from 'drizzle-orm'
import { TrustError, MIN_TRUST_LEVEL, MAX_TRUST_LEVEL } from '@fides/shared'
import type { DbClient } from '../db/client.js'
import { identities, trustEdges, reputationScores } from '../db/schema.js'
import { findTrustPath } from './graph.js'
import { computeReputationScore } from './scoring.js'
import type { CreateTrustRequest, TrustPathResult } from '../types.js'

export class TrustService {
  private discoveryUrl: string

  constructor(discoveryUrl?: string) {
    this.discoveryUrl = discoveryUrl || process.env.DISCOVERY_URL || 'http://localhost:3100'
  }

  /**
   * Create a new trust edge
   */
  async createTrust(db: DbClient, request: CreateTrustRequest): Promise<string> {
    const { issuerDid, subjectDid, trustLevel, signature, payload, expiresAt } = request

    // Validate trust level
    if (!Number.isInteger(trustLevel) || trustLevel < MIN_TRUST_LEVEL || trustLevel > MAX_TRUST_LEVEL) {
      throw new TrustError(`Trust level must be an integer between ${MIN_TRUST_LEVEL} and ${MAX_TRUST_LEVEL}`)
    }

    // Validate DIDs are provided
    if (!issuerDid || typeof issuerDid !== 'string') {
      throw new TrustError('Invalid issuer DID')
    }
    if (!subjectDid || typeof subjectDid !== 'string') {
      throw new TrustError('Invalid subject DID')
    }

    // Validate signature is provided
    if (!signature || typeof signature !== 'string') {
      throw new TrustError('Invalid signature')
    }

    // Validate payload is provided
    if (!payload || typeof payload !== 'string') {
      throw new TrustError('Payload is required for signature verification')
    }

    // Ensure both identities exist
    await this.ensureIdentity(db, issuerDid)
    await this.ensureIdentity(db, subjectDid)

    // Verify cryptographic signature
    const issuerIdentity = await db
      .select()
      .from(identities)
      .where(eq(identities.did, issuerDid))
      .limit(1)

    if (issuerIdentity.length === 0 || !issuerIdentity[0].publicKey) {
      throw new TrustError('Cannot verify signature: issuer identity not found')
    }

    // Get public key bytes
    const pubKeyBuffer = issuerIdentity[0].publicKey
    if (pubKeyBuffer.length === 0) {
      throw new TrustError('Cannot verify signature: issuer has no public key')
    }

    // Validate signature format
    let signatureBytes: Buffer
    try {
      signatureBytes = Buffer.from(signature, 'hex')
      if (signatureBytes.length !== 64) {
        throw new TrustError('Invalid signature: must be 64 bytes (Ed25519)')
      }
    } catch (error) {
      throw new TrustError('Invalid signature format: must be hex-encoded')
    }

    // Import ed25519 for verification
    const ed25519 = await import('@noble/ed25519')
    const { sha512 } = await import('@noble/hashes/sha512')
    ed25519.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed25519.etc.concatBytes(...m))

    const publicKeyBytes = new Uint8Array(pubKeyBuffer)

    // Verify the signature over the provided payload
    const payloadBytes = new TextEncoder().encode(payload)

    try {
      const isValid = await ed25519.verifyAsync(signatureBytes, payloadBytes, publicKeyBytes)
      if (!isValid) {
        throw new TrustError('Invalid signature: attestation signature verification failed')
      }
    } catch (error) {
      if (error instanceof TrustError) throw error
      throw new TrustError('Signature verification failed')
    }

    // Parse and validate the payload matches the request fields
    let parsedPayload: any
    try {
      parsedPayload = JSON.parse(payload)
    } catch {
      throw new TrustError('Invalid payload: must be valid JSON')
    }

    // Verify the signed payload matches the request parameters
    if (parsedPayload.issuerDid !== issuerDid) {
      throw new TrustError('Invalid attestation: issuerDid mismatch')
    }
    if (parsedPayload.subjectDid !== subjectDid) {
      throw new TrustError('Invalid attestation: subjectDid mismatch')
    }
    if (parsedPayload.trustLevel !== trustLevel) {
      throw new TrustError('Invalid attestation: trustLevel mismatch')
    }

    // Create trust edge
    const issuedAt = new Date().toISOString()
    const attestation = {
      issuerDid,
      subjectDid,
      trustLevel,
      issuedAt,
      ...(expiresAt && { expiresAt }),
    }

    const result = await db.insert(trustEdges).values({
      sourceDid: issuerDid,
      targetDid: subjectDid,
      trustLevel,
      attestation,
      signature: Buffer.from(signature, 'hex'),
      ...(expiresAt && { expiresAt: new Date(expiresAt) }),
    }).returning({ id: trustEdges.id })

    return result[0].id
  }

  /**
   * Get trust path between two DIDs
   */
  async getTrustPath(db: DbClient, fromDid: string, toDid: string): Promise<TrustPathResult> {
    // Fetch all active trust edges (not revoked, not expired)
    const now = new Date()
    const edges = await db
      .select({
        sourceDid: trustEdges.sourceDid,
        targetDid: trustEdges.targetDid,
        trustLevel: trustEdges.trustLevel,
        revokedAt: trustEdges.revokedAt,
        expiresAt: trustEdges.expiresAt,
      })
      .from(trustEdges)
      .where(and(
        isNull(trustEdges.revokedAt),
        or(isNull(trustEdges.expiresAt), gt(trustEdges.expiresAt, now))
      ))

    return findTrustPath(edges, fromDid, toDid)
  }

  /**
   * Get reputation score for a DID
   */
  async getScore(db: DbClient, did: string): Promise<{
    score: number
    directTrusters: number
    transitiveTrusters: number
    lastComputed: string
  }> {
    // Check cache first
    const cached = await db
      .select()
      .from(reputationScores)
      .where(eq(reputationScores.did, did))
      .limit(1)

    const now = new Date()
    const cacheValid = cached.length > 0 &&
      (now.getTime() - cached[0].lastComputed.getTime()) < 3600000 // 1 hour

    if (cacheValid) {
      return {
        score: cached[0].score,
        directTrusters: cached[0].directTrusters,
        transitiveTrusters: cached[0].transitiveTrusters,
        lastComputed: cached[0].lastComputed.toISOString(),
      }
    }

    // Compute fresh score (exclude revoked and expired edges)
    const scoreNow = new Date()
    const edges = await db
      .select({
        sourceDid: trustEdges.sourceDid,
        targetDid: trustEdges.targetDid,
        trustLevel: trustEdges.trustLevel,
        revokedAt: trustEdges.revokedAt,
        expiresAt: trustEdges.expiresAt,
      })
      .from(trustEdges)
      .where(and(
        isNull(trustEdges.revokedAt),
        or(isNull(trustEdges.expiresAt), gt(trustEdges.expiresAt, scoreNow))
      ))

    const result = computeReputationScore(edges, did)

    // Update cache
    await db
      .insert(reputationScores)
      .values({
        did,
        score: result.score,
        directTrusters: result.directTrusters,
        transitiveTrusters: result.transitiveTrusters,
        lastComputed: now,
      })
      .onConflictDoUpdate({
        target: reputationScores.did,
        set: {
          score: result.score,
          directTrusters: result.directTrusters,
          transitiveTrusters: result.transitiveTrusters,
          lastComputed: now,
        },
      })

    return {
      ...result,
      lastComputed: now.toISOString(),
    }
  }

  /**
   * Ensure identity exists in database, fetching from discovery if needed
   */
  private async ensureIdentity(db: DbClient, did: string): Promise<void> {
    const existing = await db
      .select()
      .from(identities)
      .where(eq(identities.did, did))
      .limit(1)

    if (existing.length === 0) {
      // Fetch identity from discovery service
      let identity: { did: string; publicKey: string; metadata?: Record<string, unknown> } | null = null
      try {
        const response = await fetch(`${this.discoveryUrl}/identities/${encodeURIComponent(did)}`)
        if (response.ok) {
          identity = await response.json()
        }
      } catch {
        // Discovery service unavailable
      }

      if (!identity || !identity.publicKey) {
        throw new TrustError(`Identity not found: ${did}. Register with discovery service first.`)
      }

      await db.insert(identities).values({
        did,
        publicKey: Buffer.from(identity.publicKey, 'hex'),
        metadata: identity.metadata || {},
      })
    } else {
      // Update last seen
      await db
        .update(identities)
        .set({ lastSeen: new Date() })
        .where(eq(identities.did, did))
    }
  }
}
