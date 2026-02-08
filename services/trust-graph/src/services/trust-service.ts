import { eq, and, isNull } from 'drizzle-orm'
import { TrustError, MIN_TRUST_LEVEL, MAX_TRUST_LEVEL } from '@fides/shared'
import type { DbClient } from '../db/client.js'
import { identities, trustEdges, reputationScores } from '../db/schema.js'
import { findTrustPath } from './graph.js'
import { computeReputationScore } from './scoring.js'
import type { CreateTrustRequest, TrustPathResult } from '../types.js'

export class TrustService {
  /**
   * Create a new trust edge
   */
  async createTrust(db: DbClient, request: CreateTrustRequest): Promise<string> {
    const { issuerDid, subjectDid, trustLevel, signature, expiresAt } = request

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

    // Ensure both identities exist
    await this.ensureIdentity(db, issuerDid)
    await this.ensureIdentity(db, subjectDid)

    // Create trust edge
    const attestation = {
      issuerDid,
      subjectDid,
      trustLevel,
      issuedAt: new Date().toISOString(),
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
    // Fetch all active trust edges
    const edges = await db
      .select({
        sourceDid: trustEdges.sourceDid,
        targetDid: trustEdges.targetDid,
        trustLevel: trustEdges.trustLevel,
        revokedAt: trustEdges.revokedAt,
        expiresAt: trustEdges.expiresAt,
      })
      .from(trustEdges)
      .where(isNull(trustEdges.revokedAt))

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

    // Compute fresh score
    const edges = await db
      .select({
        sourceDid: trustEdges.sourceDid,
        targetDid: trustEdges.targetDid,
        trustLevel: trustEdges.trustLevel,
        revokedAt: trustEdges.revokedAt,
        expiresAt: trustEdges.expiresAt,
      })
      .from(trustEdges)
      .where(isNull(trustEdges.revokedAt))

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
   * Ensure identity exists in database
   */
  private async ensureIdentity(db: DbClient, did: string): Promise<void> {
    const existing = await db
      .select()
      .from(identities)
      .where(eq(identities.did, did))
      .limit(1)

    if (existing.length === 0) {
      // Create stub identity (would be populated by discovery service)
      await db.insert(identities).values({
        did,
        publicKey: Buffer.from(''),
        metadata: {},
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
