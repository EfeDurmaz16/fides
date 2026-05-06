import { eq, and, isNull, or, gt, desc } from 'drizzle-orm'
import {
  verifyIncidentRecord,
  verifyRevocationRecord,
  type IncidentRecord,
  type RevocationRecord,
} from '@fides/core'
import { TrustError, MIN_TRUST_LEVEL, MAX_TRUST_LEVEL } from '@fides/shared'
import type { DbClient } from '../db/client.js'
import { identities, trustEdges, reputationScores, revocationRecords } from '../db/schema.js'
import { findTrustPath } from './graph.js'
import { computeReputationScore } from './scoring.js'
import { computeCapabilityScore, recordCapabilityInvocation, recordIncident, getIncidents } from './capability-scoring.js'
import type { CreateTrustRequest, RevocationRecordInput, TrustPathResult } from '../types.js'
import type { IncidentRecordInput, CapabilityScoreResult } from './capability-scoring.js'

const IDENTITY_CACHE_TTL_MS = 30 * 60 * 1000 // 30 minutes
const CIRCUIT_BREAKER_THRESHOLD = 5
const CIRCUIT_BREAKER_RESET_MS = 30 * 1000 // 30 seconds
const FETCH_TIMEOUT_MS = 3000 // 3 seconds

export class TrustService {
  private discoveryUrl: string

  // In-memory identity cache with TTL
  private identityCache = new Map<string, { cachedAt: number }>()

  // Circuit breaker state for discovery service
  private circuitBreaker = {
    failureCount: 0,
    openUntil: 0,
  }

  constructor(discoveryUrl?: string) {
    this.discoveryUrl = discoveryUrl || process.env.DISCOVERY_URL || 'http://localhost:3100'
  }

  /**
   * Create a new trust edge
   */
  async createTrust(db: DbClient, request: CreateTrustRequest): Promise<string> {
    const { issuerDid, subjectDid, trustLevel, capabilityId, context, signature, payload, expiresAt } = request

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

    // Ensure both identities exist — parallel resolution
    await Promise.all([
      this.ensureIdentity(db, issuerDid),
      this.ensureIdentity(db, subjectDid),
    ])

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
    if ((parsedPayload.capabilityId ?? undefined) !== capabilityId) {
      throw new TrustError('Invalid attestation: capabilityId mismatch')
    }
    if ((parsedPayload.context ?? undefined) !== context) {
      throw new TrustError('Invalid attestation: context mismatch')
    }

    // Create trust edge
    const issuedAt = new Date().toISOString()
    const attestation = {
      issuerDid,
      subjectDid,
      trustLevel,
      ...(capabilityId && { capabilityId }),
      ...(context && { context }),
      issuedAt,
      ...(expiresAt && { expiresAt }),
    }

    const result = await db.insert(trustEdges).values({
      sourceDid: issuerDid,
      targetDid: subjectDid,
      trustLevel,
      capabilityId,
      context,
      attestation,
      signature: Buffer.from(signature, 'hex'),
      ...(expiresAt && { expiresAt: new Date(expiresAt) }),
    }).returning({ id: trustEdges.id })

    // Invalidate reputation cache for subjectDid
    await db.update(reputationScores)
      .set({ lastComputed: new Date(0) })
      .where(eq(reputationScores.did, subjectDid))

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
   * Ensure identity exists in database, fetching from discovery if needed.
   * Uses in-memory cache to avoid redundant DB queries and a circuit breaker
   * for the discovery service fetch.
   */
  private async ensureIdentity(db: DbClient, did: string): Promise<void> {
    // Check in-memory cache first
    const cached = this.identityCache.get(did)
    if (cached && (Date.now() - cached.cachedAt) < IDENTITY_CACHE_TTL_MS) {
      return
    }

    const existing = await db
      .select()
      .from(identities)
      .where(eq(identities.did, did))
      .limit(1)

    if (existing.length === 0) {
      // Fetch identity from discovery service (with circuit breaker + timeout)
      let identity: { did: string; publicKey: string; metadata?: Record<string, unknown> } | null = null

      const circuitOpen = Date.now() < this.circuitBreaker.openUntil
      if (circuitOpen) {
        throw new TrustError(`Identity not found: ${did}. Discovery service circuit breaker open.`)
      }

      try {
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)

        const response = await fetch(
          `${this.discoveryUrl}/identities/${encodeURIComponent(did)}`,
          { signal: controller.signal }
        )
        clearTimeout(timeoutId)

        if (response.ok) {
          identity = await response.json()
          // Reset circuit breaker on success
          this.circuitBreaker.failureCount = 0
        }
      } catch {
        // Discovery service unavailable — increment circuit breaker
        this.circuitBreaker.failureCount++
        if (this.circuitBreaker.failureCount >= CIRCUIT_BREAKER_THRESHOLD) {
          this.circuitBreaker.openUntil = Date.now() + CIRCUIT_BREAKER_RESET_MS
        }
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

    // Cache the identity
    this.identityCache.set(did, { cachedAt: Date.now() })
  }

  /**
   * Get capability-specific score for a DID.
   */
  async getCapabilityScore(db: DbClient, did: string, capabilityId: string): Promise<CapabilityScoreResult> {
    return computeCapabilityScore(db, did, capabilityId)
  }

  /**
   * Record a capability invocation.
   */
  async recordCapabilityInvocation(db: DbClient, did: string, capabilityId: string): Promise<void> {
    return recordCapabilityInvocation(db, did, capabilityId)
  }

  /**
   * Record an incident against an agent.
   */
  async recordIncident(db: DbClient, input: Partial<IncidentRecordInput> & {
    actor?: string
    reportedBy?: string
    reporter?: string
    record?: unknown
    impact?: {
      trustPenalty?: number
      reputationPenalty?: number
      capabilitiesRevoked?: string[]
    }
  }): Promise<string> {
    const record = await this.verifyIncidentRecordInput(db, input)
    const actorDid = input.actorDid ?? input.actor ?? record.actor

    await this.ensureIdentity(db, actorDid)

    return recordIncident(db, {
      actorDid,
      type: record.type,
      severity: record.severity,
      description: record.description,
      evidenceRefs: record.evidenceRefs,
      trustPenalty: input.trustPenalty ?? input.impact?.trustPenalty ?? record.impact.trustPenalty,
      reputationPenalty: input.reputationPenalty ?? input.impact?.reputationPenalty ?? record.impact.reputationPenalty,
      capabilitiesRevoked: input.capabilitiesRevoked ?? input.impact?.capabilitiesRevoked ?? record.impact.capabilitiesRevoked,
    })
  }

  /**
   * Record an authority revocation and revoke active trust edges touching the DID.
   */
  async recordRevocation(db: DbClient, input: RevocationRecordInput): Promise<{ id: string; revokedEdges: number }> {
    const record = await this.verifyRevocationRecordInput(db, input)
    const now = new Date()

    const result = await db
      .insert(revocationRecords)
      .values({
        did: record.did,
        reason: record.reason,
        revokedBy: record.revokedBy,
        record,
      })
      .returning({ id: revocationRecords.id })

    const updateResult = await db
      .update(trustEdges)
      .set({ revokedAt: now })
      .where(or(eq(trustEdges.sourceDid, record.did), eq(trustEdges.targetDid, record.did)))

    await db
      .update(reputationScores)
      .set({ lastComputed: new Date(0) })
      .where(eq(reputationScores.did, record.did))

    return { id: result[0].id, revokedEdges: Array.isArray(updateResult) ? updateResult.length : 0 }
  }

  /**
   * Get the latest propagated authority revocation for a DID.
   */
  async getRevocation(db: DbClient, did: string): Promise<RevocationRecord | null> {
    const rows = await db
      .select({ record: revocationRecords.record })
      .from(revocationRecords)
      .where(eq(revocationRecords.did, did))
      .orderBy(desc(revocationRecords.createdAt))
      .limit(1)

    return (rows[0]?.record as RevocationRecord | undefined) ?? null
  }

  /**
   * Get all incidents for a DID.
   */
  async getIncidents(db: DbClient, did: string) {
    return getIncidents(db, did)
  }

  private async verifyRevocationRecordInput(db: DbClient, input: RevocationRecordInput): Promise<RevocationRecord> {
    if (!isRevocationRecord(input.record)) {
      throw new TrustError('signed revocation record is required')
    }

    const record = input.record
    if (input.did && input.did !== record.did) {
      throw new TrustError('revocation record did mismatch')
    }
    if (input.reason && input.reason !== record.reason) {
      throw new TrustError('revocation record reason mismatch')
    }
    if (input.revokedBy && input.revokedBy !== record.revokedBy) {
      throw new TrustError('revocation record revokedBy mismatch')
    }

    const publicKey = await this.getIdentityPublicKey(db, record.revokedBy)
    if (!await verifyRevocationRecord(record, publicKey)) {
      throw new TrustError('invalid revocation record signature')
    }

    return record
  }

  private async verifyIncidentRecordInput(
    db: DbClient,
    input: Partial<IncidentRecordInput> & {
      actor?: string
      reportedBy?: string
      reporter?: string
      record?: unknown
    }
  ): Promise<IncidentRecord> {
    if (!isIncidentRecord(input.record)) {
      throw new TrustError('signed incident record is required')
    }

    const record = input.record
    const actor = input.actorDid ?? input.actor
    const reporter = input.reportedBy ?? input.reporter

    if (actor && actor !== record.actor) {
      throw new TrustError('incident record actor mismatch')
    }
    if (reporter && reporter !== record.reportedBy) {
      throw new TrustError('incident record reporter mismatch')
    }

    const publicKey = await this.getIdentityPublicKey(db, record.reportedBy)
    if (!await verifyIncidentRecord(record, publicKey)) {
      throw new TrustError('invalid incident record signature')
    }

    return record
  }

  private async getIdentityPublicKey(db: DbClient, did: string): Promise<Uint8Array> {
    await this.ensureIdentity(db, did)

    const rows = await db
      .select()
      .from(identities)
      .where(eq(identities.did, did))
      .limit(1)

    const publicKey = rows[0]?.publicKey
    if (!publicKey || publicKey.length !== 32) {
      throw new TrustError(`Cannot verify signature: identity public key not found for ${did}`)
    }

    return new Uint8Array(publicKey)
  }
}

function isRevocationRecord(record: unknown): record is RevocationRecord {
  const candidate = record as RevocationRecord
  return Boolean(
    candidate &&
    typeof candidate.id === 'string' &&
    typeof candidate.did === 'string' &&
    typeof candidate.reason === 'string' &&
    typeof candidate.revokedAt === 'string' &&
    typeof candidate.revokedBy === 'string' &&
    typeof candidate.signature === 'string' &&
    candidate.signature.length > 0 &&
    Array.isArray(candidate.propagatedTo)
  )
}

function isIncidentRecord(record: unknown): record is IncidentRecord {
  const candidate = record as IncidentRecord
  return Boolean(
    candidate &&
    typeof candidate.id === 'string' &&
    typeof candidate.type === 'string' &&
    typeof candidate.severity === 'string' &&
    typeof candidate.actor === 'string' &&
    typeof candidate.reportedBy === 'string' &&
    typeof candidate.description === 'string' &&
    Array.isArray(candidate.evidenceRefs) &&
    typeof candidate.reportedAt === 'string' &&
    candidate.impact &&
    typeof candidate.impact.trustPenalty === 'number' &&
    typeof candidate.impact.reputationPenalty === 'number' &&
    Array.isArray(candidate.impact.capabilitiesRevoked) &&
    typeof candidate.signature === 'string' &&
    candidate.signature.length > 0
  )
}
