import { eq, and, isNull, gt, sql, or } from 'drizzle-orm'
import type { DbClient } from '../db/client.js'
import { capabilityScores, incidentRecords, trustEdges } from '../db/schema.js'

export interface CapabilityScoreResult {
  did: string
  capabilityId: string
  score: number
  invocationCount: number
  incidentCount: number
  lastComputed: string
}

export interface IncidentRecordInput {
  actorDid: string
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  evidenceRefs?: string[]
  trustPenalty?: number
  reputationPenalty?: number
  capabilitiesRevoked?: string[]
}

/**
 * Severity-to-penalty mapping for trust score adjustments.
 */
const SEVERITY_PENALTY: Record<string, number> = {
  low: 0.05,
  medium: 0.15,
  high: 0.35,
  critical: 0.6,
}

/**
 * Compute capability-specific score for a DID.
 * Score = base_trust * (1 - incident_penalty) * success_rate_factor
 */
export async function computeCapabilityScore(
  db: DbClient,
  did: string,
  capabilityId: string
): Promise<CapabilityScoreResult> {
  // Get base trust score from trust edges for this capability
  const capabilityEdges = await db
    .select({
      trustLevel: trustEdges.trustLevel,
      revokedAt: trustEdges.revokedAt,
      expiresAt: trustEdges.expiresAt,
    })
    .from(trustEdges)
    .where(and(
      eq(trustEdges.targetDid, did),
      eq(trustEdges.capabilityId, capabilityId),
      isNull(trustEdges.revokedAt),
      or(
        isNull(trustEdges.expiresAt),
        gt(trustEdges.expiresAt, new Date())
      )
    ))

  let baseTrust = 0.5 // Default neutral trust
  if (capabilityEdges.length > 0) {
    const total = capabilityEdges.reduce((sum, e) => sum + (e.trustLevel / 100), 0)
    baseTrust = Math.min(total / capabilityEdges.length, 1.0)
  }

  // Get incident count and total penalty
  const incidents = await db
    .select({
      count: sql<number>`count(*)`.as('count'),
      totalPenalty: sql<number>`coalesce(sum(trust_penalty), 0)`.as('totalPenalty'),
    })
    .from(incidentRecords)
    .where(eq(incidentRecords.actorDid, did))

  const incidentCount = Number(incidents[0]?.count ?? 0)
  const totalPenalty = Number(incidents[0]?.totalPenalty ?? 0)

  // Get invocation count
  const existing = await db
    .select()
    .from(capabilityScores)
    .where(and(
      eq(capabilityScores.did, did),
      eq(capabilityScores.capabilityId, capabilityId)
    ))

  const invocationCount = existing.length > 0 ? existing[0].invocationCount : 0

  // Compute final score
  const incidentPenalty = Math.min(totalPenalty, 1.0)
  const successRate = invocationCount > 0
    ? Math.max(0, 1 - (incidentCount / invocationCount))
    : 1.0

  const finalScore = Math.max(0, Math.min(1, baseTrust * (1 - incidentPenalty) * successRate))

  // Upsert capability score
  const now = new Date()
  await db
    .insert(capabilityScores)
    .values({
      did,
      capabilityId,
      score: finalScore,
      invocationCount,
      incidentCount,
      lastComputed: now,
    })
    .onConflictDoUpdate({
      target: [capabilityScores.did, capabilityScores.capabilityId],
      set: {
        score: finalScore,
        invocationCount,
        incidentCount,
        lastComputed: now,
      },
    })

  return {
    did,
    capabilityId,
    score: finalScore,
    invocationCount,
    incidentCount,
    lastComputed: now.toISOString(),
  }
}

/**
 * Record a capability invocation (increments counter).
 */
export async function recordCapabilityInvocation(
  db: DbClient,
  did: string,
  capabilityId: string
): Promise<void> {
  await db
    .insert(capabilityScores)
    .values({
      did,
      capabilityId,
      score: 0.5,
      invocationCount: 1,
      incidentCount: 0,
      lastComputed: new Date(),
    })
    .onConflictDoUpdate({
      target: [capabilityScores.did, capabilityScores.capabilityId],
      set: {
        invocationCount: sql`${capabilityScores.invocationCount} + 1`,
        lastComputed: new Date(),
      },
    })
}

/**
 * Record an incident against an agent.
 */
export async function recordIncident(
  db: DbClient,
  input: IncidentRecordInput
): Promise<string> {
  const penalty = input.trustPenalty ?? SEVERITY_PENALTY[input.severity] ?? 0.1

  const result = await db
    .insert(incidentRecords)
    .values({
      actorDid: input.actorDid,
      type: input.type,
      severity: input.severity,
      description: input.description,
      evidenceRefs: input.evidenceRefs ?? [],
      trustPenalty: penalty,
      reputationPenalty: input.reputationPenalty ?? penalty * 2,
      capabilitiesRevoked: input.capabilitiesRevoked ?? [],
    })
    .returning({ id: incidentRecords.id })

  // Recompute capability scores for affected capabilities
  if (input.capabilitiesRevoked && input.capabilitiesRevoked.length > 0) {
    for (const capId of input.capabilitiesRevoked) {
      await computeCapabilityScore(db, input.actorDid, capId)
    }
  }

  return result[0].id
}

/**
 * Get all incidents for a DID.
 */
export async function getIncidents(
  db: DbClient,
  did: string
): Promise<Array<{
  id: string
  type: string
  severity: string
  description: string
  reportedAt: string
  resolvedAt: string | null
  trustPenalty: number
}>> {
  const results = await db
    .select({
      id: incidentRecords.id,
      type: incidentRecords.type,
      severity: incidentRecords.severity,
      description: incidentRecords.description,
      reportedAt: incidentRecords.reportedAt,
      resolvedAt: incidentRecords.resolvedAt,
      trustPenalty: incidentRecords.trustPenalty,
    })
    .from(incidentRecords)
    .where(eq(incidentRecords.actorDid, did))

  return results.map(r => ({
    ...r,
    reportedAt: r.reportedAt.toISOString(),
    resolvedAt: r.resolvedAt?.toISOString() ?? null,
  }))
}
