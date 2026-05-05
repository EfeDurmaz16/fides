import { pgTable, text, jsonb, timestamp, uuid, smallint, doublePrecision, integer, primaryKey, customType, index, uniqueIndex } from 'drizzle-orm/pg-core'
import { sql } from 'drizzle-orm'

const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return 'bytea'
  },
})

export const identities = pgTable('identities', {
  did: text('did').primaryKey(),
  publicKey: bytea('public_key').notNull(),
  metadata: jsonb('metadata').notNull().default({}),
  firstSeen: timestamp('first_seen').notNull().defaultNow(),
  lastSeen: timestamp('last_seen').notNull().defaultNow(),
})

export const trustEdges = pgTable('trust_edges', {
  id: uuid('id').primaryKey().defaultRandom(),
  sourceDid: text('source_did').notNull().references(() => identities.did),
  targetDid: text('target_did').notNull().references(() => identities.did),
  trustLevel: smallint('trust_level').notNull(),
  capabilityId: text('capability_id'),
  context: text('context'),
  attestation: jsonb('attestation').notNull(),
  signature: bytea('signature').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  expiresAt: timestamp('expires_at'),
  revokedAt: timestamp('revoked_at'),
}, (table) => ({
  uniqueSourceTarget: uniqueIndex('unique_source_target').on(table.sourceDid, table.targetDid, table.capabilityId),
  idxSource: index('idx_trust_edges_source').on(table.sourceDid),
  idxTarget: index('idx_trust_edges_target').on(table.targetDid),
  idxCapability: index('idx_trust_edges_capability').on(table.capabilityId),
}))

export const incidentRecords = pgTable('incident_records', {
  id: uuid('id').primaryKey().defaultRandom(),
  actorDid: text('actor_did').notNull().references(() => identities.did),
  type: text('type').notNull(),
  severity: text('severity').notNull(),
  description: text('description').notNull(),
  evidenceRefs: jsonb('evidence_refs').notNull().default([]),
  reportedAt: timestamp('reported_at').notNull().defaultNow(),
  resolvedAt: timestamp('resolved_at'),
  trustPenalty: doublePrecision('trust_penalty').notNull().default(0),
  reputationPenalty: doublePrecision('reputation_penalty').notNull().default(0),
  capabilitiesRevoked: jsonb('capabilities_revoked').notNull().default([]),
})

export const revocationRecords = pgTable('revocation_records', {
  id: uuid('id').primaryKey().defaultRandom(),
  did: text('did').notNull(),
  reason: text('reason').notNull(),
  revokedBy: text('revoked_by').notNull(),
  record: jsonb('record').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (table) => ({
  idxRevocationDid: index('idx_revocation_records_did').on(table.did),
}))

export const capabilityScores = pgTable('capability_scores', {
  did: text('did').notNull().references(() => identities.did),
  capabilityId: text('capability_id').notNull(),
  score: doublePrecision('score').notNull(),
  invocationCount: integer('invocation_count').notNull().default(0),
  incidentCount: integer('incident_count').notNull().default(0),
  lastComputed: timestamp('last_computed').notNull().defaultNow(),
}, (table) => ({
  pk: primaryKey({ columns: [table.did, table.capabilityId] }),
}))

export const keyHistory = pgTable('key_history', {
  did: text('did').notNull().references(() => identities.did),
  publicKey: bytea('public_key').notNull(),
  successorKey: bytea('successor_key'),
  successionSignature: bytea('succession_signature'),
  activeFrom: timestamp('active_from').notNull().defaultNow(),
  activeUntil: timestamp('active_until'),
}, (table) => ({
  pk: primaryKey({ columns: [table.did, table.publicKey] }),
}))

export const reputationScores = pgTable('reputation_scores', {
  did: text('did').primaryKey().references(() => identities.did),
  score: doublePrecision('score').notNull(),
  directTrusters: integer('direct_trusters').notNull().default(0),
  transitiveTrusters: integer('transitive_trusters').notNull().default(0),
  lastComputed: timestamp('last_computed').notNull().defaultNow(),
})
