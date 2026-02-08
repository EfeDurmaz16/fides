import { pgTable, text, jsonb, timestamp, uuid, smallint, doublePrecision, integer, primaryKey, customType } from 'drizzle-orm/pg-core'
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
  attestation: jsonb('attestation').notNull(),
  signature: bytea('signature').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  expiresAt: timestamp('expires_at'),
  revokedAt: timestamp('revoked_at'),
}, (table) => ({
  uniqueSourceTarget: {
    name: 'unique_source_target',
    columns: [table.sourceDid, table.targetDid],
  },
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
