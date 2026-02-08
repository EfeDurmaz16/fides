import { pgTable, text, jsonb, timestamp, customType } from 'drizzle-orm/pg-core'

export const identities = pgTable('identities', {
  did: text('did').primaryKey(),
  publicKey: text('public_key').notNull(), // hex-encoded
  metadata: jsonb('metadata').notNull().default({}),
  domain: text('domain'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
})
