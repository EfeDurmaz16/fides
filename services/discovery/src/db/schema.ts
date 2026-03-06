import { pgTable, text, jsonb, timestamp, boolean, integer, varchar } from 'drizzle-orm/pg-core'

export const identities = pgTable('identities', {
  did: text('did').primaryKey(),
  publicKey: text('public_key').notNull(), // hex-encoded
  metadata: jsonb('metadata').notNull().default({}),
  domain: text('domain'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
})

export const agents = pgTable('agents', {
  did: text('did').primaryKey().references(() => identities.did),
  name: text('name').notNull(),
  description: text('description'),
  url: text('url').notNull(),
  version: varchar('version', { length: 32 }).notNull().default('1.0.0'),
  provider: jsonb('provider').$type<{ organization: string; url?: string }>(),
  capabilities: jsonb('capabilities').$type<{
    streaming?: boolean
    pushNotifications?: boolean
    stateTransitionHistory?: boolean
    a2aCompatible?: boolean
  }>().notNull().default({}),
  skills: jsonb('skills').$type<Array<{
    id: string
    name: string
    description?: string
    tags?: string[]
    examples?: string[]
    inputModes?: string[]
    outputModes?: string[]
  }>>().notNull().default([]),
  defaultInputModes: jsonb('default_input_modes').$type<string[]>().default([]),
  defaultOutputModes: jsonb('default_output_modes').$type<string[]>().default([]),
  status: varchar('status', { length: 16 }).notNull().default('online'),
  heartbeatAt: timestamp('heartbeat_at').notNull().defaultNow(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
})
