import postgres from 'postgres'
import { drizzle } from 'drizzle-orm/postgres-js'
import * as schema from './schema.js'

export function createDbClient() {
  const connectionString = process.env.DATABASE_URL || 'postgresql://fides:fides@localhost:5432/fides'
  const connection = postgres(connectionString)
  return drizzle(connection, { schema })
}

/** Raw postgres connection for shutdown/health checks */
export function createRawClient() {
  const connectionString = process.env.DATABASE_URL || 'postgresql://fides:fides@localhost:5432/fides'
  return postgres(connectionString)
}

export type DbClient = ReturnType<typeof createDbClient>
