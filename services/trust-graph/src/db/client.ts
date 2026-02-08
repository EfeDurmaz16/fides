import postgres from 'postgres'
import { drizzle } from 'drizzle-orm/postgres-js'
import * as schema from './schema.js'

export function createDbClient() {
  const connectionString = process.env.DATABASE_URL || 'postgresql://localhost:5432/fides_trust'
  const sql = postgres(connectionString)
  return drizzle(sql, { schema })
}

export type DbClient = ReturnType<typeof createDbClient>
