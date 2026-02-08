import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import * as schema from './schema.js'

const connectionString = process.env.DATABASE_URL || 'postgresql://localhost:5432/fides_discovery'

export const sql = postgres(connectionString)
export const db = drizzle(sql, { schema })
