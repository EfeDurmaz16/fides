import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import * as schema from './schema.js'

const DEV_FALLBACK = 'postgresql://fides:fides@localhost:5432/fides'

function getConnectionString(): string {
  const url = process.env.DATABASE_URL
  if (url) return url

  if (process.env.NODE_ENV === 'production') {
    throw new Error('DATABASE_URL must be set in production')
  }

  console.warn('DATABASE_URL not set — using development fallback')
  return DEV_FALLBACK
}

const poolConfig = {
  max: parseInt(process.env.DB_POOL_MAX || '10', 10),
  idle_timeout: 20,
  connect_timeout: 10,
}

const connectionString = getConnectionString()

export const sql = postgres(connectionString, poolConfig)
export const db = drizzle(sql, { schema })
