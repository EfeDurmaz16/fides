import postgres from 'postgres'
import { runRegistryMigrations } from './storage.js'

async function main(): Promise<void> {
  const connectionString = process.env.REGISTRY_DATABASE_URL || process.env.DATABASE_URL
  if (!connectionString) {
    throw new Error('REGISTRY_DATABASE_URL or DATABASE_URL is required')
  }

  const sql = postgres(connectionString, {
    max: 1,
    idle_timeout: 5,
    connect_timeout: 10,
  })

  try {
    await runRegistryMigrations(sql)
    console.log('Registry migrations applied')
  } finally {
    await sql.end()
  }
}

main().catch(error => {
  console.error(error)
  process.exit(1)
})
