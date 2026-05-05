import postgres from 'postgres'
import { runAuthorityMigrations } from './storage.js'

async function main() {
  const connectionString = process.env.AGENTD_DATABASE_URL || process.env.DATABASE_URL
  if (!connectionString) {
    throw new Error('AGENTD_DATABASE_URL or DATABASE_URL is required')
  }

  const sql = postgres(connectionString, {
    max: 1,
    idle_timeout: 5,
    connect_timeout: 10,
  })

  try {
    await runAuthorityMigrations(sql)
    console.log('agentd authority store migrations applied')
  } finally {
    await sql.end()
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
