import { createRawClient, runDiscoveryMigrations } from './db/client.js'

async function main() {
  const sql = createRawClient()
  try {
    await runDiscoveryMigrations(sql)
    console.log('discovery migrations applied')
  } finally {
    await sql.end()
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
