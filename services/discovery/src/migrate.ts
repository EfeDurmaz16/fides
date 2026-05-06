import { runDiscoveryMigrations, sql } from './db/client.js'

async function main() {
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
