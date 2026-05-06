import { createRawClient, runTrustGraphMigrations } from './db/client.js'

async function main() {
  const sql = createRawClient()
  try {
    await runTrustGraphMigrations(sql)
    console.log('trust-graph migrations applied')
  } finally {
    await sql.end()
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
