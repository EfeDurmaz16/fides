import { Command } from 'commander'
import { getJson, postJson, printResult } from './authority-utils.js'

export function createPropagationCommand(): Command {
  const cmd = new Command('propagation')
    .description('Inspect and retry agentd authority propagation outbox records')

  cmd.command('pending')
    .description('List due authority propagation retries')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--limit <count>', 'Maximum records to return', '25')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const url = new URL(`${options.agentdUrl.replace(/\/$/, '')}/v1/authority/propagations/pending`)
        url.searchParams.set('limit', String(options.limit))
        const result = await getJson(url.toString())
        printResult('Pending authority propagations:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('retry')
    .description('Retry due authority propagations')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--limit <count>', 'Maximum records to retry', '25')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await postJson(`${options.agentdUrl.replace(/\/$/, '')}/v1/authority/propagations/retry`, {
          limit: Number(options.limit),
        })
        printResult('Authority propagations retried:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  return cmd
}
