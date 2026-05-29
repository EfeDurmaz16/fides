import { Command } from 'commander'
import { getJson, postJson, printResult } from './authority-utils.js'

export function createEvidenceCommand(): Command {
  const cmd = new Command('evidence')
    .description('Evidence ledger commands')

  cmd.command('list')
    .description('List evidence events')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await getJson(`${baseUrl(options.agentdUrl)}/evidence`)
        printResult('Evidence events:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('inspect')
    .description('Inspect an evidence event')
    .argument('<event-id>', 'Evidence event ID')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (eventId, options) => {
      try {
        const result = await getJson(`${baseUrl(options.agentdUrl)}/evidence/${encodeURIComponent(eventId)}`)
        printResult('Evidence event:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('verify')
    .description('Verify the evidence hash chain')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/evidence/verify`, {})
        printResult('Evidence verification:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('export')
    .description('Export evidence events')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/evidence/export`, {})
        printResult('Evidence export:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  return cmd
}

function baseUrl(url: string): string {
  return url.replace(/\/+$/, '')
}
