import { Command } from 'commander'
import { postJson, printResult } from './authority-utils.js'

export function createDemoCommand(): Command {
  const cmd = new Command('demo')
    .description('Run FIDES demo scenarios')

  cmd.command('run')
    .description('Run the full local Agent Trust Fabric demo')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/demo/run`, {})
        printResult('Demo run:', result, options)
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
