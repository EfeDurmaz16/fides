import { Command } from 'commander'
import { postJson, printResult } from './authority-utils.js'

export function createSimulateCommand(): Command {
  const cmd = new Command('simulate')
    .description('Run adversarial simulations')

  cmd.command('adversarial')
    .description('Simulate fake agents, tampering, revocation, and policy denial')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/simulate/adversarial`, {})
        printResult('Adversarial simulation:', result, options)
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
