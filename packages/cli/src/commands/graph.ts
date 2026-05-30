import { Command } from 'commander'
import { getJson, printResult } from './authority-utils.js'

export function createGraphCommand(): Command {
  const cmd = new Command('graph')
    .description('Inspect local trust graph views')

  cmd.command('inspect')
    .description('Inspect local trust graph state for an agent candidate')
    .argument('<agent-id>', 'Agent DID to inspect')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (agentId, options) => {
      const result = await getJson(`${baseUrl(options.agentdUrl)}/trust/${encodeURIComponent(agentId)}`)
      printResult('Trust graph view:', {
        agentId,
        authorityGranted: false,
        graphView: result,
      }, options)
    })

  return cmd
}

function baseUrl(url: string): string {
  return url.replace(/\/$/, '')
}
