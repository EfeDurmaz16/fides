import { Command } from 'commander'
import { getJson, postJson, printResult } from './authority-utils.js'

export function createAgentsCommand(): Command {
  const cmd = new Command('agents')
    .description('Registered local agent candidates')

  cmd.command('list')
    .description('List registered local agent candidates')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      const result = await getJson(`${baseUrl(options.agentdUrl)}/agents`)
      printResult('Registered agents:', result, options)
    })

  cmd.command('inspect')
    .description('Inspect a registered local agent candidate')
    .argument('<agent-id>', 'Agent DID')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (agentId, options) => {
      const result = await getJson(`${baseUrl(options.agentdUrl)}/agents/${encodeURIComponent(agentId)}`)
      printResult('Registered agent:', result, options)
    })

  return cmd
}

export function createRegisterCommand(): Command {
  return new Command('register')
    .description('Register a local AgentCard as a discovery candidate')
    .argument('<agent-card-id>', 'Local AgentCard ID')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (agentCardId, options) => {
      const result = await postJson(`${baseUrl(options.agentdUrl)}/agents/register`, { agentCardId })
      printResult('Agent registered:', result, options)
    })
}

function baseUrl(url: string): string {
  return url.replace(/\/+$/, '')
}
