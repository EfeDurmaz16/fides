import { Command } from 'commander'
import { getJson, postJson, printResult } from './authority-utils.js'

export function createDhtCommand(): Command {
  const cmd = new Command('dht')
    .description('DHT pointer discovery commands')

  cmd.command('publish')
    .description('Publish an AgentCard pointer to the local DHT service')
    .argument('[agent-card]', 'AgentCard path or URL for external/unresolved pointers')
    .option('--capability <capability>', 'Capability ID for the pointer')
    .option('--agent-id <agent-id>', 'Registered local agent DID for signed local pointer publish')
    .option('--agent-card-id <agent-card-id>', 'Registered local AgentCard ID for signed local pointer publish')
    .option('--agent-card-url <url>', 'Optional AgentCard URL; omitted local records use local://agent-cards/<card-id>')
    .option('--expires-at <iso>', 'Pointer expiry timestamp')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (agentCard, options) => {
      try {
        if (!options.capability) {
          throw new Error('--capability is required')
        }
        if (!agentCard && !options.agentId && !options.agentCardId) {
          throw new Error('provide an AgentCard path/URL, --agent-id, or --agent-card-id')
        }
        const result = await postJson(`${baseUrl(options.agentdUrl)}/dht/publish`, {
          capability: options.capability,
          ...(agentCard ? { agentCard } : {}),
          ...(options.agentId ? { agentId: options.agentId } : {}),
          ...(options.agentCardId ? { agentCardId: options.agentCardId } : {}),
          ...(options.agentCardUrl ? { agentCardUrl: options.agentCardUrl } : {}),
          ...(options.expiresAt ? { expiresAt: options.expiresAt } : {}),
        })
        printResult('DHT pointer published:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('find')
    .description('Find AgentCard pointers by capability')
    .requiredOption('--capability <capability>', 'Capability ID')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await getJson(`${baseUrl(options.agentdUrl)}/dht/find?capability=${encodeURIComponent(options.capability)}`)
        printResult('DHT pointers:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('start')
    .description('Start DHT service through agentd')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/dht/start`, {})
        printResult('DHT service started:', result, options)
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
