import { Command } from 'commander'
import { getJson, postJson, printResult } from './authority-utils.js'

export function createDhtCommand(): Command {
  const cmd = new Command('dht')
    .description('DHT pointer discovery commands')

  cmd.command('publish')
    .description('Publish an AgentCard pointer to the local DHT service')
    .argument('<agent-card>', 'AgentCard path or URL')
    .option('--capability <capability>', 'Capability ID for the pointer')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (agentCard, options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/dht/publish`, {
          agentCard,
          capability: options.capability,
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
