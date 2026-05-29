import { Command } from 'commander'
import { getJson, parseList, postJson, printResult } from './authority-utils.js'

export function createRegistryCommand(): Command {
  const cmd = new Command('registry')
    .description('Local agentd registry discovery commands')

  cmd.command('start')
    .description('Start the local mock registry through agentd')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/registry/start`, {})
        printResult('Registry started:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('publish')
    .description('Publish a registered local AgentCard to the local mock registry')
    .argument('<agent-card-id>', 'Local AgentCard ID')
    .option('--mode <mode>', 'Registry mode: public or private', 'public')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (agentCardId, options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/registry/publish`, {
          agentCardId,
          mode: options.mode,
        })
        printResult('Registry record published:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('search')
    .description('Search local mock registry records by capability')
    .requiredOption('--capability <capability>', 'Capability ID')
    .option('--supported-versions <versions>', 'Comma-separated FIDES protocol versions supported by the requester')
    .option('--required-versions <versions>', 'Comma-separated FIDES protocol versions required by the requester')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/registry/search`, {
          capability: options.capability,
          ...(options.supportedVersions ? { supported_versions: parseList(options.supportedVersions) } : {}),
          ...(options.requiredVersions ? { required_versions: parseList(options.requiredVersions) } : {}),
        })
        printResult('Registry records:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('index')
    .description('Read the local mock registry index')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await getJson(`${baseUrl(options.agentdUrl)}/registry/index`)
        printResult('Registry index:', result, options)
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
