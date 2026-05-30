import { Command } from 'commander'
import { getJson, postJson, printResult } from './authority-utils.js'

export function createReputationCommand(): Command {
  const cmd = new Command('reputation')
    .description('Capability-specific reputation records')

  cmd.command('update')
    .description('Update root v2 capability-specific reputation')
    .requiredOption('--agent <id>', 'Agent DID')
    .requiredOption('--capability <capability>', 'Capability ID')
    .option('--publisher <id>', 'Publisher DID')
    .option('--principal <id>', 'Principal DID')
    .option('--successful-invocations <count>', 'Successful invocation count')
    .option('--failed-invocations <count>', 'Failed invocation count')
    .option('--incident-count <count>', 'Incident count')
    .option('--publisher-weight <weight>', 'Publisher weight')
    .option('--context-boundary-mismatch', 'Apply context boundary mismatch penalty')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      const result = await postJson(`${baseUrl(options.agentdUrl)}/reputation/update`, {
        agentId: options.agent,
        capability: options.capability,
        ...(options.publisher && { publisherId: options.publisher }),
        ...(options.principal && { principalId: options.principal }),
        ...(options.successfulInvocations && { successfulInvocations: Number(options.successfulInvocations) }),
        ...(options.failedInvocations && { failedInvocations: Number(options.failedInvocations) }),
        ...(options.incidentCount && { incidentCount: Number(options.incidentCount) }),
        ...(options.publisherWeight && { publisherWeight: Number(options.publisherWeight) }),
        ...(options.contextBoundaryMismatch && { contextBoundaryMismatch: true }),
      })
      printResult('Reputation updated:', result, options)
    })

  cmd.command('get')
    .description('Get root v2 reputation records for an agent')
    .argument('<agent-id>', 'Agent DID')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (agentId, options) => {
      const result = await getJson(`${baseUrl(options.agentdUrl)}/reputation/${encodeURIComponent(agentId)}`)
      printResult('Reputation records:', result, options)
    })

  return cmd
}

function baseUrl(url: string): string {
  return url.replace(/\/+$/, '')
}
