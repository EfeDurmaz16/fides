import { Command } from 'commander'
import { parseTokenInput, postJson, printResult } from './authority-utils.js'

export function createSessionCommand(): Command {
  const cmd = new Command('session')
    .description('Create and revoke delegated agentd sessions')

  cmd.command('create')
    .description('Create an agentd SessionGrant from a DelegationToken')
    .requiredOption('--capability <id>', 'Capability ID')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--token-file <path>', 'DelegationToken JSON file')
    .option('--token-json <json>', 'DelegationToken JSON string')
    .option('--audience <value>', 'Session audience', 'agentd')
    .option('--ttl-ms <ms>', 'Session TTL in milliseconds')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const token = parseTokenInput(options)
        const result = await postJson(`${options.agentdUrl.replace(/\/$/, '')}/v1/sessions`, {
          token,
          capabilityId: options.capability,
          audience: options.audience,
          ...(options.ttlMs && { ttlMs: Number(options.ttlMs) }),
        })
        printResult('Session created:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('revoke')
    .description('Revoke an agentd SessionGrant')
    .argument('<sessionId>', 'Session ID')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--reason <text>', 'Revocation reason', 'revoked by CLI')
    .option('--json', 'Print JSON only')
    .action(async (sessionId, options) => {
      try {
        const result = await postJson(`${options.agentdUrl.replace(/\/$/, '')}/v1/sessions/${encodeURIComponent(sessionId)}/revoke`, {
          reason: options.reason,
        })
        printResult('Session revoked:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  return cmd
}

