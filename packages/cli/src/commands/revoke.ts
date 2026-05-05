import { Command } from 'commander'
import { postJson, printResult } from './authority-utils.js'

export function createRevokeCommand(): Command {
  const cmd = new Command('revoke')
    .description('Record authority revocations')

  cmd.command('agent')
    .description('Revoke an agent DID across the authority fabric')
    .argument('<did>', 'Agent DID')
    .requiredOption('--revoked-by <did>', 'Revoking principal DID')
    .requiredOption('--reason <text>', 'Revocation reason')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--signature <hex>', 'External revocation signature')
    .option('--json', 'Print JSON only')
    .action(async (did, options) => {
      try {
        const result = await postJson(`${options.agentdUrl.replace(/\/$/, '')}/v1/revocations`, {
          did,
          reason: options.reason,
          revokedBy: options.revokedBy,
          ...(options.signature && { signature: options.signature }),
        })
        printResult('Revocation recorded:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  return cmd
}

