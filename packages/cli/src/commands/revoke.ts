import { Command } from 'commander'
import { derivePublicKeyHex, postJson, printResult } from './authority-utils.js'
import { createRevocationRecord, signRevocationRecord } from '@fides/core'

export function createRevokeCommand(): Command {
  const cmd = new Command('revoke')
    .description('Record authority revocations')

  cmd.command('agent')
    .description('Revoke an agent DID across the authority fabric')
    .argument('<did>', 'Agent DID')
    .requiredOption('--revoked-by <did>', 'Revoking principal DID')
    .requiredOption('--reason <text>', 'Revocation reason')
    .requiredOption('--private-key-hex <hex>', 'Revoking principal Ed25519 private key')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (did, options) => {
      try {
        const privateKey = Buffer.from(options.privateKeyHex, 'hex')
        const record = await signRevocationRecord(createRevocationRecord({
          did,
          reason: options.reason,
          revokedBy: options.revokedBy,
        }), privateKey)
        const result = await postJson(`${options.agentdUrl.replace(/\/$/, '')}/v1/revocations`, {
          record,
          revokerPublicKey: await derivePublicKeyHex(options.privateKeyHex),
        })
        printResult('Revocation recorded:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  return cmd
}
