import { Command } from 'commander'
import { derivePublicKeyHex, getJson, parseList, postJson, printResult } from './authority-utils.js'
import { createRevocationRecord, signRevocationRecord } from '@fides/core'

export function createRevokeCommand(): Command {
  const cmd = new Command('revoke')
    .description('Record authority revocations')

  cmd.command('agent')
    .description('Revoke an agent DID across the authority fabric')
    .argument('<did>', 'Agent DID')
    .option('--revoked-by <did>', 'Legacy v1 revoking principal DID')
    .option('--reason <text>', 'Revocation reason', 'Revoked by CLI')
    .option('--issuer <did>', 'Root v2 issuer DID')
    .option('--private-key-hex <hex>', 'Revoking principal Ed25519 private key for legacy v1 signed revocations')
    .option('--evidence-refs <ids>', 'Comma-separated evidence references')
    .option('--expires-at <iso>', 'Optional revocation expiry timestamp')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (did, options) => {
      try {
        if (!options.privateKeyHex) {
          const result = await postRootRevocation(options.agentdUrl, {
            targetType: 'agent',
            targetId: did,
            reason: options.reason,
            issuer: options.issuer,
            evidenceRefs: parseList(options.evidenceRefs),
            expiresAt: options.expiresAt,
          })
          printResult('Revocation recorded:', result, options)
          return
        }
        if (!options.revokedBy) {
          throw new Error('--revoked-by is required for legacy signed revocations')
        }
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

  for (const targetType of ['key', 'identity', 'card', 'capability', 'session', 'attestation', 'publisher'] as const) {
    cmd.command(targetType)
      .description(`Record a root v2 ${targetType} revocation`)
      .argument('<id>', `${targetType} ID`)
      .option('--reason <text>', 'Revocation reason', 'Revoked by CLI')
      .option('--issuer <did>', 'Issuer DID')
      .option('--evidence-refs <ids>', 'Comma-separated evidence references')
      .option('--expires-at <iso>', 'Optional revocation expiry timestamp')
      .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
      .option('--json', 'Print JSON only')
      .action(async (id, options) => {
        try {
          const result = await postRootRevocation(options.agentdUrl, {
            targetType: targetType === 'card' ? 'agent_card' : targetType,
            targetId: id,
            reason: options.reason,
            issuer: options.issuer,
            evidenceRefs: parseList(options.evidenceRefs),
            expiresAt: options.expiresAt,
          })
          printResult('Revocation recorded:', result, options)
        } catch (error) {
          console.error('Error:', error instanceof Error ? error.message : String(error))
          process.exit(1)
        }
      })
  }

  cmd.command('list')
    .description('List root v2 revocations')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await getJson(`${baseUrl(options.agentdUrl)}/revocations`)
        printResult('Revocations:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('inspect')
    .description('Inspect a root v2 revocation by record ID or target ID')
    .argument('<id>', 'Revocation record ID or target ID')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (id, options) => {
      try {
        const result = await getJson(`${baseUrl(options.agentdUrl)}/revocations/${encodeURIComponent(id)}`)
        printResult('Revocation:', result, options)
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

function postRootRevocation(agentdUrl: string, body: {
  targetType: string
  targetId: string
  reason?: string
  issuer?: string
  evidenceRefs?: string[]
  expiresAt?: string
}): Promise<unknown> {
  return postJson(`${baseUrl(agentdUrl)}/revocations`, {
    targetType: body.targetType,
    targetId: body.targetId,
    reason: body.reason,
    ...(body.issuer && { issuer: body.issuer }),
    ...(body.evidenceRefs && body.evidenceRefs.length > 0 ? { evidenceRefs: body.evidenceRefs } : {}),
    ...(body.expiresAt && { expiresAt: body.expiresAt }),
  })
}
