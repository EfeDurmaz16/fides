import { Command } from 'commander'
import { getJson, parseList, parseJsonObject, parseTokenInput, postJson, printResult } from './authority-utils.js'

export function createSessionCommand(): Command {
  const cmd = new Command('session')
    .description('Create and revoke delegated agentd sessions')

  cmd.command('request')
    .description('Request a root v2 SessionGrant for an agent capability')
    .argument('<agent-id>', 'Target agent DID')
    .requiredOption('--capability <id>', 'Capability ID')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--principal-id <did>', 'Principal DID')
    .option('--requester-agent-id <did>', 'Requester agent DID')
    .option('--requested-scopes <list>', 'Comma-separated requested scopes')
    .option('--constraints-json <json>', 'Session constraints JSON object')
    .option('--attestation-id <id>', 'Runtime attestation ID')
    .option('--approval-granted', 'Mark approval as granted for policy evaluation')
    .option('--json', 'Print JSON only')
    .action(async (agentId, options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/sessions`, {
          agentId,
          capability: options.capability,
          requestedScopes: parseList(options.requestedScopes),
          ...(options.principalId && { principalId: options.principalId }),
          ...(options.requesterAgentId && { requesterAgentId: options.requesterAgentId }),
          ...(options.constraintsJson && { constraints: parseJsonObject(options.constraintsJson) }),
          ...(options.attestationId && { attestationId: options.attestationId }),
          ...(options.approvalGranted && { approvalGranted: true }),
        })
        printResult('Session requested:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('verify')
    .description('Verify a root v2 SessionGrant')
    .argument('<session-id>', 'Session ID')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (sessionId, options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/sessions/${encodeURIComponent(sessionId)}/verify`, {})
        printResult('Session verification:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('show')
    .description('Read a root v2 SessionGrant')
    .argument('<session-id>', 'Session ID')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (sessionId, options) => {
      try {
        const result = await getJson(`${baseUrl(options.agentdUrl)}/sessions/${encodeURIComponent(sessionId)}`)
        printResult('Session:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('create')
    .description('Create an agentd SessionGrant from a DelegationToken')
    .requiredOption('--capability <id>', 'Capability ID')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--token-file <path>', 'DelegationToken JSON file')
    .option('--token-json <json>', 'DelegationToken JSON string')
    .option('--delegator-public-key <hex>', 'Delegator Ed25519 public key as 32-byte hex')
    .option('--audience <value>', 'Session audience', 'agentd')
    .option('--ttl-ms <ms>', 'Session TTL in milliseconds')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const token = parseTokenInput(options)
        const tokenBody = createSessionTokenBody(token, options)
        const result = await postJson(`${options.agentdUrl.replace(/\/$/, '')}/v1/sessions`, {
          ...tokenBody,
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

function baseUrl(url: string): string {
  return url.replace(/\/+$/, '')
}

function createSessionTokenBody(
  token: unknown,
  options: { delegatorPublicKey?: string }
): { token: unknown; delegatorPublicKey?: string } | { signedToken: unknown } {
  if (isCanonicalSignedObject(token)) {
    if (options.delegatorPublicKey) {
      throw new Error('--delegator-public-key is only valid for legacy DelegationToken input')
    }
    return { signedToken: token }
  }

  return {
    token,
    ...(options.delegatorPublicKey && { delegatorPublicKey: options.delegatorPublicKey }),
  }
}

function isCanonicalSignedObject(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false
  const candidate = value as { payload?: unknown; proof?: unknown }
  if (!candidate.payload || typeof candidate.payload !== 'object') return false
  if (!candidate.proof || typeof candidate.proof !== 'object') return false
  const proof = candidate.proof as { verificationMethod?: unknown; proofValue?: unknown }
  return typeof proof.verificationMethod === 'string' && typeof proof.proofValue === 'string'
}
