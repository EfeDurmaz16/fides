import { readFileSync } from 'node:fs'
import { Command } from 'commander'
import { parseList, parseJsonObject, postJson, printResult } from './authority-utils.js'

export function createInvokeCommand(): Command {
  return new Command('invoke')
    .description('Invoke a capability through the local agentd authority path')
    .argument('[agentId]', 'Target agent DID when creating a session first')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--session-id <id>', 'Existing SessionGrant ID')
    .option('--capability <capability>', 'Capability ID when creating a session first')
    .option('--input <path>', 'Invocation input JSON file')
    .option('--input-json <json>', 'Invocation input JSON object')
    .option('--dry-run', 'Request dry-run execution')
    .option('--principal-id <did>', 'Principal DID for session creation')
    .option('--requester-agent-id <did>', 'Requester agent DID for session creation')
    .option('--requested-scopes <list>', 'Comma-separated requested scopes for session creation')
    .option('--constraints-json <json>', 'Session constraint JSON object')
    .option('--attestation-id <id>', 'Runtime attestation ID for session policy')
    .option('--approval-granted', 'Mark approval as granted for session policy')
    .option('--json', 'Print JSON only')
    .action(async (agentId, options) => {
      try {
        const input = readInput(options)
        const baseUrl = options.agentdUrl.replace(/\/$/, '')
        const sessionId = options.sessionId ?? await createSession(baseUrl, agentId, options)
        const result = await postJson(`${baseUrl}/invoke`, {
          sessionId,
          input,
          ...(options.dryRun && { dryRun: true }),
        })
        printResult('Invocation result:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })
}

function readInput(options: { input?: string; inputJson?: string }): unknown {
  if (options.input) return JSON.parse(readFileSync(options.input, 'utf-8'))
  if (options.inputJson) return JSON.parse(options.inputJson)
  return {}
}

async function createSession(baseUrl: string, agentId: string | undefined, options: {
  capability?: string
  principalId?: string
  requesterAgentId?: string
  requestedScopes?: string
  constraintsJson?: string
  attestationId?: string
  approvalGranted?: boolean
}): Promise<string> {
  if (!agentId || !options.capability) {
    throw new Error('Either --session-id or <agentId> with --capability is required')
  }

  const response = await postJson(`${baseUrl}/sessions`, {
    agentId,
    capability: options.capability,
    requestedScopes: parseList(options.requestedScopes),
    ...(options.principalId && { principalId: options.principalId }),
    ...(options.requesterAgentId && { requesterAgentId: options.requesterAgentId }),
    ...(options.constraintsJson && { constraints: parseJsonObject(options.constraintsJson) }),
    ...(options.attestationId && { attestationId: options.attestationId }),
    ...(options.approvalGranted && { approvalGranted: true }),
  })

  if (!response || typeof response !== 'object') {
    throw new Error('Session response was not an object')
  }
  const session = (response as { session?: { session_id?: unknown } }).session
  if (typeof session?.session_id !== 'string') {
    throw new Error('Session response did not include session.session_id')
  }
  return session.session_id
}
