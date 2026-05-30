import { readFileSync } from 'node:fs'
import {
  createInvocationRequest,
  deriveEd25519PublicKeyHex,
  didFromPublicKey,
  signInvocationRequest,
  type SessionGrantV2,
  type SignedInvocationRequest,
} from '@fides/core'
import { Command } from 'commander'
import { getJson, parseList, parseJsonObject, postJson, printResult } from './authority-utils.js'

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
    .option('--sign', 'Sign the invocation request with the requester agent key')
    .option('--requester-private-key <hex>', 'Requester Ed25519 private key as 32-byte hex')
    .option('--requester-private-key-file <path>', 'File containing requester Ed25519 private key hex')
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
        const wantsSignedRequest = shouldSignInvocation(options)
        const session = options.sessionId
          ? wantsSignedRequest ? await getSession(baseUrl, options.sessionId) : undefined
          : await createSession(baseUrl, agentId, options)
        const sessionId = session?.session_id ?? options.sessionId
        if (!sessionId) {
          throw new Error('Either --session-id or <agentId> with --capability is required')
        }

        const signedRequest = session
          ? await maybeSignInvocationRequest(session, input, options)
          : undefined
        const result = await postJson(`${baseUrl}/invoke`, {
          sessionId,
          input,
          ...(options.dryRun && { dryRun: true }),
          ...(signedRequest && { signedRequest }),
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

function shouldSignInvocation(options: {
  sign?: boolean
  requesterPrivateKey?: string
  requesterPrivateKeyFile?: string
}): boolean {
  return Boolean(options.sign || options.requesterPrivateKey || options.requesterPrivateKeyFile)
}

async function createSession(baseUrl: string, agentId: string | undefined, options: {
  capability?: string
  principalId?: string
  requesterAgentId?: string
  requestedScopes?: string
  constraintsJson?: string
  attestationId?: string
  approvalGranted?: boolean
}): Promise<SessionGrantV2> {
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
  return parseSessionGrant((response as { session?: unknown }).session, 'Session response did not include a valid session')
}

async function getSession(baseUrl: string, sessionId: string): Promise<SessionGrantV2> {
  const response = await getJson(`${baseUrl}/sessions/${encodeURIComponent(sessionId)}`)
  if (!response || typeof response !== 'object') {
    throw new Error('Session lookup response was not an object')
  }
  return parseSessionGrant((response as { session?: unknown }).session, 'Session lookup response did not include a valid session')
}

async function maybeSignInvocationRequest(
  session: SessionGrantV2,
  input: unknown,
  options: {
    sign?: boolean
    requesterPrivateKey?: string
    requesterPrivateKeyFile?: string
    dryRun?: boolean
  }
): Promise<SignedInvocationRequest | undefined> {
  if (!options.sign && !options.requesterPrivateKey && !options.requesterPrivateKeyFile) {
    return undefined
  }

  const privateKeyHex = readPrivateKeyHex(options)
  const publicKeyHex = await deriveEd25519PublicKeyHex(privateKeyHex)
  const signerDid = didFromPublicKey(Uint8Array.from(Buffer.from(publicKeyHex, 'hex')))
  if (signerDid !== session.requester_agent_id) {
    throw new Error(`Requester private key resolves to ${signerDid}, expected ${session.requester_agent_id}`)
  }

  const request = createInvocationRequest({
    issuer: session.requester_agent_id,
    sessionGrant: session,
    input,
    dryRun: options.dryRun,
  })

  return signInvocationRequest(
    request,
    Uint8Array.from(Buffer.from(privateKeyHex, 'hex')),
    session.requester_agent_id
  )
}

function readPrivateKeyHex(options: { requesterPrivateKey?: string; requesterPrivateKeyFile?: string }): string {
  const value = options.requesterPrivateKeyFile
    ? readFileSync(options.requesterPrivateKeyFile, 'utf-8')
    : options.requesterPrivateKey
  if (!value) {
    throw new Error('--requester-private-key or --requester-private-key-file is required when signing')
  }

  const hex = value.trim()
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('Requester private key must be a 32-byte hex string')
  }
  return hex.toLowerCase()
}

function parseSessionGrant(value: unknown, message: string): SessionGrantV2 {
  if (!value || typeof value !== 'object') {
    throw new Error(message)
  }

  const session = value as Partial<SessionGrantV2>
  if (
    typeof session.session_id !== 'string' ||
    typeof session.requester_agent_id !== 'string' ||
    typeof session.target_agent_id !== 'string' ||
    typeof session.principal_id !== 'string' ||
    typeof session.capability !== 'string' ||
    !Array.isArray(session.scopes)
  ) {
    throw new Error('Session response did not include session.session_id')
  }

  return session as SessionGrantV2
}
