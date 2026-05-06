import { readFileSync } from 'node:fs'
import { Command } from 'commander'
import { parseJsonObject, postJson, printResult } from './authority-utils.js'

export function createAuthorizeCommand(): Command {
  const cmd = new Command('authorize')
    .description('Check agentd authorization decisions')

  cmd.command('check')
    .description('Evaluate whether an agent can use a capability')
    .requiredOption('--agent-did <did>', 'Agent DID')
    .requiredOption('--capability <id>', 'Capability ID')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--session-id <id>', 'Delegated SessionGrant ID')
    .option('--audience <value>', 'Session or policy audience')
    .option('--context-json <json>', 'Authorization context JSON object')
    .option('--policy-file <path>', 'PolicyBundle JSON file')
    .option('--attestation-valid', 'Ask agentd to include local runtime attestation')
    .option('--requires-approval', 'Mark this authorization as approval-gated')
    .option('--approval-granted', 'Mark approval as granted')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await postJson(`${options.agentdUrl.replace(/\/$/, '')}/v1/authorize`, {
          agentDid: options.agentDid,
          capabilityId: options.capability,
          ...(options.sessionId && { sessionId: options.sessionId }),
          ...(options.audience && { audience: options.audience }),
          ...(options.contextJson && { context: parseJsonObject(options.contextJson) }),
          ...(options.policyFile && { policy: JSON.parse(readFileSync(options.policyFile, 'utf-8')) }),
          ...(options.attestationValid && { attestationValid: true }),
          ...(options.requiresApproval && { requiresApproval: true }),
          ...(options.approvalGranted && { approvalGranted: true }),
        })
        printResult('Authorization decision:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  return cmd
}
