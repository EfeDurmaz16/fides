import { Command } from 'commander'
import { evaluatePolicy, type PolicyBundle } from '@fides/policy'
import { readFileSync } from 'node:fs'
import { parseList, postJson, printResult } from './authority-utils.js'

export function createPolicyCommand(): Command {
  const cmd = new Command('policy')
    .description('Policy evaluation')

  cmd.command('evaluate')
    .description('Evaluate a policy against context')
    .option('--bundle <path>', 'Policy bundle JSON file')
    .option('--context <json>', 'JSON context string or file path')
    .option('--agent <id>', 'Target agent DID for root v2 policy evaluation')
    .option('--capability <capability>', 'Capability ID for root v2 policy evaluation')
    .option('--principal <id>', 'Principal DID')
    .option('--requester-agent <id>', 'Requester agent DID')
    .option('--requested-scopes <csv>', 'Comma-separated requested scopes')
    .option('--runtime-attestation-valid', 'Mark runtime attestation as valid')
    .option('--revocation-active', 'Mark revocation as active')
    .option('--kill-switch-active', 'Mark kill switch as active')
    .option('--incidents-active', 'Mark incidents as active')
    .option('--approval-granted', 'Mark human approval as granted')
    .option('--evidence-refs <csv>', 'Comma-separated evidence event IDs')
    .option('--agentd-url <url>', 'Evaluate policy through local agentd')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        if (options.agentdUrl) {
          if (!options.agent || !options.capability) {
            throw new Error('--agent and --capability are required with --agentd-url')
          }
          const result = await postJson(`${baseUrl(options.agentdUrl)}/policy/evaluate`, {
            agentId: options.agent,
            capability: options.capability,
            ...(options.principal && { principalId: options.principal }),
            ...(options.requesterAgent && { requesterAgentId: options.requesterAgent }),
            requestedScopes: parseList(options.requestedScopes),
            ...(options.runtimeAttestationValid && { runtimeAttestationValid: true }),
            ...(options.revocationActive && { revocationActive: true }),
            ...(options.killSwitchActive && { killSwitchActive: true }),
            ...(options.incidentsActive && { incidentsActive: true }),
            ...(options.approvalGranted && { approvalGranted: true }),
            evidenceRefs: parseList(options.evidenceRefs),
          })
          printResult('Policy decision:', result, options)
          return
        }

        if (!options.bundle || !options.context) {
          throw new Error('--bundle and --context are required without --agentd-url')
        }
        const bundle: PolicyBundle = JSON.parse(readFileSync(options.bundle, 'utf-8'))
        let context: Record<string, unknown>

        if (options.context.endsWith('.json')) {
          context = JSON.parse(readFileSync(options.context, 'utf-8'))
        } else {
          context = JSON.parse(options.context)
        }

        const result = evaluatePolicy(bundle, context)
        console.log(`Decision: ${result.decision}`)
        console.log(`Explanation: ${result.explanation.decision}`)
        console.log(`Matched rules: ${result.matchedRules.join(', ') || 'none'}`)
        console.log(`Factors:`)
        for (const f of result.explanation.factors) {
          console.log(`  - ${f.factor} (weight: ${f.weight}): ${f.description}`)
        }
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
