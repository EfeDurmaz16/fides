import { Command } from 'commander'
import { derivePublicKeyHex, getJson, parseList, postJson, printResult } from './authority-utils.js'
import { createIncidentRecord, signIncidentRecord } from '@fides/core'

export function createIncidentCommand(): Command {
  const cmd = new Command('incident')
    .description('Record authority incidents')

  cmd.command('report')
    .description('Report a policy, runtime, delegation, or trust incident')
    .argument('[agent-id]', 'Target agent DID for root v2 incident reporting')
    .option('--actor <did>', 'Legacy v1 actor DID')
    .option('--type <type>', 'Legacy v1 incident type')
    .requiredOption('--severity <level>', 'Incident severity')
    .requiredOption('--description <text>', 'Incident description')
    .option('--category <category>', 'Root v2 incident category', 'suspicious_behavior')
    .option('--reporter <did>', 'Reporter DID')
    .option('--private-key-hex <hex>', 'Reporter Ed25519 private key for legacy v1 signed incidents')
    .option('--evidence-refs <ids>', 'Comma-separated evidence references')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (agentId, options) => {
      try {
        if (!options.privateKeyHex) {
          const targetAgentId = agentId ?? options.actor
          if (!targetAgentId) {
            throw new Error('agent-id or --actor is required for root incident reporting')
          }
          const result = await postJson(`${baseUrl(options.agentdUrl)}/incidents`, {
            targetAgentId,
            severity: options.severity,
            category: options.category,
            description: options.description,
            ...(options.reporter && { reporter: options.reporter }),
            evidenceRefs: parseList(options.evidenceRefs),
          })
          printResult('Incident recorded:', result, options)
          return
        }
        if (!options.actor || !options.type || !options.reporter) {
          throw new Error('--actor, --type, --reporter, and --private-key-hex are required for legacy signed incidents')
        }
        const privateKey = Buffer.from(options.privateKeyHex, 'hex')
        const record = await signIncidentRecord(createIncidentRecord({
          actor: options.actor,
          reportedBy: options.reporter,
          type: options.type,
          severity: options.severity,
          description: options.description,
          evidenceRefs: parseList(options.evidenceRefs),
        }), privateKey)
        const result = await postJson(`${options.agentdUrl.replace(/\/$/, '')}/v1/incidents`, {
          record,
          reporterPublicKey: await derivePublicKeyHex(options.privateKeyHex),
        })
        printResult('Incident recorded:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('list')
    .description('List root v2 incidents')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await getJson(`${baseUrl(options.agentdUrl)}/incidents`)
        printResult('Incidents:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('inspect')
    .description('Inspect a root v2 incident')
    .argument('<incident-id>', 'Incident ID')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (incidentId, options) => {
      try {
        const result = await getJson(`${baseUrl(options.agentdUrl)}/incidents/${encodeURIComponent(incidentId)}`)
        printResult('Incident:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('resolve')
    .description('Resolve a root v2 incident')
    .argument('<incident-id>', 'Incident ID')
    .option('--status <status>', 'Resolution status: resolved, dismissed, false_positive', 'resolved')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (incidentId, options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/incidents/${encodeURIComponent(incidentId)}/resolve`, {
          status: options.status,
        })
        printResult('Incident resolved:', result, options)
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
