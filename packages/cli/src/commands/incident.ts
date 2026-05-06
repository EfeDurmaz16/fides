import { Command } from 'commander'
import { derivePublicKeyHex, parseList, postJson, printResult } from './authority-utils.js'
import { createIncidentRecord, signIncidentRecord } from '@fides/core'

export function createIncidentCommand(): Command {
  const cmd = new Command('incident')
    .description('Record authority incidents')

  cmd.command('report')
    .description('Report a policy, runtime, delegation, or trust incident')
    .requiredOption('--actor <did>', 'Actor DID')
    .requiredOption('--type <type>', 'Incident type')
    .requiredOption('--severity <level>', 'Incident severity')
    .requiredOption('--description <text>', 'Incident description')
    .requiredOption('--reporter <did>', 'Reporter DID')
    .requiredOption('--private-key-hex <hex>', 'Reporter Ed25519 private key')
    .option('--evidence-refs <ids>', 'Comma-separated evidence references')
    .option('--agentd-url <url>', 'agentd base URL', 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
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

  return cmd
}
