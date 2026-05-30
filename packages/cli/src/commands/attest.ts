import { Command } from 'commander'
import { getJson, postJson, printResult } from './authority-utils.js'

export function createAttestCommand(): Command {
  const cmd = new Command('attest')
    .description('Issue root v2 attestations through local agentd')

  cmd.command('runtime')
    .description('Issue a runtime attestation through agentd')
    .requiredOption('--agent <id>', 'Agent DID')
    .requiredOption('--code-hash <hash>', 'Code hash')
    .requiredOption('--runtime-hash <hash>', 'Runtime hash')
    .requiredOption('--policy-hash <hash>', 'Policy hash')
    .option('--enclave-measurement <hash>', 'TEE enclave measurement hash')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      const body = {
        agentId: options.agent,
        codeHash: options.codeHash,
        runtimeHash: options.runtimeHash,
        policyHash: options.policyHash,
        ...(options.enclaveMeasurement && { enclaveMeasurement: options.enclaveMeasurement }),
      }
      const result = await postJson(`${baseUrl(options.agentdUrl)}/attestations`, body)
      printResult('Runtime attestation issued:', result, options)
    })

  cmd.command('show')
    .description('Inspect a runtime attestation from agentd')
    .argument('<attestation-id>', 'Attestation ID')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (attestationId, options) => {
      const result = await getJson(`${baseUrl(options.agentdUrl)}/attestations/${encodeURIComponent(attestationId)}`)
      printResult('Runtime attestation:', result, options)
    })

  cmd.command('verify')
    .description('Verify a runtime attestation through agentd')
    .argument('<attestation-id>', 'Attestation ID')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (attestationId, options) => {
      const result = await postJson(`${baseUrl(options.agentdUrl)}/attestations/${encodeURIComponent(attestationId)}/verify`, {})
      printResult('Runtime attestation verification:', result, options)
    })

  return cmd
}

function baseUrl(url: string): string {
  return url.replace(/\/+$/, '')
}
