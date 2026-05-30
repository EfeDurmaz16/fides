import { Command } from 'commander'
import { getJson, postJson, printResult } from './authority-utils.js'

export function createAttestCommand(): Command {
  const cmd = new Command('attest')
    .description('Issue root v2 attestations through local agentd')

  cmd.command('github')
    .description('Add a local mock GitHub trust anchor to an identity')
    .requiredOption('--identity <id>', 'Identity DID')
    .requiredOption('--handle <handle>', 'GitHub handle')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      await issueIdentityAttestation('github', { identity: options.identity, handle: options.handle }, options)
    })

  cmd.command('email')
    .description('Add a local mock email trust anchor to an identity')
    .requiredOption('--identity <id>', 'Identity DID')
    .requiredOption('--email <email>', 'Email address')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      await issueIdentityAttestation('email', { identity: options.identity, email: options.email }, options)
    })

  cmd.command('domain')
    .description('Add a local mock domain trust anchor to an identity')
    .requiredOption('--identity <id>', 'Identity DID')
    .requiredOption('--domain <domain>', 'Domain name')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      await issueIdentityAttestation('domain', { identity: options.identity, domain: options.domain }, options)
    })

  cmd.command('package')
    .description('Add a local mock package registry trust anchor to an identity')
    .requiredOption('--identity <id>', 'Identity DID')
    .requiredOption('--registry <registry>', 'Package registry: npm or pypi')
    .requiredOption('--package <name>', 'Package name')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      await issueIdentityAttestation('package', {
        identity: options.identity,
        registry: options.registry,
        package: options.package,
      }, options)
    })

  cmd.command('wallet')
    .description('Add a local mock wallet trust anchor to an identity')
    .requiredOption('--identity <id>', 'Identity DID')
    .requiredOption('--address <address>', 'Wallet address')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      await issueIdentityAttestation('wallet', { identity: options.identity, address: options.address }, options)
    })

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

async function issueIdentityAttestation(
  type: string,
  body: Record<string, unknown>,
  options: { agentdUrl: string; json?: boolean }
): Promise<void> {
  const result = await postJson(`${baseUrl(options.agentdUrl)}/attestations`, {
    type,
    ...body,
  })
  printResult('Identity attestation issued:', result, options)
}

function baseUrl(url: string): string {
  return url.replace(/\/+$/, '')
}
