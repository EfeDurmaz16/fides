import { Command } from 'commander'
import { MockTEEProvider } from '@fides/runtime'
import { readFileSync } from 'node:fs'

export function createRuntimeCommand(): Command {
  const cmd = new Command('runtime')
    .description('Runtime attestation')

  cmd.command('attest')
    .description('Create a runtime attestation')
    .requiredOption('--did <did>', 'Agent DID')
    .option('--provider <name>', 'TEE provider', 'mock-tee')
    .action(async (options) => {
      try {
        const provider = new MockTEEProvider()
        const attestation = await provider.attest(options.did)
        const verified = await provider.verify(attestation)

        console.log('Runtime Attestation:')
        console.log(`  ID: ${attestation.id}`)
        console.log(`  Agent: ${attestation.agentDid}`)
        console.log(`  Provider: ${attestation.provider}`)
        console.log(`  Measurement: ${attestation.measurement}`)
        console.log(`  Timestamp: ${attestation.timestamp}`)
        console.log(`  Expires: ${attestation.expiresAt}`)
        console.log(`  Verified: ${verified}`)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('verify')
    .description('Verify a runtime attestation')
    .requiredOption('--attestation <json>', 'Attestation JSON string or file path')
    .action(async (options) => {
      try {
        let attestation
        if (options.attestation.endsWith('.json')) {
          attestation = JSON.parse(readFileSync(options.attestation, 'utf-8'))
        } else {
          attestation = JSON.parse(options.attestation)
        }

        const provider = new MockTEEProvider()
        const verified = await provider.verify(attestation)
        console.log(`Verified: ${verified}`)
        if (!verified) {
          process.exit(1)
        }
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  return cmd
}
