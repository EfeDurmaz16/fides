import { Command } from 'commander'
import { validateAgentCard } from '@fides/core'
import type { AgentCard } from '@fides/core'

export function createCardCommand(): Command {
  const cmd = new Command('card')
    .description('Agent card management')

  cmd.command('create')
    .description('Create a new AgentCard')
    .requiredOption('--did <did>', 'Agent DID')
    .option('--name <name>', 'Agent name')
    .action((options) => {
      const card: AgentCard = {
        id: options.did,
        identity: {
          did: options.did,
          publicKey: new Uint8Array(32),
          keyType: 'Ed25519',
          createdAt: new Date().toISOString(),
        },
        capabilities: [],
        endpoints: [],
        policies: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }
      const result = validateAgentCard(card)
      if (result.valid) {
        console.log('AgentCard created:', JSON.stringify(card, null, 2))
      } else {
        console.error('Validation failed:', result.errors)
        process.exit(1)
      }
    })

  cmd.command('verify')
    .description('Verify an AgentCard')
    .argument('<did>', 'DID to verify')
    .action((did) => {
      console.log(`Verifying AgentCard for ${did}...`)
    })

  return cmd
}
