import { Command } from 'commander'
import { validateAgentCard, createIdentity, classifyCapabilityRisk } from '@fides/core'
import type { AgentCard, CapabilityDescriptor } from '@fides/core'
import { DiscoveryClient } from '@fides/sdk'
import { WellKnownDiscoveryProvider } from '@fides/discovery'
import { readFileSync } from 'node:fs'

export function createCardCommand(): Command {
  const cmd = new Command('card')
    .description('Agent card management')

  cmd.command('create')
    .description('Create a new AgentCard')
    .requiredOption('--did <did>', 'Agent DID')
    .option('--name <name>', 'Agent name')
    .option('--capabilities <json>', 'Capabilities JSON array')
    .action((options) => {
      const identity = createIdentity(options.did, 'agent', { name: options.name || 'Unknown' })

      let capabilities: CapabilityDescriptor[] = []
      if (options.capabilities) {
        capabilities = JSON.parse(options.capabilities)
      }

      const card: AgentCard = {
        id: options.did,
        identity,
        capabilities,
        endpoints: [],
        policies: [{ requiresRuntimeAttestation: false, requiresApproval: false }],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }

      const result = validateAgentCard(card)
      if (result.valid) {
        console.log('AgentCard created successfully')
        console.log(`  DID: ${card.identity.did}`)
        console.log(`  Name: ${options.name || 'Unknown'}`)
        console.log(`  Capabilities: ${capabilities.length}`)
        for (const cap of capabilities) {
          const risk = classifyCapabilityRisk(cap.id)
          console.log(`    - ${cap.id} (risk: ${risk})`)
        }
      } else {
        console.error('Validation failed:', result.errors)
        process.exit(1)
      }
    })

  cmd.command('verify')
    .description('Verify an AgentCard')
    .argument('<source>', 'AgentCard JSON file path or DID to lookup')
    .option('--discovery-url <url>', 'Discovery service URL')
    .action(async (source, options) => {
      try {
        let card: AgentCard

        if (source.endsWith('.json')) {
          card = JSON.parse(readFileSync(source, 'utf-8'))
        } else if (source.startsWith('did:')) {
          const provider = new WellKnownDiscoveryProvider()
          const resolved = await provider.resolve(source)
          if (!resolved) {
            console.error(`Could not resolve AgentCard for DID: ${source}`)
            process.exit(1)
          }
          card = resolved
        } else {
          console.error('Source must be a .json file path or a DID')
          process.exit(1)
        }

        const result = validateAgentCard(card)
        if (result.valid) {
          console.log('AgentCard is VALID')
          console.log(`  DID: ${card.identity.did}`)
          console.log(`  Created: ${card.createdAt}`)
          console.log(`  Updated: ${card.updatedAt}`)
          console.log(`  Capabilities: ${card.capabilities.length}`)
          console.log(`  Endpoints: ${card.endpoints.length}`)
          console.log(`  Policies: ${card.policies.length}`)
        } else {
          console.error('AgentCard is INVALID:')
          for (const err of result.errors) {
            console.error(`  - ${err}`)
          }
          process.exit(1)
        }
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  return cmd
}
