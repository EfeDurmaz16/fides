import { Command } from 'commander'
import { validateAgentCard, createIdentity, classifyCapabilityRisk } from '@fides/core'
import type { AgentCard, CapabilityDescriptor } from '@fides/core'
import { RegistryClient, type AgentCard as RegistryAgentCard } from '@fides/sdk'
import { WellKnownDiscoveryProvider } from '@fides/discovery'
import { readFileSync } from 'node:fs'
import { loadConfig } from '../utils/config.js'
import { error, formatTable, info, success } from '../utils/output.js'

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

  cmd.command('publish')
    .description('Publish an AgentCard JSON file to the hosted registry')
    .argument('<file>', 'AgentCard JSON file path')
    .option('--registry-url <url>', 'Registry service URL')
    .option('--api-key <key>', 'Registry API key. Defaults to FIDES_API_KEY')
    .action(async (file, options) => {
      try {
        const card = JSON.parse(readFileSync(file, 'utf-8')) as AgentCard
        const result = validateAgentCard(card)
        if (!result.valid) {
          error('AgentCard is INVALID:')
          for (const err of result.errors) console.error(`  - ${err}`)
          process.exit(1)
        }

        const registry = createRegistryClient(options)
        const response = await registry.register(card as unknown as RegistryAgentCard)
        success('AgentCard published')
        info(`DID: ${response.did}`)
        info(`Registered At: ${response.registeredAt}`)
      } catch (err) {
        error(`Failed to publish AgentCard: ${err instanceof Error ? err.message : String(err)}`)
        process.exit(1)
      }
    })

  cmd.command('get')
    .description('Read a public AgentCard from the hosted registry')
    .argument('<did>', 'Agent DID')
    .option('--registry-url <url>', 'Registry service URL')
    .action(async (did, options) => {
      try {
        const registry = createRegistryClient(options)
        const card = await registry.getCard(did)
        if (!card) {
          error(`AgentCard not found: ${did}`)
          process.exit(1)
        }
        console.log(JSON.stringify(card, null, 2))
      } catch (err) {
        error(`Failed to read AgentCard: ${err instanceof Error ? err.message : String(err)}`)
        process.exit(1)
      }
    })

  cmd.command('search')
    .description('Search public AgentCards in the hosted registry')
    .argument('[query]', 'Search query', '')
    .option('--registry-url <url>', 'Registry service URL')
    .action(async (query, options) => {
      try {
        const registry = createRegistryClient(options)
        const response = await registry.search(query)
        if (response.results.length === 0) {
          info('No AgentCards found')
          return
        }
        formatTable([
          ['DID', 'Name', 'Capabilities'],
          ...response.results.map(result => [
            result.did,
            result.name || '',
            (result.capabilities || []).join(', '),
          ]),
        ])
      } catch (err) {
        error(`Failed to search registry: ${err instanceof Error ? err.message : String(err)}`)
        process.exit(1)
      }
    })

  cmd.command('mode')
    .description('Set a registry AgentCard visibility mode')
    .argument('<did>', 'Agent DID')
    .argument('<mode>', 'public or private')
    .option('--registry-url <url>', 'Registry service URL')
    .option('--api-key <key>', 'Registry API key. Defaults to FIDES_API_KEY')
    .action(async (did, mode, options) => {
      try {
        if (mode !== 'public' && mode !== 'private') {
          error('Mode must be public or private')
          process.exit(1)
        }
        const registry = createRegistryClient(options)
        await registry.setMode(did, mode)
        success(`AgentCard mode set to ${mode}`)
      } catch (err) {
        error(`Failed to set AgentCard mode: ${err instanceof Error ? err.message : String(err)}`)
        process.exit(1)
      }
    })

  cmd.command('metadata')
    .description('Merge metadata into a registry AgentCard')
    .argument('<did>', 'Agent DID')
    .argument('<json>', 'Metadata JSON object')
    .option('--registry-url <url>', 'Registry service URL')
    .option('--api-key <key>', 'Registry API key. Defaults to FIDES_API_KEY')
    .action(async (did, json, options) => {
      try {
        const metadata = JSON.parse(json)
        if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
          error('Metadata must be a JSON object')
          process.exit(1)
        }
        const registry = createRegistryClient(options)
        await registry.updateMetadata(did, metadata)
        success('AgentCard metadata updated')
      } catch (err) {
        error(`Failed to update AgentCard metadata: ${err instanceof Error ? err.message : String(err)}`)
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

function createRegistryClient(options: { registryUrl?: string; apiKey?: string }): RegistryClient {
  const config = loadConfig()
  return new RegistryClient({
    baseUrl: options.registryUrl || config.registryUrl,
    apiKey: options.apiKey || process.env.FIDES_API_KEY,
  })
}
