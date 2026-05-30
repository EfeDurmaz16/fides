import { Command } from 'commander'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { deleteJson, getJson, postJson, printResult } from './authority-utils.js'

const KILLSTATE_PATH = join(homedir(), '.fides', 'killswitch.json')

interface KillState {
  global: boolean
  agents: Record<string, boolean>
  capabilities: Record<string, boolean>
}

function loadKillState(): KillState {
  if (!existsSync(KILLSTATE_PATH)) {
    return { global: false, agents: {}, capabilities: {} }
  }
  return JSON.parse(readFileSync(KILLSTATE_PATH, 'utf-8'))
}

function saveKillState(state: KillState): void {
  const dir = join(homedir(), '.fides')
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }
  writeFileSync(KILLSTATE_PATH, JSON.stringify(state, null, 2))
}

export function createKillswitchCommand(): Command {
  const cmd = new Command('killswitch')
    .description('Kill switch control')

  cmd.command('enable')
    .description('Enable a root v2 kill switch rule through agentd')
    .option('--agent <did>', 'Kill an agent')
    .option('--publisher <did>', 'Kill a publisher')
    .option('--capability <id>', 'Kill a capability')
    .option('--session <id>', 'Kill a session')
    .option('--principal <did>', 'Kill a principal')
    .option('--risk-class <level>', 'Kill a risk class')
    .option('--reason <text>', 'Kill switch reason', 'Enabled by CLI')
    .option('--issuer <did>', 'Issuer DID')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const target = killSwitchTarget(options)
        const result = await postJson(`${baseUrl(options.agentdUrl)}/killswitch`, {
          targetType: target.targetType,
          target: target.target,
          reason: options.reason,
          ...(options.issuer && { issuer: options.issuer }),
        })
        printResult('Kill switch enabled:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('disable')
    .description('Disable a root v2 kill switch rule through agentd')
    .argument('<rule-id>', 'Kill switch rule ID')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (ruleId, options) => {
      try {
        const result = await deleteJson(`${baseUrl(options.agentdUrl)}/killswitch/${encodeURIComponent(ruleId)}`)
        printResult('Kill switch disabled:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('list')
    .description('List root v2 kill switch rules through agentd')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await getJson(`${baseUrl(options.agentdUrl)}/killswitch`)
        printResult('Kill switch rules:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('engage')
    .description('Engage kill switch')
    .option('--global', 'Engage globally')
    .option('--agent <did>', 'Engage for agent')
    .option('--capability <id>', 'Engage for capability')
    .action(async (options) => {
      try {
        const state = loadKillState()
        if (options.global) {
          state.global = true
          console.log('Global kill switch ENGAGED')
        } else if (options.agent) {
          state.agents[options.agent] = true
          console.log(`Kill switch ENGAGED for agent ${options.agent}`)
        } else if (options.capability) {
          state.capabilities[options.capability] = true
          console.log(`Kill switch ENGAGED for capability ${options.capability}`)
        } else {
          state.global = true
          console.log('Global kill switch ENGAGED (default)')
        }
        saveKillState(state)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('disengage')
    .description('Disengage kill switch')
    .option('--global', 'Disengage globally')
    .option('--agent <did>', 'Disengage for agent')
    .option('--capability <id>', 'Disengage for capability')
    .action(async (options) => {
      try {
        const state = loadKillState()
        if (options.global) {
          state.global = false
          console.log('Global kill switch DISENGAGED')
        } else if (options.agent) {
          delete state.agents[options.agent]
          console.log(`Kill switch DISENGAGED for agent ${options.agent}`)
        } else if (options.capability) {
          delete state.capabilities[options.capability]
          console.log(`Kill switch DISENGAGED for capability ${options.capability}`)
        } else {
          state.global = false
          state.agents = {}
          state.capabilities = {}
          console.log('All kill switches DISENGAGED')
        }
        saveKillState(state)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('status')
    .description('Show kill switch status')
    .action(() => {
      try {
        const state = loadKillState()
        console.log('Kill Switch Status:')
        console.log(`  Global: ${state.global ? 'ENGAGED' : 'disengaged'}`)
        console.log(`  Agents: ${Object.keys(state.agents).length > 0 ? Object.keys(state.agents).join(', ') : 'none'}`)
        console.log(`  Capabilities: ${Object.keys(state.capabilities).length > 0 ? Object.keys(state.capabilities).join(', ') : 'none'}`)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  return cmd
}

function killSwitchTarget(options: {
  agent?: string
  publisher?: string
  capability?: string
  session?: string
  principal?: string
  riskClass?: string
}): { targetType: string; target: string } {
  const targets = [
    ['agent', options.agent],
    ['publisher', options.publisher],
    ['capability', options.capability],
    ['session', options.session],
    ['principal', options.principal],
    ['risk_class', options.riskClass],
  ].filter(([, value]) => typeof value === 'string') as Array<[string, string]>
  if (targets.length !== 1) {
    throw new Error('provide exactly one of --agent, --publisher, --capability, --session, --principal, or --risk-class')
  }
  const [targetType, target] = targets[0]
  return { targetType, target }
}

function baseUrl(url: string): string {
  return url.replace(/\/+$/, '')
}
