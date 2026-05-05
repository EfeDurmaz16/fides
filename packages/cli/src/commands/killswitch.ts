import { Command } from 'commander'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'

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
