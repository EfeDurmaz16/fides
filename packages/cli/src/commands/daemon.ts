import { Command } from 'commander'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import { dirname, join } from 'node:path'
import { formatTable } from '../utils/output.js'

const AGENTD_PID_PATH = join(os.homedir(), '.fides', 'agentd.pid')
const AGENTD_LOG_PATH = join(os.homedir(), '.fides', 'agentd.log')

interface AgentdHealth {
  status?: string
  service?: string
  uptime?: number
  timestamp?: string
  pid?: number
  checks?: Record<string, string>
  authorityStore?: {
    kind?: string
    ok?: boolean
    path?: string
    detail?: string
  }
  localStateStore?: {
    kind?: string
    ok?: boolean
    path?: string
    detail?: string
  }
}

export function createDaemonCommand(): Command {
  const cmd = new Command('daemon')
    .description('Local daemon control')

  cmd.command('start')
    .description('Start agentd')
    .option('--port <port>', 'Port to listen on', '7345')
    .option('--sqlite-path <path>', 'SQLite path for root v2 local daemon state')
    .option('--local-state <mode>', 'Local daemon state mode: sqlite or memory')
    .option('--authority-store-path <path>', 'File authority store path')
    .option('--command <command>', 'Command used to start agentd', 'pnpm')
    .option('--args <args>', 'Comma-separated command args', '--filter,@fides/agentd,dev')
    .option('--pid-file <path>', 'PID file path', AGENTD_PID_PATH)
    .option('--log-file <path>', 'Log file path', AGENTD_LOG_PATH)
    .action((options) => {
      try {
        const existingPid = readPid(options.pidFile)
        if (existingPid) {
          console.log(`agentd already appears to be running (pid ${existingPid})`)
          return
        }

        ensureDir(options.pidFile)
        ensureDir(options.logFile)
        const logFd = fs.openSync(options.logFile, 'a')
        const args = String(options.args).split(',').map(item => item.trim()).filter(Boolean)
        const localState = normalizeLocalStateMode(options.localState)
        const child = spawn(options.command, args, {
          detached: true,
          stdio: ['ignore', logFd, logFd],
          env: {
            ...process.env,
            AGENTD_PORT: String(options.port),
            ...(options.sqlitePath && { AGENTD_SQLITE_PATH: String(options.sqlitePath) }),
            ...(localState && { AGENTD_LOCAL_STATE: localState }),
            ...(options.authorityStorePath && { AGENTD_STATE_STORE_PATH: String(options.authorityStorePath) }),
          },
        })
        if (!child.pid) {
          throw new Error('agentd process did not expose a pid')
        }
        child.unref()
        fs.writeFileSync(options.pidFile, String(child.pid), 'utf-8')
        console.log(`agentd started on port ${options.port} (pid ${child.pid})`)
        console.log(`logs: ${options.logFile}`)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('status')
    .description('Check agentd status')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await fetchAgentdHealth(options.agentdUrl)
        const pid = readPid(AGENTD_PID_PATH)
        if (pid) {
          result.pid = pid
        }
        if (options.json) {
          console.log(JSON.stringify(result, null, 2))
        } else {
          printAgentdHealth(options.agentdUrl, result)
        }
        if (result.status !== 'healthy') {
          process.exitCode = 1
        }
      } catch (error) {
        if (options.json) {
          console.log(JSON.stringify({
            status: 'unreachable',
            service: 'agentd',
            error: error instanceof Error ? error.message : String(error),
          }, null, 2))
        } else {
          console.error(`agentd unreachable: ${error instanceof Error ? error.message : String(error)}`)
        }
        process.exitCode = 1
      }
    })

  cmd.command('stop')
    .description('Stop agentd')
    .option('--pid-file <path>', 'PID file path', AGENTD_PID_PATH)
    .action((options) => {
      try {
        const pid = readPid(options.pidFile)
        if (!pid) {
          console.log('agentd is not running')
          return
        }
        process.kill(pid, 'SIGTERM')
        fs.rmSync(options.pidFile, { force: true })
        console.log(`agentd stop signal sent (pid ${pid})`)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  return cmd
}

async function fetchAgentdHealth(agentdUrl: string): Promise<AgentdHealth> {
  const baseUrl = agentdUrl.replace(/\/$/, '')
  const response = await fetch(`${baseUrl}/health`)
  const text = await response.text()
  const payload = text ? JSON.parse(text) : {}
  return payload as AgentdHealth
}

function printAgentdHealth(agentdUrl: string, health: AgentdHealth): void {
  const checks = health.checks ?? {}
  const rows: string[][] = [
    ['Agentd URL:', agentdUrl.replace(/\/$/, '')],
    ['Status:', health.status ?? 'unknown'],
    ['Service:', health.service ?? 'agentd'],
  ]

  if (typeof health.uptime === 'number') {
    rows.push(['Uptime:', `${health.uptime}s`])
  }
  if (typeof health.pid === 'number') {
    rows.push(['PID:', String(health.pid)])
  }
  if (health.timestamp) {
    rows.push(['Timestamp:', health.timestamp])
  }
  if (health.authorityStore) {
    rows.push(['Authority Store:', `${health.authorityStore.kind ?? 'unknown'} (${health.authorityStore.ok ? 'ready' : 'unready'})`])
    if (health.authorityStore.path) {
      rows.push(['Authority Path:', health.authorityStore.path])
    }
    if (health.authorityStore.detail) {
      rows.push(['Authority Detail:', health.authorityStore.detail])
    }
  }
  if (health.localStateStore) {
    rows.push(['Local State Store:', `${health.localStateStore.kind ?? 'unknown'} (${health.localStateStore.ok ? 'ready' : 'unready'})`])
    if (health.localStateStore.path) {
      rows.push(['Local State Path:', health.localStateStore.path])
    }
    if (health.localStateStore.detail) {
      rows.push(['Local State Detail:', health.localStateStore.detail])
    }
  }
  for (const [name, status] of Object.entries(checks)) {
    rows.push([`Check ${name}:`, status])
  }

  console.log('')
  formatTable(rows)
  console.log('')
}

function ensureDir(filePath: string): void {
  const dir = dirname(filePath)
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
  }
}

function readPid(pidFile: string): number | null {
  if (!fs.existsSync(pidFile)) {
    return null
  }
  const pid = Number(fs.readFileSync(pidFile, 'utf-8'))
  if (!Number.isInteger(pid) || pid <= 0) {
    return null
  }
  try {
    process.kill(pid, 0)
    return pid
  } catch {
    fs.rmSync(pidFile, { force: true })
    return null
  }
}

function normalizeLocalStateMode(mode?: string): 'sqlite' | 'memory' | undefined {
  if (mode === undefined) return undefined
  if (mode === 'sqlite' || mode === 'memory') return mode
  throw new Error('--local-state must be sqlite or memory')
}
