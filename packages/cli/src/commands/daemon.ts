import { Command } from 'commander'
import { formatTable } from '../utils/output.js'

interface AgentdHealth {
  status?: string
  service?: string
  uptime?: number
  timestamp?: string
  checks?: Record<string, string>
  authorityStore?: {
    kind?: string
    ok?: boolean
    detail?: string
  }
}

export function createDaemonCommand(): Command {
  const cmd = new Command('daemon')
    .description('Local daemon control')

  cmd.command('start')
    .description('Start agentd')
    .option('--port <port>', 'Port to listen on', '7345')
    .action((options) => {
      console.log(`Starting agentd on port ${options.port}...`)
    })

  cmd.command('status')
    .description('Check agentd status')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await fetchAgentdHealth(options.agentdUrl)
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
    .action(() => {
      console.log('Stopping agentd...')
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
  if (health.timestamp) {
    rows.push(['Timestamp:', health.timestamp])
  }
  if (health.authorityStore) {
    rows.push(['Authority Store:', `${health.authorityStore.kind ?? 'unknown'} (${health.authorityStore.ok ? 'ready' : 'unready'})`])
    if (health.authorityStore.detail) {
      rows.push(['Authority Detail:', health.authorityStore.detail])
    }
  }
  for (const [name, status] of Object.entries(checks)) {
    rows.push([`Check ${name}:`, status])
  }

  console.log('')
  formatTable(rows)
  console.log('')
}
