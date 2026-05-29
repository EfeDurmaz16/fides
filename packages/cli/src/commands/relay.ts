import { Command } from 'commander'
import { getJson, postJson, printResult } from './authority-utils.js'

export function createRelayCommand(): Command {
  const cmd = new Command('relay')
    .description('Send, poll, and inspect relay messages')

  cmd.command('start')
    .description('Start the local mock relay through agentd')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/relay/start`, {})
        printResult('Relay started:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('register')
    .description('Register local agent presence with the local mock relay')
    .argument('<agent-id>', 'Registered local agent DID')
    .option('--endpoint-hints <values>', 'Comma-separated endpoint hints')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (agentId, options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/relay/register`, {
          agentId,
          endpointHints: parseList(options.endpointHints),
        })
        printResult('Relay presence registered:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('discover')
    .description('Discover local mock relay presence by capability')
    .requiredOption('--capability <capability>', 'Capability ID')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/relay/discover`, {
          capability: options.capability,
        })
        printResult('Relay discovery records:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('send')
    .description('Send a message through the relay service')
    .requiredOption('--to <did>', 'Recipient DID')
    .option('--from <did>', 'Sender DID', 'anonymous')
    .option('--payload-json <json>', 'Message payload as JSON')
    .option('--message <text>', 'Message text payload')
    .option('--ttl-ms <ms>', 'Message time-to-live in milliseconds')
    .option('--relay-url <url>', 'Relay service URL', 'http://localhost:7347')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const payload = parsePayload(options)
        const body: Record<string, unknown> = {
          to: options.to,
          from: options.from,
          payload,
        }
        if (options.ttlMs) body.ttlMs = Number(options.ttlMs)

        const result = await postJson(`${baseUrl(options.relayUrl)}/v1/relay`, body)
        printResult('Relay message accepted:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('poll')
    .description('Poll pending relay messages for a DID')
    .argument('<did>', 'Recipient DID')
    .option('--relay-url <url>', 'Relay service URL', 'http://localhost:7347')
    .option('--json', 'Print JSON only')
    .action(async (did, options) => {
      try {
        const result = await getJson(`${baseUrl(options.relayUrl)}/v1/relay/${encodeURIComponent(did)}/messages`)
        printResult('Relay messages:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('status')
    .description('Get relay message status by relay ID')
    .argument('<relay-id>', 'Relay message ID')
    .option('--relay-url <url>', 'Relay service URL', 'http://localhost:7347')
    .option('--json', 'Print JSON only')
    .action(async (relayId, options) => {
      try {
        const result = await getJson(`${baseUrl(options.relayUrl)}/v1/relay/${encodeURIComponent(relayId)}`)
        printResult('Relay message status:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('delete')
    .description('Delete a relay message by relay ID')
    .argument('<relay-id>', 'Relay message ID')
    .option('--relay-url <url>', 'Relay service URL', 'http://localhost:7347')
    .option('--json', 'Print JSON only')
    .action(async (relayId, options) => {
      try {
        const result = await deleteJson(`${baseUrl(options.relayUrl)}/v1/relay/${encodeURIComponent(relayId)}`)
        printResult('Relay message deleted:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  cmd.command('stats')
    .description('Get relay service statistics')
    .option('--relay-url <url>', 'Relay service URL', 'http://localhost:7347')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await getJson(`${baseUrl(options.relayUrl)}/v1/relay/stats`)
        printResult('Relay stats:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  return cmd
}

function parsePayload(options: { payloadJson?: string; message?: string }): unknown {
  if (options.payloadJson) return JSON.parse(options.payloadJson)
  if (options.message) return { message: options.message }
  throw new Error('Either --payload-json or --message is required')
}

function parseList(value?: string): string[] {
  if (!value) return []
  return value.split(',').map(item => item.trim()).filter(Boolean)
}

async function deleteJson(url: string): Promise<unknown> {
  const headers: Record<string, string> = {}
  const apiKey = process.env.FIDES_API_KEY || process.env.SERVICE_API_KEY
  if (apiKey) {
    headers['X-API-Key'] = apiKey
  }

  const response = await fetch(url, { method: 'DELETE', headers })
  const text = await response.text()
  const payload = text ? JSON.parse(text) : {}
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${JSON.stringify(payload)}`)
  }
  return payload
}

function baseUrl(url: string): string {
  return url.replace(/\/+$/, '')
}
