import { Command } from 'commander'
import { getJson, postJson, printResult } from './authority-utils.js'

export function createRelayCommand(): Command {
  const cmd = new Command('relay')
    .description('Send, poll, and inspect relay messages')

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
