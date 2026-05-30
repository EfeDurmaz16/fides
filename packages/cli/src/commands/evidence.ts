import { Command } from 'commander'
import { getJson, postJson, printResult } from './authority-utils.js'

export function createEvidenceCommand(): Command {
  const cmd = new Command('evidence')
    .description('Evidence ledger commands')

  cmd.command('list')
    .description('List evidence events')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await getJson(`${baseUrl(options.agentdUrl)}/evidence`)
        printResult('Evidence events:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('inspect')
    .description('Inspect an evidence event')
    .argument('<event-id>', 'Evidence event ID')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (eventId, options) => {
      try {
        const result = await getJson(`${baseUrl(options.agentdUrl)}/evidence/${encodeURIComponent(eventId)}`)
        printResult('Evidence event:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('verify')
    .description('Verify the evidence hash chain')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const result = await postJson(`${baseUrl(options.agentdUrl)}/evidence/verify`, {})
        printResult('Evidence verification:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  cmd.command('export')
    .description('Export evidence events')
    .option('--privacy-mode <mode>', 'Evidence privacy mode: public, private, redacted, hash_only')
    .option('--include-metadata', 'Include evidence metadata in export', true)
    .option('--no-metadata', 'Exclude evidence metadata from export')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const body = evidenceExportBody(options)
        const result = await postJson(`${baseUrl(options.agentdUrl)}/evidence/export`, body)
        printResult('Evidence export:', result, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exitCode = 1
      }
    })

  return cmd
}

function baseUrl(url: string): string {
  return url.replace(/\/+$/, '')
}

function evidenceExportBody(options: { privacyMode?: string; includeMetadata?: boolean; metadata?: boolean }): Record<string, unknown> {
  const body: Record<string, unknown> = {}
  if (options.privacyMode !== undefined) {
    const mode = normalizePrivacyMode(options.privacyMode)
    if (!['public', 'private', 'redacted', 'hash_only'].includes(mode)) {
      throw new Error('--privacy-mode must be one of public, private, redacted, hash_only')
    }
    body.privacy_mode = mode
  }
  if (typeof options.metadata === 'boolean') {
    body.include_metadata = options.metadata
  } else if (typeof options.includeMetadata === 'boolean') {
    body.include_metadata = options.includeMetadata
  }
  return body
}

function normalizePrivacyMode(mode: string): string {
  return mode === 'hash-only' ? 'hash_only' : mode
}
