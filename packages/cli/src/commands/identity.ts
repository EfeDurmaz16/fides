import { Command } from 'commander'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { resolveTxt } from 'node:dns/promises'
import {
  createAgentIdentity,
  createDomainVerificationChallenge,
  createPrincipalIdentity,
  createPublisherIdentity,
  verifyDomainDid,
  type AgentIdentity,
  type PrincipalIdentity,
  type PublisherIdentity,
} from '@fides/core'
import { error, formatTable, info, success } from '../utils/output.js'
import { getJson, postJson, printResult } from './authority-utils.js'

type LocalIdentityType = 'agent' | 'publisher' | 'principal'

interface StoredIdentity {
  type: LocalIdentityType
  identity: AgentIdentity | PublisherIdentity | PrincipalIdentity
  publicKeyHex: string
  privateKeyHex: string
  createdAt: string
}

export function createIdentityCommand(): Command {
  const cmd = new Command('identity')
    .description('Identity creation and verification utilities')

  cmd.command('create')
    .description('Create a local FIDES identity')
    .requiredOption('--type <type>', 'Identity type: agent, publisher, or principal')
    .option('--name <name>', 'Display name for publisher/principal or agent metadata')
    .option('--domain <domain>', 'Optional domain for publisher/principal identities')
    .option('--agentd-url <url>', 'Create the identity through a local agentd root v2 API instead of local files')
    .option('--json', 'Emit JSON output')
    .action(async (options) => {
      try {
        const type = parseIdentityType(options.type)
        if (options.agentdUrl) {
          const result = await postJson(`${baseUrl(options.agentdUrl)}/identities`, {
            type,
            ...(options.name && { name: options.name }),
            ...(options.domain && { domain: options.domain }),
          })
          printResult('Identity created:', result, options)
          return
        }

        const stored = await createStoredIdentity(type, {
          name: options.name,
          domain: options.domain,
        })
        const filePath = writeStoredIdentity(stored)
        const output = {
          type: stored.type,
          did: stored.identity.did,
          publicKeyHex: stored.publicKeyHex,
          path: filePath,
        }

        if (options.json) {
          console.log(JSON.stringify(output, null, 2))
          return
        }

        success(`${type} identity created`)
        info(`DID: ${stored.identity.did}`)
        info(`Public Key: ${stored.publicKeyHex}`)
        info(`Stored At: ${filePath}`)
      } catch (err) {
        error(`Failed to create identity: ${err instanceof Error ? err.message : String(err)}`)
        process.exit(1)
      }
    })

  cmd.command('list')
    .description('List local FIDES identities')
    .option('--agentd-url <url>', 'List identities through a local agentd root v2 API instead of local files')
    .option('--json', 'Emit JSON output')
    .action(async (options) => {
      try {
        if (options.agentdUrl) {
          const result = await getJson(`${baseUrl(options.agentdUrl)}/identities`)
          printResult('Identities:', result, options)
          return
        }

        const identities = readStoredIdentities().map(({ privateKeyHex: _privateKeyHex, ...stored }) => ({
          type: stored.type,
          did: stored.identity.did,
          identity: stored.identity,
          publicKeyHex: stored.publicKeyHex,
          createdAt: stored.createdAt,
        }))
        if (options.json) {
          console.log(JSON.stringify({ identities }, null, 2))
          return
        }

        if (identities.length === 0) {
          info('No local identities found')
          return
        }

        formatTable([
          ['Type', 'DID', 'Public Key'],
          ...identities.map(stored => [
            stored.type,
            stored.identity.did,
            stored.publicKeyHex.slice(0, 16) + '...',
          ]),
        ])
      } catch (err) {
        error(`Failed to list identities: ${err instanceof Error ? err.message : String(err)}`)
        process.exit(1)
      }
    })

  cmd.command('show')
    .description('Show a local FIDES identity without exposing its private key')
    .argument('<did>', 'Identity DID')
    .option('--agentd-url <url>', 'Read the identity through a local agentd root v2 API instead of local files')
    .option('--json', 'Emit JSON output')
    .action(async (did, options) => {
      try {
        if (options.agentdUrl) {
          const result = await getJson(`${baseUrl(options.agentdUrl)}/identities/${encodeURIComponent(did)}`)
          printResult('Identity:', result, options)
          return
        }

        const stored = readStoredIdentity(did)
        if (!stored) {
          error(`Identity not found: ${did}`)
          process.exit(1)
        }
        const { privateKeyHex: _privateKeyHex, ...safeStored } = stored

        if (options.json) {
          console.log(JSON.stringify(safeStored, null, 2))
          return
        }

        info(`Type: ${safeStored.type}`)
        info(`DID: ${safeStored.identity.did}`)
        info(`Public Key: ${safeStored.publicKeyHex}`)
        info(`Created At: ${safeStored.createdAt}`)
      } catch (err) {
        error(`Failed to show identity: ${err instanceof Error ? err.message : String(err)}`)
        process.exit(1)
      }
    })

  const domain = cmd.command('domain')
    .description('Verify domain ownership for FIDES DIDs')

  domain.command('challenge')
    .description('Print the DNS TXT record required to bind a domain to a FIDES DID')
    .argument('<domain>', 'Domain to verify')
    .argument('<did>', 'FIDES DID to bind to the domain')
    .option('--json', 'Emit JSON output')
    .action((domainName, did, options) => {
      try {
        const challenge = createDomainVerificationChallenge(domainName, did)
        if (options.json) {
          console.log(JSON.stringify(challenge, null, 2))
          return
        }

        success('Domain verification challenge created')
        info(`Domain: ${challenge.domain}`)
        info(`Record Name: ${challenge.recordName}`)
        info(`Record Type: TXT`)
        info(`Record Value: ${challenge.recordValue}`)
      } catch (err) {
        error(`Failed to create domain verification challenge: ${err instanceof Error ? err.message : String(err)}`)
        process.exit(1)
      }
    })

  domain.command('verify')
    .description('Resolve DNS TXT records and verify a domain-to-DID binding')
    .argument('<domain>', 'Domain to verify')
    .argument('<did>', 'Expected FIDES DID')
    .option('--json', 'Emit JSON output')
    .action(async (domainName, did, options) => {
      try {
        const result = await verifyDomainDid({
          domain: domainName,
          did,
          resolver: resolveTxt,
        })

        if (options.json) {
          console.log(JSON.stringify(result, null, 2))
        } else if (result.verified) {
          success(`Domain verified: ${result.domain}`)
          info(`DID: ${result.did}`)
          info(`Record Name: ${result.recordName}`)
        } else {
          error(`Domain verification failed: ${result.reason || 'unknown'}`)
          info(`Domain: ${result.domain}`)
          info(`DID: ${result.did}`)
          info(`Record Name: ${result.recordName}`)
        }

        if (!result.verified) {
          process.exitCode = 1
        }
      } catch (err) {
        error(`Failed to verify domain: ${err instanceof Error ? err.message : String(err)}`)
        process.exit(1)
      }
    })

  return cmd
}

function fidesHome(): string {
  return process.env.FIDES_HOME || path.join(os.homedir(), '.fides')
}

function identityDir(): string {
  return path.join(fidesHome(), 'identities')
}

function identityFileName(did: string): string {
  return `${Buffer.from(did).toString('base64url')}.json`
}

function identityPath(did: string): string {
  return path.join(identityDir(), identityFileName(did))
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}

function parseIdentityType(type: string): LocalIdentityType {
  if (type === 'agent' || type === 'publisher' || type === 'principal') {
    return type
  }
  throw new Error('Identity type must be agent, publisher, or principal')
}

async function createStoredIdentity(
  type: LocalIdentityType,
  options: { name?: string; domain?: string }
): Promise<StoredIdentity> {
  if (type === 'agent') {
    const issued = await createAgentIdentity()
    return {
      type,
      identity: {
        ...issued.identity,
        metadata: { name: options.name || 'Agent' },
      },
      publicKeyHex: bytesToHex(issued.publicKey),
      privateKeyHex: bytesToHex(issued.privateKey),
      createdAt: issued.identity.createdAt,
    }
  }

  if (type === 'publisher') {
    const issued = await createPublisherIdentity({
      name: options.name || 'Publisher',
      ...(options.domain !== undefined && { domain: options.domain }),
      publisherType: options.domain ? 'domain_verified' : 'self_signed',
      verificationMethod: options.domain ? 'dns' : 'self_signed',
      verified: false,
    })
    return {
      type,
      identity: issued.identity,
      publicKeyHex: bytesToHex(issued.publicKey),
      privateKeyHex: bytesToHex(issued.privateKey),
      createdAt: new Date().toISOString(),
    }
  }

  const issued = await createPrincipalIdentity({
    type: 'individual',
    displayName: options.name || 'Principal',
    ...(options.domain !== undefined && { domain: options.domain }),
    verificationMethod: options.domain ? 'dns' : 'self_signed',
    verified: false,
  })
  return {
    type,
    identity: issued.identity,
    publicKeyHex: bytesToHex(issued.publicKey),
    privateKeyHex: bytesToHex(issued.privateKey),
    createdAt: new Date().toISOString(),
  }
}

function writeStoredIdentity(stored: StoredIdentity): string {
  fs.mkdirSync(identityDir(), { recursive: true })
  const filePath = identityPath(stored.identity.did)
  fs.writeFileSync(filePath, JSON.stringify(stored, null, 2), { encoding: 'utf-8', mode: 0o600 })
  try {
    fs.chmodSync(filePath, 0o600)
  } catch {
    // chmod is best-effort on filesystems that do not support POSIX modes.
  }
  return filePath
}

function readStoredIdentities(): StoredIdentity[] {
  const dir = identityDir()
  if (!fs.existsSync(dir)) {
    return []
  }
  return fs.readdirSync(dir)
    .filter(file => file.endsWith('.json'))
    .map(file => JSON.parse(fs.readFileSync(path.join(dir, file), 'utf-8')) as StoredIdentity)
}

function readStoredIdentity(did: string): StoredIdentity | null {
  const filePath = identityPath(did)
  if (!fs.existsSync(filePath)) {
    return null
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as StoredIdentity
}

function baseUrl(url: string): string {
  return url.replace(/\/+$/, '')
}
