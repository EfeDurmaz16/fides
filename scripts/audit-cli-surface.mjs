import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const cliEntrypoint = resolve(root, 'packages/cli/src/index.ts')

const checks = [
  {
    args: ['--help'],
    contains: [
      'init',
      'identity',
      'attest',
      'card',
      'register',
      'agents',
      'discover',
      'trust',
      'reputation',
      'graph',
      'policy',
      'session',
      'invoke',
      'approval',
      'evidence',
      'revoke',
      'incident',
      'killswitch',
      'registry',
      'relay',
      'dht',
      'delegate',
      'demo',
      'simulate',
      'daemon',
    ],
  },
  { args: ['identity', '--help'], contains: ['create', 'list', 'show'] },
  { args: ['identity', 'create', '--help'], contains: ['--type <type>', 'agent, publisher, or principal', '--agentd-url <url>'] },
  { args: ['identity', 'list', '--help'], contains: ['--agentd-url <url>'] },
  { args: ['identity', 'show', '--help'], contains: ['<did>', '--agentd-url <url>'] },
  { args: ['attest', '--help'], contains: ['github', 'email', 'domain', 'package', 'wallet', 'runtime', 'show', 'verify'] },
  { args: ['attest', 'github', '--help'], contains: ['--identity <id>', '--handle <handle>'] },
  { args: ['attest', 'email', '--help'], contains: ['--identity <id>', '--email <email>'] },
  { args: ['attest', 'domain', '--help'], contains: ['--identity <id>', '--domain <domain>'] },
  { args: ['attest', 'package', '--help'], contains: ['--identity <id>', '--registry <registry>', '--package <name>'] },
  { args: ['attest', 'wallet', '--help'], contains: ['--identity <id>', '--address <address>'] },
  { args: ['attest', 'runtime', '--help'], contains: ['--agent <id>', '--code-hash <hash>'] },
  { args: ['card', '--help'], contains: ['create', 'sign', 'verify', 'inspect'] },
  { args: ['card', 'create', '--help'], contains: ['--did <did>', '--name <name>', '--capabilities <json>'] },
  { args: ['card', 'sign', '--help'], contains: ['<agent-card-id>', '--agentd-url <url>'] },
  { args: ['card', 'verify', '--help'], contains: ['<source>'] },
  { args: ['card', 'inspect', '--help'], contains: ['<agent-card-id>', '--agentd-url <url>'] },
  { args: ['discover', '--help'], contains: ['--capability <capability>', '--provider <provider>', '--all-providers'] },
  { args: ['registry', '--help'], contains: ['start', 'publish', 'search', 'index'] },
  { args: ['registry', 'publish', '--help'], contains: ['<agent-card-id>', '--agentd-url <url>'] },
  { args: ['registry', 'search', '--help'], contains: ['--capability <capability>'] },
  { args: ['relay', '--help'], contains: ['start', 'register', 'discover', 'send', 'poll', 'status', 'delete', 'stats'] },
  { args: ['relay', 'register', '--help'], contains: ['<agent-id>', '--agentd-url <url>'] },
  { args: ['relay', 'discover', '--help'], contains: ['--capability <capability>'] },
  { args: ['dht', '--help'], contains: ['start', 'publish', 'find'] },
  { args: ['dht', 'publish', '--help'], contains: ['[agent-card]', '--capability <capability>'] },
  { args: ['dht', 'find', '--help'], contains: ['--capability <capability>'] },
  { args: ['trust', '--help'], contains: ['--capability <capability>'] },
  { args: ['reputation', '--help'], contains: ['update', 'get', '--capability <capability>'] },
  { args: ['graph', '--help'], contains: ['inspect'] },
  { args: ['policy', '--help'], contains: ['evaluate'] },
  { args: ['policy', 'evaluate', '--help'], contains: ['--agent <id>', '--capability <capability>', '--requested-scopes <csv>'] },
  { args: ['session', '--help'], contains: ['request', 'show', 'verify', 'create', 'revoke'] },
  { args: ['session', 'request', '--help'], contains: ['<agent-id>', '--capability <id>', '--requested-scopes <list>'] },
  { args: ['session', 'verify', '--help'], contains: ['<session-id>', '--agentd-url <url>'] },
  { args: ['session', 'create', '--help'], contains: ['--token-file <path>', '--token-json <json>', '--delegator-public-key <hex>'] },
  { args: ['delegate', '--help'], contains: ['create'] },
  { args: ['delegate', 'create', '--help'], contains: ['--delegator <did>', '--delegatee <did>', '--capabilities <ids>', '--agentd-url <url>'] },
  { args: ['invoke', '--help'], contains: ['--capability <capability>', '--input <path>', '--dry-run', '--sign', '--requester-private-key-file <path>'] },
  { args: ['approval', '--help'], contains: ['request', 'list', 'approve', 'deny'] },
  { args: ['approval', 'approve', '--help'], contains: ['<approval-id>', '--approver <id>'] },
  { args: ['approval', 'deny', '--help'], contains: ['<approval-id>', '--approver <id>'] },
  { args: ['evidence', '--help'], contains: ['list', 'inspect', 'verify', 'export'] },
  { args: ['evidence', 'inspect', '--help'], contains: ['<event-id>', '--agentd-url <url>'] },
  { args: ['evidence', 'export', '--help'], contains: ['--privacy-mode <mode>', '--agentd-url <url>'] },
  { args: ['revoke', '--help'], contains: ['agent', 'key', 'identity', 'card', 'capability', 'session', 'attestation', 'publisher', 'list', 'inspect'] },
  { args: ['revoke', 'agent', '--help'], contains: ['<did>', '--reason <text>'] },
  { args: ['revoke', 'session', '--help'], contains: ['<id>', '--reason <text>'] },
  { args: ['incident', '--help'], contains: ['report', 'list', 'inspect', 'resolve'] },
  { args: ['incident', 'report', '--help'], contains: ['[agent-id]', '--severity <level>', '--category <category>'] },
  { args: ['incident', 'resolve', '--help'], contains: ['<incident-id>', '--status <status>'] },
  { args: ['killswitch', '--help'], contains: ['enable', 'list', 'disable'] },
  { args: ['killswitch', 'enable', '--help'], contains: ['--agent <did>', '--capability <id>'] },
  { args: ['killswitch', 'disable', '--help'], contains: ['<rule-id>'] },
  { args: ['daemon', '--help'], contains: ['start', 'status', 'stop'] },
  { args: ['demo', '--help'], contains: ['run'] },
  { args: ['demo', 'run', '--help'], contains: ['--agentd-url <url>'] },
  { args: ['simulate', '--help'], contains: ['adversarial'] },
  { args: ['simulate', 'adversarial', '--help'], contains: ['--agentd-url <url>'] },
]

const errors = []

for (const check of checks) {
  const result = spawnSync(process.execPath, ['--import', 'tsx', cliEntrypoint, ...check.args], {
    cwd: root,
    encoding: 'utf8',
    stdio: 'pipe',
  })
  const label = `agentd ${check.args.join(' ')}`
  const output = `${result.stdout}\n${result.stderr}`

  if (result.status !== 0) {
    errors.push(`${label} exited with ${result.status ?? 'null'}: ${output.trim()}`)
    continue
  }

  for (const expected of check.contains) {
    if (!output.includes(expected)) {
      errors.push(`${label} help output is missing "${expected}"`)
    }
  }
}

if (errors.length > 0) {
  console.error(errors.join('\n'))
  process.exit(1)
}

console.log(`CLI surface audit passed for ${checks.length} command surfaces.`)
