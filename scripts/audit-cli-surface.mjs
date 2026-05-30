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
      'demo',
      'simulate',
      'daemon',
    ],
  },
  { args: ['identity', '--help'], contains: ['create', 'list', 'show'] },
  { args: ['identity', 'create', '--help'], contains: ['--type <type>', '--agentd-url <url>'] },
  { args: ['attest', '--help'], contains: ['github', 'email', 'domain', 'package', 'wallet', 'runtime'] },
  { args: ['card', '--help'], contains: ['create', 'sign', 'verify', 'inspect'] },
  { args: ['discover', '--help'], contains: ['--capability <capability>', '--provider <provider>', '--all-providers'] },
  { args: ['registry', '--help'], contains: ['start', 'publish', 'search'] },
  { args: ['relay', '--help'], contains: ['start', 'register', 'discover'] },
  { args: ['dht', '--help'], contains: ['start', 'publish', 'find'] },
  { args: ['trust', '--help'], contains: ['--capability <capability>'] },
  { args: ['reputation', '--help'], contains: ['update', 'get', '--capability <capability>'] },
  { args: ['graph', '--help'], contains: ['inspect'] },
  { args: ['policy', '--help'], contains: ['evaluate'] },
  { args: ['session', '--help'], contains: ['request', 'show', 'verify'] },
  { args: ['invoke', '--help'], contains: ['--capability <capability>', '--input <path>', '--dry-run'] },
  { args: ['approval', '--help'], contains: ['request', 'list', 'approve', 'deny'] },
  { args: ['evidence', '--help'], contains: ['list', 'inspect', 'verify', 'export'] },
  { args: ['revoke', '--help'], contains: ['agent', 'key', 'identity', 'card', 'capability', 'session', 'attestation', 'publisher'] },
  { args: ['incident', '--help'], contains: ['report', 'list', 'inspect', 'resolve'] },
  { args: ['killswitch', '--help'], contains: ['enable', 'list', 'disable'] },
  { args: ['demo', '--help'], contains: ['run'] },
  { args: ['simulate', '--help'], contains: ['adversarial'] },
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
