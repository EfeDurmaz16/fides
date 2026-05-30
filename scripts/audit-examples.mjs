import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const catalogPath = resolve(root, 'examples/agent-catalog.ts')

const result = spawnSync(process.execPath, ['--import', 'tsx', catalogPath], {
  cwd: root,
  encoding: 'utf8',
  stdio: 'pipe',
})

if (result.status !== 0) {
  console.error(result.stderr || result.stdout)
  process.exit(result.status ?? 1)
}

const parsed = JSON.parse(result.stdout)
const agents = parsed.agents
const errors = []

const required = {
  'calendar-agent': [{ id: 'calendar.schedule', riskLevel: 'low' }],
  'invoice-agent': [{ id: 'invoice.reconcile', riskLevel: 'medium' }],
  'payment-agent': [
    { id: 'payments.prepare', riskLevel: 'high' },
    { id: 'payments.execute', riskLevel: 'critical' },
  ],
  'requester-agent': [{ id: 'agent.request', riskLevel: 'medium' }],
  'malicious-agent': [{ id: 'payments.execute', riskLevel: 'critical' }],
}

for (const [agentId, capabilities] of Object.entries(required)) {
  const agentDir = resolve(root, 'examples', agentId)
  if (!existsSync(join(agentDir, 'index.ts'))) {
    errors.push(`${agentId} is missing examples/${agentId}/index.ts`)
  }
  if (!existsSync(join(agentDir, 'README.md'))) {
    errors.push(`${agentId} is missing examples/${agentId}/README.md`)
  }

  const agent = agents.find(entry => entry.id === agentId)
  if (!agent) {
    errors.push(`example catalog is missing ${agentId}`)
    continue
  }

  if (!Array.isArray(agent.authorityNotes) || agent.authorityNotes.length === 0) {
    errors.push(`${agentId} is missing authority notes`)
  }

  for (const capability of capabilities) {
    const actual = agent.capabilities.find(entry => entry.id === capability.id)
    if (!actual) {
      errors.push(`${agentId} is missing ${capability.id}`)
      continue
    }
    if (actual.riskLevel !== capability.riskLevel) {
      errors.push(`${agentId} ${capability.id} risk is ${actual.riskLevel}, expected ${capability.riskLevel}`)
    }
    if (!Array.isArray(actual.requiredScopes) || actual.requiredScopes.length === 0) {
      errors.push(`${agentId} ${capability.id} is missing required scopes`)
    }
    if (typeof actual.dryRunSupported !== 'boolean') {
      errors.push(`${agentId} ${capability.id} is missing dryRunSupported`)
    }
    if (typeof actual.humanApprovalSupported !== 'boolean') {
      errors.push(`${agentId} ${capability.id} is missing humanApprovalSupported`)
    }
    if (typeof actual.policyProofSupported !== 'boolean') {
      errors.push(`${agentId} ${capability.id} is missing policyProofSupported`)
    }
  }
}

const paymentAgent = agents.find(entry => entry.id === 'payment-agent')
if (paymentAgent?.capabilities.find(entry => entry.id === 'payments.execute')?.dryRunSupported !== false) {
  errors.push('payment-agent payments.execute must not be marked dry-run supported in generic FIDES')
}

if (!paymentAgent?.authorityNotes.some(note => note.includes('Sardis-specific'))) {
  errors.push('payment-agent must document that execution remains Sardis-specific')
}

const forbiddenLegacyCapabilities = [
  'calendar:create',
  'calendar:list',
  'calendar:delete',
  'invoice:create',
  'invoice:approve',
  'invoice:list',
  'payment:charge',
  'payment:refund',
  'payment:status',
  'email:send',
]
const exampleSourceFiles = findExampleSourceFiles(resolve(root, 'examples'))
  .filter(file => !file.endsWith('agent-catalog.ts'))

for (const file of exampleSourceFiles) {
  const source = readFileSync(file, 'utf8')
  for (const capability of forbiddenLegacyCapabilities) {
    if (source.includes(capability)) {
      errors.push(`${relativeToExamples(file)} still references legacy capability ${capability}`)
    }
  }
}

if (errors.length > 0) {
  console.error(errors.join('\n'))
  process.exit(1)
}

console.log(`Example catalog audit passed for ${agents.length} agents.`)

function findExampleSourceFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const absolutePath = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') return []
      return findExampleSourceFiles(absolutePath)
    }
    return entry.isFile() && entry.name.endsWith('.ts') ? [absolutePath] : []
  })
}

function relativeToExamples(file) {
  return file.slice(resolve(root, 'examples').length + 1)
}
