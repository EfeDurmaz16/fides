import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const errors = []

const requiredDocs = [
  'docs/inspection/fides-report.md',
  'docs/inspection/agit-report.md',
  'docs/inspection/osp-report.md',
  'docs/inspection/oaps-report.md',
  'docs/inspection/sardis-report.md',
  'docs/inspection/cross-repo-primitive-map.md',
  'docs/architecture/fides-v2-agent-trust-fabric.md',
  'docs/architecture/gap-analysis.md',
  'docs/architecture/implementation-plan.md',
  'docs/architecture/implementation-agent-prompt.md',
  'docs/protocol/canonical-object-signing.md',
  'docs/protocol/version-negotiation.md',
  'docs/protocol/error-vocabulary.md',
  'docs/protocol/privacy-model.md',
  'docs/protocol/identity-model.md',
  'docs/protocol/agent-card.md',
  'docs/protocol/capability-ontology.md',
  'docs/protocol/discovery.md',
  'docs/protocol/dht-discovery.md',
  'docs/protocol/relay-discovery.md',
  'docs/protocol/registry-federation.md',
  'docs/protocol/trust-model.md',
  'docs/protocol/reputation-model.md',
  'docs/protocol/policy-engine.md',
  'docs/protocol/delegation-and-sessions.md',
  'docs/protocol/evidence-ledger.md',
  'docs/protocol/runtime-attestation.md',
  'docs/protocol/revocation.md',
  'docs/protocol/incidents.md',
  'docs/protocol/approvals.md',
  'docs/protocol/kill-switch.md',
  'docs/protocol/interop-adapters.md',
  'docs/threat-model.md',
  'docs/getting-started.md',
  'docs/api-reference.md',
  'docs/cli-reference.md',
  'docs/sdk-reference.md',
  'docs/adversarial-simulation.md',
  'docs/adr/use-effect-internally.md',
  'docs/adr/ts-first-rust-adapter-ready.md',
  'docs/adr/oaps-concepts-ported.md',
  'docs/adr/sardis-patterns-only.md',
]

for (const docPath of requiredDocs) {
  const absolutePath = join(root, docPath)
  if (!existsSync(absolutePath)) {
    errors.push(`required FIDES v2 doc is missing: ${docPath}`)
    continue
  }
  if (readFileSync(absolutePath, 'utf8').trim().length < 120) {
    errors.push(`required FIDES v2 doc is too small to be useful: ${docPath}`)
  }
}

const inspectionReports = [
  'docs/inspection/fides-report.md',
  'docs/inspection/agit-report.md',
  'docs/inspection/osp-report.md',
  'docs/inspection/oaps-report.md',
  'docs/inspection/sardis-report.md',
]

for (const reportPath of inspectionReports) {
  if (!existsSync(join(root, reportPath))) continue
  requireMatches(reportPath, [
    /^##\s+\d+\.\s+Repo Purpose/m,
    /^##\s+\d+\.\s+Main Packages\s*\/\s*Modules/m,
    /^##\s+\d+\.\s+Existing .*Primitives/m,
    /^##\s+\d+\.\s+(Relevant Files|Payment-Specific Items To Keep Separate)/m,
    /^##\s+\d+\.\s+Reusable Components/m,
    /^##\s+\d+\.\s+Missing Components/m,
    /^##\s+\d+\.\s+Conflicts With FIDES v2 Architecture/m,
    /^##\s+\d+\.\s+Recommended Action/m,
  ])
}

requireContains('docs/inspection/cross-repo-primitive-map.md', [
  '| Primitive | FIDES | AGIT | OSP | OAPS | Sardis | Best source | Action |',
  'Agent identity',
  'Publisher identity',
  'Principal identity',
  'Canonical object signing',
  'DelegationToken',
  'SessionGrant',
  'EvidenceEvent',
  'Runtime attestation',
  'MCP adapter',
  'Sardis adapter',
])

requireContains('docs/architecture/fides-v2-agent-trust-fabric.md', [
  '### 1. Identity Layer',
  '### 2. Attestation Layer',
  '### 3. Agent Metadata Layer',
  '### 4. Discovery Layer',
  '### 5. Trust Layer',
  '### 6. Reputation Layer',
  '### 7. Policy Layer',
  '### 8. Delegation Layer',
  '### 9. Invocation Layer',
  '### 10. Evidence Layer',
  '### 11. Revocation Layer',
  '### 12. Incident Layer',
  '### 13. Registry Layer',
  '### 14. Transport Layer',
  '### 15. Runtime Layer',
  '### 16. Developer Layer',
  '### 17. Interop Layer',
  'FIDES v2 is TS-first and Rust adapter-ready',
  'FIDES must not depend on `@oaps/core` as a runtime dependency',
  'Payment-specific domain stays in Sardis',
  'Protocol objects, schemas, crypto, canonical JSON, signing, AgentCards, EvidenceEvents, DHT records, SessionGrants, attestations, revocations, and incidents remain framework-agnostic',
  'Public SDK APIs are Promise-based',
])

requireContains('docs/getting-started.md', [
  'Discovery is not authority',
  'Identity is not trust',
  'Trust is not permission',
  'Policy and scoped session grants are the authority path',
])

requireContains('docs/protocol/privacy-model.md', [
  'hash_only',
  'redacted',
])

requireContains('docs/protocol/canonical-object-signing.md', [
  'canonical',
  'payload_hash',
  'signature',
])

requireContains('docs/adr/oaps-concepts-ported.md', [
  'FIDES does not depend on `@oaps/core` at runtime',
])

requireContains('docs/adr/sardis-patterns-only.md', [
  'Payment-specific domain remains in Sardis',
])

requireContains('docs/adr/use-effect-internally.md', [
  'Protocol objects and public SDK APIs remain framework-agnostic',
  'Promise-based',
])

requireNoRuntimeDependency('@oaps/core')

if (errors.length > 0) {
  console.error('FIDES v2 docs audit failed:')
  for (const error of errors) {
    console.error(`- ${error}`)
  }
  process.exit(1)
}

console.log(`FIDES v2 docs audit passed for ${requiredDocs.length} required docs.`)

function requireContains(filePath, expectedSnippets) {
  const absolutePath = join(root, filePath)
  if (!existsSync(absolutePath)) return

  const contents = readFileSync(absolutePath, 'utf8')
  for (const snippet of expectedSnippets) {
    if (!contents.includes(snippet)) {
      errors.push(`${filePath} is missing required text: ${snippet}`)
    }
  }
}

function requireMatches(filePath, expectedPatterns) {
  const absolutePath = join(root, filePath)
  if (!existsSync(absolutePath)) return

  const contents = readFileSync(absolutePath, 'utf8')
  for (const pattern of expectedPatterns) {
    if (!pattern.test(contents)) {
      errors.push(`${filePath} is missing required pattern: ${pattern}`)
    }
  }
}

function requireNoRuntimeDependency(packageName) {
  for (const packageJsonPath of findFiles(root, 'package.json')) {
    const relativePath = relative(root, packageJsonPath)
    if (relativePath.includes('node_modules')) continue
    const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf8'))
    const runtimeDependencyMaps = [
      ['dependencies', pkg.dependencies],
      ['peerDependencies', pkg.peerDependencies],
      ['optionalDependencies', pkg.optionalDependencies],
    ]
    for (const [field, dependencies] of runtimeDependencyMaps) {
      if (dependencies?.[packageName]) {
        errors.push(`${relativePath} must not declare runtime dependency ${field}.${packageName}`)
      }
    }
  }
}

function findFiles(dir, fileName) {
  const entries = readdirSync(dir)
  const files = []
  for (const entry of entries) {
    if (entry === 'node_modules' || entry === '.git' || entry === 'dist' || entry === '.turbo') continue
    const absolutePath = join(dir, entry)
    const stats = statSync(absolutePath)
    if (stats.isDirectory()) {
      files.push(...findFiles(absolutePath, fileName))
    } else if (stats.isFile() && entry === fileName) {
      files.push(absolutePath)
    }
  }
  return files
}
