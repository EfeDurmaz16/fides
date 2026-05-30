import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const errors = []

const requiredProtocolObjects = [
  {
    name: 'AgentIdentity',
    source: ['AgentIdentity'],
    docs: ['AgentIdentity'],
    tests: ['createAgentIdentity', 'AgentIdentity'],
  },
  {
    name: 'PublisherIdentity',
    source: ['PublisherIdentity'],
    docs: ['PublisherIdentity'],
    tests: ['createPublisherIdentity', 'PublisherIdentity'],
  },
  {
    name: 'PrincipalIdentity',
    source: ['PrincipalIdentity'],
    docs: ['PrincipalIdentity'],
    tests: ['createPrincipalIdentity', 'PrincipalIdentity'],
  },
  {
    name: 'TrustAnchor',
    source: ['TrustAnchor', 'IdentityTrustAnchor', 'GovernedTrustAnchor'],
    docs: ['TrustAnchor', 'trust anchor'],
    tests: ['TrustAnchor', 'trust anchor'],
  },
  {
    name: 'Attestation',
    source: ['interface Attestation ', 'createAttestation', 'SignedAttestation'],
    docs: ['Attestation', 'attestation'],
    tests: ['createAttestation', 'signAttestation'],
  },
  {
    name: 'RuntimeAttestation',
    source: ['RuntimeAttestation'],
    docs: ['RuntimeAttestation'],
    tests: ['RuntimeAttestation', 'MockTEEProvider', 'verifyRuntimeAttestation'],
  },
  {
    name: 'AgentCard',
    source: ['AgentCard'],
    docs: ['AgentCard'],
    tests: ['AgentCard', 'signAgentCard', 'verifySignedAgentCard'],
  },
  {
    name: 'CapabilityDescriptor',
    source: ['CapabilityDescriptor'],
    docs: ['CapabilityDescriptor'],
    tests: ['CapabilityDescriptor', 'createCapabilityDescriptor'],
  },
  {
    name: 'CapabilityOntologyEntry',
    source: ['CapabilityOntologyEntry', 'DEFAULT_CAPABILITY_ONTOLOGY'],
    docs: ['CapabilityOntologyEntry', 'ontology'],
    tests: ['CapabilityOntologyEntry', 'DEFAULT_CAPABILITY_ONTOLOGY', 'findCapabilityOntologyEntry'],
  },
  {
    name: 'DiscoveryQuery',
    source: ['DiscoveryQuery'],
    docs: ['DiscoveryQuery'],
    tests: ['DiscoveryQuery', 'createDiscoveryQuery'],
  },
  {
    name: 'DiscoveryCandidate',
    source: ['DiscoveryCandidate'],
    docs: ['DiscoveryCandidate'],
    tests: ['DiscoveryCandidate', 'createDiscoveryCandidate'],
  },
  {
    name: 'DHTPointerRecord',
    source: ['DHTPointerRecord'],
    docs: ['DHTPointerRecord'],
    tests: ['DHTPointerRecord', 'createDHTPointerRecord'],
  },
  {
    name: 'RegistryIndexRecord',
    source: ['RegistryIndexRecord'],
    docs: ['RegistryIndexRecord'],
    tests: ['RegistryIndexRecord', 'createRegistryIndexRecord'],
  },
  {
    name: 'RegistryPeerRecord',
    source: ['RegistryPeerRecord'],
    docs: ['RegistryPeerRecord'],
    tests: ['RegistryPeerRecord', 'createRegistryPeerRecord'],
  },
  {
    name: 'TrustResult',
    source: ['TrustResult'],
    docs: ['TrustResult'],
    tests: ['TrustResult', 'computeTrust'],
  },
  {
    name: 'ReputationRecord',
    source: ['ReputationRecord'],
    docs: ['ReputationRecord', 'reputation record'],
    tests: ['ReputationRecord', 'createReputationRecord'],
  },
  {
    name: 'PolicyBundle',
    source: ['PolicyBundle'],
    docs: ['PolicyBundle'],
    tests: ['PolicyBundle', 'evaluatePolicy'],
  },
  {
    name: 'PolicyDecision',
    source: ['FidesPolicyDecision', 'PolicyResult'],
    docs: ['PolicyDecision', 'policy decision'],
    tests: ['FidesPolicyDecision', 'evaluateFidesPolicy', 'PolicyResult'],
  },
  {
    name: 'ApprovalRequest',
    source: ['ApprovalRequest'],
    docs: ['ApprovalRequest'],
    tests: ['ApprovalRequest', 'createApprovalRequest'],
  },
  {
    name: 'ApprovalDecision',
    source: ['ApprovalDecision'],
    docs: ['ApprovalDecision'],
    tests: ['ApprovalDecision', 'createApprovalDecision'],
  },
  {
    name: 'KillSwitchRule',
    source: ['KillSwitchRule'],
    docs: ['KillSwitchRule'],
    tests: ['KillSwitchRule', 'createKillSwitchRule'],
  },
  {
    name: 'DelegationToken',
    source: ['DelegationTokenV2', 'DelegationToken'],
    docs: ['DelegationToken'],
    tests: ['DelegationTokenV2', 'createDelegationTokenV2', 'createDelegationToken'],
  },
  {
    name: 'SessionGrant',
    source: ['SessionGrantV2', 'SessionGrant'],
    docs: ['SessionGrant'],
    tests: ['SessionGrantV2', 'createSessionGrantV2', 'createSessionGrant'],
  },
  {
    name: 'InvocationRequest',
    source: ['InvocationRequest'],
    docs: ['InvocationRequest'],
    tests: ['InvocationRequest', 'createInvocationRequest'],
  },
  {
    name: 'InvocationResult',
    source: ['InvocationResult'],
    docs: ['InvocationResult'],
    tests: ['InvocationResult', 'createInvocationResult'],
  },
  {
    name: 'EvidenceEvent',
    source: ['EvidenceEventV2', 'EvidenceEvent'],
    docs: ['EvidenceEvent'],
    tests: ['EvidenceEventV2', 'createEvidenceEventV2', 'appendEvidenceEvent'],
  },
  {
    name: 'RevocationRecord',
    source: ['RevocationRecordV2', 'RevocationRecord'],
    docs: ['RevocationRecord'],
    tests: ['RevocationRecordV2', 'createRevocationRecordV2', 'createRevocationRecord'],
  },
  {
    name: 'IncidentRecord',
    source: ['IncidentRecordV2', 'IncidentRecord'],
    docs: ['IncidentRecord'],
    tests: ['IncidentRecordV2', 'createIncidentRecordV2', 'createIncidentRecord'],
  },
  {
    name: 'ErrorEnvelope',
    source: ['ErrorEnvelope'],
    docs: ['ErrorEnvelope'],
    tests: ['ErrorEnvelope', 'createErrorEnvelope'],
  },
  {
    name: 'VersionNegotiationRecord',
    source: ['VersionNegotiationRecord'],
    docs: ['VersionNegotiationRecord'],
    tests: ['VersionNegotiationRecord', 'negotiateProtocolVersion'],
  },
]

const sourceCorpus = readCorpus([
  'packages/core/src',
  'packages/evidence/src',
  'packages/policy/src',
])
const docsCorpus = readCorpus([
  'docs/protocol',
  'docs/architecture',
  'docs/api-reference.md',
  'docs/cli-reference.md',
  'docs/sdk-reference.md',
])
const testCorpus = readCorpus([
  'packages/core/test',
  'packages/evidence/test',
  'packages/policy/test',
  'packages/invocation/test',
  'tests',
])

for (const object of requiredProtocolObjects) {
  requireAny(sourceCorpus, object.source, `${object.name} source`)
  requireAny(docsCorpus, object.docs, `${object.name} docs`)
  requireAny(testCorpus, object.tests, `${object.name} tests`)
}

requireContains(readFile('packages/core/src/index.ts'), [
  './identity.js',
  './runtime-attestation.js',
  './agent-card.js',
  './capability.js',
  './discovery.js',
  './dht.js',
  './trust.js',
  './reputation.js',
  './approval.js',
  './delegation.js',
  './invocation.js',
  './registry.js',
  './revocation.js',
  './versioning.js',
  './errors.js',
])

if (errors.length > 0) {
  console.error('FIDES v2 protocol object audit failed:')
  for (const error of errors) {
    console.error(`- ${error}`)
  }
  process.exit(1)
}

console.log(`FIDES v2 protocol object audit passed for ${requiredProtocolObjects.length} required objects.`)

function requireAny(corpus, needles, label) {
  if (needles.some(needle => corpus.includes(needle))) return
  errors.push(`${label} is missing one of: ${needles.join(', ')}`)
}

function requireContains(corpus, snippets) {
  for (const snippet of snippets) {
    if (!corpus.includes(snippet)) {
      errors.push(`core package barrel export coverage is missing: ${snippet}`)
    }
  }
}

function readCorpus(paths) {
  return paths.map(readPath).join('\n')
}

function readPath(path) {
  const absolutePath = join(root, path)
  if (!existsSync(absolutePath)) return ''
  const stats = statSync(absolutePath)
  if (stats.isFile()) return readFileSync(absolutePath, 'utf8')

  const chunks = []
  for (const filePath of findFiles(absolutePath)) {
    chunks.push(`\n// ${relative(root, filePath)}\n`)
    chunks.push(readFileSync(filePath, 'utf8'))
  }
  return chunks.join('\n')
}

function readFile(path) {
  const absolutePath = join(root, path)
  return existsSync(absolutePath) ? readFileSync(absolutePath, 'utf8') : ''
}

function findFiles(dir) {
  const entries = readdirSync(dir)
  const files = []
  for (const entry of entries) {
    if (entry === 'node_modules' || entry === '.git' || entry === 'dist' || entry === '.turbo') continue
    const absolutePath = join(dir, entry)
    const stats = statSync(absolutePath)
    if (stats.isDirectory()) {
      files.push(...findFiles(absolutePath))
    } else if (stats.isFile() && /\.(ts|md)$/.test(entry)) {
      files.push(absolutePath)
    }
  }
  return files
}
