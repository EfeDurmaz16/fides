import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AgentdClient } from '@fides/sdk'

const openApiPath = resolve(process.cwd(), '../../docs/api/agentd.yaml')
const openApi = readFileSync(openApiPath, 'utf8')
const agentdSourcePath = resolve(process.cwd(), '../../services/agentd/src/index.ts')
const agentdSource = readFileSync(agentdSourcePath, 'utf8')
const agentdPaths = extractOpenApiPaths(openApi)
const securedOperations = extractApiKeySecuredOperations(openApi)

describe('Agentd OpenAPI contract', () => {
  const fetchMock = vi.fn()
  const token = {
    id: 'tok-1',
    delegator: 'did:fides:principal',
    delegatee: 'did:fides:agent',
    capabilities: ['payments.execute'],
    constraints: {},
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2026-01-01T01:00:00.000Z',
    nonce: 'nonce-1',
    signature: 'aa',
    audience: ['agentd'],
  }
  const revocation = {
    id: 'rev-1',
    did: 'did:fides:agent',
    reason: 'disabled',
    revokedAt: '2026-01-01T00:00:00.000Z',
    revokedBy: 'did:fides:principal',
    signature: 'bb',
    propagatedTo: [],
  }
  const incident = {
    id: 'inc-1',
    type: 'policy_violation' as const,
    severity: 'high' as const,
    actor: 'did:fides:agent',
    reportedBy: 'did:fides:principal',
    description: 'policy bypass',
    evidenceRefs: [],
    reportedAt: '2026-01-01T00:00:00.000Z',
    impact: {
      trustPenalty: 0.35,
      reputationPenalty: 0.7,
      capabilitiesRevoked: ['payments.execute'],
    },
    signature: 'cc',
  }

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
  })

  it('documents every AgentdClient route and method', async () => {
    const client = new AgentdClient({ baseUrl: 'http://agentd.test/', apiKey: 'contract-key' })
    const session = {
      id: 'sess-1',
      token,
      sessionKey: 'redacted',
      expiresAt: token.expiresAt,
    }

    fetchMock.mockResolvedValue({ ok: true, status: 200, text: async () => JSON.stringify({ ok: true }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 201, text: async () => JSON.stringify({ authorized: true, session }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ session }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ did: token.delegatee, card: { id: token.delegatee } }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ domain: 'example.com', did: token.delegatee, recordName: '_fides.example.com', verified: true }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ revoked: true, session: { ...session, revoked: true } }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 201, text: async () => JSON.stringify({ revoked: true, record: revocation }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ did: revocation.did, revoked: true, record: revocation }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 201, text: async () => JSON.stringify({ recorded: true, record: incident }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ did: incident.actor, incidents: [incident], impact: {} }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ decision: 'allow', explanation: 'allowed' }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ count: 1, propagations: [{ id: 'prop-1' }] }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ attempted: 1, results: [{ id: 'prop-1', ok: true, status: 200 }] }) })

    await client.createSession({ token, capabilityId: 'payments.execute', audience: 'agentd' })
    await client.getSession(session.id)
    await client.getCard(token.delegatee)
    await client.verifyDomain('example.com', token.delegatee)
    await client.revokeSession(session.id, 'operator disabled')
    await client.recordRevocation({ record: revocation })
    await client.getRevocation(revocation.did)
    await client.recordIncident({ record: incident })
    await client.listIncidents(incident.actor)
    await client.authorize({ agentDid: token.delegatee, capabilityId: 'payments.execute' })
    await client.listPendingPropagations(5)
    await client.retryPropagations(5)

    const calls = fetchMock.mock.calls.map(([url, init]) => ({
      method: ((init as RequestInit).method || 'GET').toLowerCase(),
      path: normalizeAgentdPath(String(url)),
    }))

    for (const call of calls) {
      expect(agentdPaths.get(call.path), `${call.method.toUpperCase()} ${call.path}`).toContain(call.method)
    }
  })

  it('keeps authority and card schemas documented', () => {
    expect(openApi).toContain('CardResponse:')
    expect(openApi).toContain('DomainVerificationResponse:')
    expect(openApi).toContain('SessionCreateResponse:')
    expect(openApi).toContain('RevocationSubmitResponse:')
    expect(openApi).toContain('IncidentSubmitResponse:')
    expect(openApi).toContain('AuthorizationResponse:')
    expect(openApi).toContain('AuthorityPropagationListResponse:')
    expect(openApi).toContain('AuthorityPropagationRetryResponse:')
    expect(openApi).toContain('ApiKeyAuth:')
  })

  it('documents runtime evidence privacy modes', () => {
    expect(openApi).toContain('enum: [public, private, redacted, hash_only]')
    expect(openApi).not.toContain('enum: [public, private, redacted, hash-only]')
  })

  it('documents root v2 local Agent Trust Fabric endpoints', () => {
    const expectedOperations = [
      'post /identities',
      'get /identities',
      'get /identities/{id}',
      'post /attestations',
      'get /attestations/{id}',
      'post /attestations/{id}/verify',
      'post /agent-cards',
      'get /agent-cards/{id}',
      'post /agent-cards/{id}/sign',
      'post /agent-cards/{id}/verify',
      'post /agents/register',
      'get /agents',
      'get /agents/{id}',
      'post /discover',
      'post /discover/local',
      'post /discover/well-known',
      'post /discover/registry',
      'post /discover/relay',
      'post /discover/dht',
      'post /discover/federation',
      'post /trust/evaluate',
      'get /trust/{id}',
      'post /reputation/update',
      'get /reputation/{id}',
      'post /policy/evaluate',
      'post /approvals',
      'get /approvals',
      'post /approvals/{id}/approve',
      'post /approvals/{id}/deny',
      'post /delegations',
      'post /sessions',
      'get /sessions/{id}',
      'post /sessions/{id}/verify',
      'post /invoke',
      'post /evidence',
      'get /evidence',
      'get /evidence/{id}',
      'post /evidence/verify',
      'post /evidence/export',
      'post /revocations',
      'get /revocations',
      'get /revocations/{id}',
      'post /incidents',
      'get /incidents',
      'get /incidents/{id}',
      'post /incidents/{id}/resolve',
      'post /killswitch',
      'get /killswitch',
      'delete /killswitch/{id}',
      'post /dht/start',
      'post /dht/publish',
      'get /dht/find',
      'post /dht/find',
      'post /registry/start',
      'post /registry/publish',
      'post /registry/search',
      'get /registry/index',
      'post /relay/start',
      'post /relay/register',
      'post /relay/discover',
      'get /.well-known/fides.json',
      'get /.well-known/agents.json',
      'get /.well-known/agents/{id}.json',
      'post /demo/run',
      'post /simulate/adversarial',
    ]

    for (const operation of expectedOperations) {
      const [method, path] = operation.split(' ')
      expect(agentdPaths.get(path), operation).toContain(method)
    }
  })

  it('documents demo and adversarial simulation response invariants', () => {
    expect(extractSchemaRequired(openApi, 'LocalDemoRunResponse')).toEqual([
      'status',
      'mode',
      'steps',
      'identities',
      'discovery',
      'verification',
      'authority',
      'surfaces',
      'limitations',
    ])
    expect(extractSchemaRequired(openApi, 'LocalDemoAuthoritySummary')).toEqual([
      'discoveryGrantsAuthority',
      'policyBeforeExecution',
      'evidenceProduced',
    ])
    expect(extractNestedRequired(openApi, 'LocalDemoRunResponse', 'verification')).toEqual([
      'agentCardsVerified',
      'evidenceHashChainValid',
      'evidenceEventCount',
      'evidenceExport',
    ])
    expect(extractSchemaRequired(openApi, 'LocalAdversarialScenario')).toEqual([
      'name',
      'detected',
      'outcome',
      'evidenceRef',
    ])
    expect(extractSchemaRequired(openApi, 'LocalAdversarialSimulationResponse')).toEqual([
      'status',
      'mode',
      'detections',
      'scenarios',
      'evidence',
      'authority',
      'limitations',
    ])
    expect(extractNestedRequired(openApi, 'LocalAdversarialSimulationResponse', 'evidence')).toEqual([
      'scenarioEvents',
      'incidentEvidenceRef',
      'rootChainValid',
      'rootEventCount',
      'brokenEvidenceChainValid',
    ])
  })

  it('documents discovery publish and presence writes as non-authority responses', () => {
    for (const schemaName of ['LocalDhtPublishResponse', 'LocalRegistryPublishResponse', 'LocalRelayRegisterResponse']) {
      expect(extractSchemaRequired(openApi, schemaName), schemaName).toContain('authorityGranted')
      expect(extractSchemaPropertyBlock(openApi, schemaName, 'authorityGranted'), schemaName).toContain('enum: [false]')
    }
  })

  it('documents discovery responses as evidence-producing candidate results', () => {
    const schema = extractSchemaBlock(openApi, 'DiscoveryResponse')
    expect(schema).toContain('authorityGranted:')
    expect(schema).toContain('enum: [false]')
    expect(schema).toContain('evidenceRefs:')
    expect(schema).toContain('evidence_refs:')
  })

  it('keeps root v2 runtime routes documented in OpenAPI', () => {
    const runtimeOperations = extractAgentdRuntimeRoutes(agentdSource)
      .filter(operation => operation.path.startsWith('/'))
      .filter(operation => !operation.path.startsWith('/v1/'))
      .filter(operation => operation.path !== '/metrics')

    for (const operation of runtimeOperations) {
      expect(agentdPaths.get(operation.path), `${operation.method} ${operation.path}`).toContain(operation.method)
    }
  })

  it('documents API key auth on mutating v1 operations', () => {
    const mutatingV1Operations = [
      'post /v1/policy/evaluate',
      'post /v1/sessions',
      'post /v1/sessions/{id}/revoke',
      'post /v1/revocations',
      'post /v1/incidents',
      'post /v1/authorize',
      'post /v1/evidence',
      'post /v1/authority/propagations/retry',
      'post /v1/attest',
      'post /v1/killswitch/engage',
      'post /v1/killswitch/disengage',
    ]

    for (const operation of mutatingV1Operations) {
      expect(securedOperations, operation).toContain(operation)
    }
  })
})

function normalizeAgentdPath(url: string): string {
  const parsed = new URL(url)
  const decoded = decodeURIComponent(parsed.pathname)
  if (decoded.startsWith('/v1/sessions/') && decoded.endsWith('/revoke')) return '/v1/sessions/{id}/revoke'
  if (decoded.startsWith('/v1/sessions/')) return '/v1/sessions/{id}'
  if (decoded.startsWith('/v1/cards/did:')) return '/v1/cards/{did}'
  if (decoded.startsWith('/v1/revocations/did:')) return '/v1/revocations/{did}'
  if (decoded.startsWith('/v1/incidents/did:')) return '/v1/incidents/{did}'
  return decoded
}

function extractAgentdRuntimeRoutes(source: string): Array<{ method: string; path: string }> {
  const routes: Array<{ method: string; path: string }> = []
  const routeRegex = /app\.(get|post|delete)\('([^']+)'/g
  let match: RegExpExecArray | null
  while ((match = routeRegex.exec(source))) {
    routes.push({
      method: match[1],
      path: normalizeAgentdRuntimePath(match[2]),
    })
  }
  return routes
}

function normalizeAgentdRuntimePath(path: string): string {
  if (path === '/.well-known/agents/*') return '/.well-known/agents/{id}.json'
  return path.replace(/\/:[^/]+/g, '/{id}')
}

function extractOpenApiPaths(source: string): Map<string, string[]> {
  const paths = new Map<string, string[]>()
  let inPaths = false
  let currentPath: string | null = null

  for (const line of source.split('\n')) {
    if (line === 'paths:') {
      inPaths = true
      continue
    }
    if (inPaths && line.startsWith('components:')) break

    const pathMatch = line.match(/^  (\/[^:]+):$/)
    if (pathMatch) {
      currentPath = pathMatch[1]
      paths.set(currentPath, [])
      continue
    }

    const methodMatch = line.match(/^    (get|post|patch|delete):$/)
    if (currentPath && methodMatch) {
      paths.get(currentPath)?.push(methodMatch[1])
    }
  }

  return paths
}

function extractApiKeySecuredOperations(source: string): string[] {
  const secured = new Set<string>()
  let inPaths = false
  let currentPath: string | null = null
  let currentMethod: string | null = null
  let inSecurityBlock = false

  for (const line of source.split('\n')) {
    if (line === 'paths:') {
      inPaths = true
      continue
    }
    if (inPaths && line.startsWith('components:')) break

    const pathMatch = line.match(/^  (\/[^:]+):$/)
    if (pathMatch) {
      currentPath = pathMatch[1]
      currentMethod = null
      inSecurityBlock = false
      continue
    }

    const methodMatch = line.match(/^    (get|post|patch|delete):$/)
    if (methodMatch) {
      currentMethod = methodMatch[1]
      inSecurityBlock = false
      continue
    }

    if (currentPath && currentMethod && line.match(/^      security:$/)) {
      inSecurityBlock = true
      continue
    }

    if (currentPath && currentMethod && inSecurityBlock && line.match(/^        - ApiKeyAuth: \[\]$/)) {
      secured.add(`${currentMethod} ${currentPath}`)
      inSecurityBlock = false
    }
  }

  return Array.from(secured)
}

function extractSchemaRequired(source: string, schemaName: string): string[] {
  const schema = extractSchemaBlock(source, schemaName)
  for (const line of schema.split('\n')) {
    const match = line.match(/^ {6}required: \[(.*)\]$/)
    if (match) return match[1].split(',').map(item => item.trim()).filter(Boolean)
  }
  throw new Error(`OpenAPI schema ${schemaName} does not define a top-level required array`)
}

function extractNestedRequired(source: string, schemaName: string, propertyName: string): string[] {
  const property = extractSchemaPropertyBlock(source, schemaName, propertyName)
  for (const line of property.split('\n')) {
    const match = line.match(/^ {10}required: \[(.*)\]$/)
    if (match) return match[1].split(',').map(item => item.trim()).filter(Boolean)
  }
  throw new Error(`OpenAPI schema ${schemaName}.${propertyName} does not define a required array`)
}

function extractSchemaPropertyBlock(source: string, schemaName: string, propertyName: string): string {
  const schema = extractSchemaBlock(source, schemaName)
  const lines = schema.split('\n')
  const propertyStart = lines.findIndex(line => line === `        ${propertyName}:`)
  if (propertyStart === -1) throw new Error(`OpenAPI schema ${schemaName} does not define ${propertyName}`)

  const propertyLines = []
  for (const line of lines.slice(propertyStart + 1)) {
    if (line.match(/^        [A-Za-z0-9_]+:$/)) break
    propertyLines.push(line)
  }
  return propertyLines.join('\n')
}

function extractSchemaBlock(source: string, schemaName: string): string {
  const lines = source.split('\n')
  const schemaStart = lines.findIndex(line => line === `    ${schemaName}:`)
  if (schemaStart === -1) throw new Error(`OpenAPI schema ${schemaName} was not found`)

  const schemaLines = []
  for (const line of lines.slice(schemaStart + 1)) {
    if (line.match(/^    [A-Za-z0-9_]+:$/)) break
    schemaLines.push(line)
  }
  return schemaLines.join('\n')
}
