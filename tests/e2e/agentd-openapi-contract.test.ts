import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AgentdClient } from '@fides/sdk'

const openApiPath = resolve(process.cwd(), '../../docs/api/agentd.yaml')
const openApi = readFileSync(openApiPath, 'utf8')
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
