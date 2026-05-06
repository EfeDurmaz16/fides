import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AgentDiscoveryClient, DiscoveryClient } from '@fides/sdk'

const openApiPath = resolve(process.cwd(), '../../docs/api/discovery.yaml')
const openApi = readFileSync(openApiPath, 'utf8')
const discoveryPaths = extractOpenApiPaths(openApi)
const securedOperations = extractApiKeySecuredOperations(openApi)

describe('Discovery OpenAPI contract', () => {
  const fetchMock = vi.fn()
  const did = 'did:fides:contract-agent'
  const identity = {
    did,
    publicKey: 'aa'.repeat(32),
    algorithm: 'ed25519' as const,
    metadata: {},
    createdAt: '2026-01-01T00:00:00.000Z',
  }
  const agent = {
    did,
    name: 'Contract Agent',
    url: 'https://agent.example.com',
    version: '1.0.0',
    publicKey: identity.publicKey,
    algorithm: 'ed25519',
    provider: null,
    capabilities: {},
    skills: [],
    defaultInputModes: [],
    defaultOutputModes: [],
    status: 'online',
    heartbeatAt: '2026-01-01T00:00:00.000Z',
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  }

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
  })

  it('documents every discovery SDK route and method', async () => {
    const identities = new DiscoveryClient({ baseUrl: 'http://discovery.test', apiKey: 'contract-key' })
    const agents = new AgentDiscoveryClient({ baseUrl: 'http://discovery.test', apiKey: 'contract-key' })

    fetchMock.mockResolvedValue({ ok: true, status: 200, text: async () => JSON.stringify({ ok: true }), json: async () => ({ ok: true }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 201, json: async () => identity })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, json: async () => identity })
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        ...identity,
        domain: 'agent.example.com',
        domainVerified: true,
        domainVerifiedAt: '2026-01-01T00:00:00.000Z',
        verificationMethod: 'dns',
        verification: { domain: 'agent.example.com', did, recordName: '_fides.agent.example.com', verified: true },
      }),
    })
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        ...identity,
        organizationDomain: 'example.com',
        organizationDomainVerified: true,
        organizationDomainVerifiedAt: '2026-01-01T00:00:00.000Z',
        organizationVerificationMethod: 'dns',
        verification: { domain: 'example.com', did, recordName: '_fides-org.example.com', verified: true },
      }),
    })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 201, json: async () => agent })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, json: async () => [agent] })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, json: async () => agent })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ ...agent, name: 'Contract Agent v2' }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ status: 'online' }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ message: 'Agent deregistered' }) })

    await identities.register({ did, publicKey: identity.publicKey })
    await identities.resolve(did)
    await identities.verifyDomain(did, 'agent.example.com')
    await identities.verifyOrganizationDomain(did, 'example.com')
    await agents.registerAgent({ did, name: agent.name, url: agent.url })
    await agents.discoverAgents({ status: 'online', capability: 'payments.execute', tag: 'payments', provider: 'fides', limit: 10, offset: 0 })
    await agents.getAgent(did)
    await agents.updateAgent(did, { name: 'Contract Agent v2' })
    await agents.heartbeat(did)
    await agents.deregisterAgent(did)

    const calls = fetchMock.mock.calls.map(([url, init]) => ({
      method: ((init as RequestInit | undefined)?.method || 'GET').toLowerCase(),
      path: normalizeDiscoveryPath(String(url)),
    }))

    for (const call of calls) {
      expect(discoveryPaths.get(call.path), `${call.method.toUpperCase()} ${call.path}`).toContain(call.method)
    }
  })

  it('documents discovery schemas and API key security on write operations', () => {
    expect(openApi).toContain('IdentityResponse:')
    expect(openApi).toContain('IdentityDomainVerificationResponse:')
    expect(openApi).toContain('OrganizationDomainVerificationResponse:')
    expect(openApi).toContain('AgentResponse:')
    expect(openApi).toContain('DiscoveryDocument:')
    expect(openApi).toContain('ApiKeyAuth:')

    const writeOperations = [
      'post /identities',
      'post /identities/{did}/domain/verify',
      'post /identities/{did}/organization-domain/verify',
      'post /agents',
      'put /agents/{did}',
      'delete /agents/{did}',
      'put /agents/{did}/heartbeat',
    ]

    for (const operation of writeOperations) {
      expect(securedOperations, operation).toContain(operation)
    }
  })
})

function normalizeDiscoveryPath(url: string): string {
  const parsed = new URL(url)
  const decoded = decodeURIComponent(parsed.pathname)
  if (decoded.startsWith('/identities/did:') && decoded.endsWith('/organization-domain/verify')) {
    return '/identities/{did}/organization-domain/verify'
  }
  if (decoded.startsWith('/identities/did:') && decoded.endsWith('/domain/verify')) return '/identities/{did}/domain/verify'
  if (decoded.startsWith('/identities/did:')) return '/identities/{did}'
  if (decoded.startsWith('/agents/did:') && decoded.endsWith('/heartbeat')) return '/agents/{did}/heartbeat'
  if (decoded.startsWith('/agents/did:')) return '/agents/{did}'
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

    const methodMatch = line.match(/^    (get|post|put|patch|delete):$/)
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

    const methodMatch = line.match(/^    (get|post|put|patch|delete):$/)
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
