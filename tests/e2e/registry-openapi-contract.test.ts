import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { RegistryClient } from '@fides/sdk'

const openApiPath = resolve(process.cwd(), '../../docs/api/registry.yaml')
const openApi = readFileSync(openApiPath, 'utf8')
const registryPaths = extractOpenApiPaths(openApi)

describe('Registry OpenAPI contract', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
  })

  it('documents every RegistryClient route and method', async () => {
    const client = new RegistryClient({ baseUrl: 'http://registry.test/', apiKey: 'contract-key' })
    const card = {
      id: 'did:fides:contract-agent',
      name: 'Contract Agent',
      version: '1.0.0',
      capabilities: [{ id: 'registry.contract', name: 'Registry Contract' }],
      protocols: ['mcp'],
      endpoints: [],
      security: { authentication: ['api-key'], encryption: ['tls1.3'] },
      metadata: {},
    }

    fetchMock.mockResolvedValue({ ok: true, status: 200, text: async () => JSON.stringify({ success: true, mode: 'private' }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 201, text: async () => JSON.stringify({ success: true, did: card.id, registeredAt: '2026-01-01T00:00:00.000Z' }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify(card) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ results: [{ did: card.id, name: card.name, capabilities: ['registry.contract'] }], count: 1, query: 'Contract' }) })
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ total: 1, public: 1, private: 0 }) })

    await client.register(card)
    await client.getCard(card.id)
    await client.search('Contract')
    await client.stats()
    await client.setMode(card.id, 'private')
    await client.updateMetadata(card.id, { owner: 'contract' })
    await client.deleteCard(card.id)

    const calls = fetchMock.mock.calls.map(([url, init]) => ({
      method: ((init as RequestInit).method || 'GET').toLowerCase(),
      path: normalizeRegistryPath(String(url)),
    }))

    for (const call of calls) {
      expect(registryPaths.get(call.path), `${call.method.toUpperCase()} ${call.path}`).toContain(call.method)
    }
  })

  it('keeps registry lifecycle schemas documented', () => {
    expect(openApi).toContain('RegisterResponse:')
    expect(openApi).toContain('SearchResponse:')
    expect(openApi).toContain('StatsResponse:')
    expect(openApi).toContain('HealthResponse:')
    expect(openApi).toContain('enum: [memory, file, postgres]')
    expect(openApi).toContain('ApiKeyAuth:')
  })
})

function normalizeRegistryPath(url: string): string {
  const parsed = new URL(url)
  const decoded = decodeURIComponent(parsed.pathname)
  if (decoded.startsWith('/v1/cards/did:') && decoded.endsWith('/mode')) return '/v1/cards/{did}/mode'
  if (decoded.startsWith('/v1/cards/did:') && decoded.endsWith('/metadata')) return '/v1/cards/{did}/metadata'
  if (decoded.startsWith('/v1/cards/did:')) return '/v1/cards/{did}'
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
