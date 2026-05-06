import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { PlatformClient } from '@fides/sdk'

const openApiPath = resolve(process.cwd(), '../../docs/api/platform-api.yaml')
const openApi = readFileSync(openApiPath, 'utf8')
const platformPaths = extractOpenApiPaths(openApi)
const securedOperations = extractApiKeySecuredOperations(openApi)

describe('Platform API OpenAPI contract', () => {
  const fetchMock = vi.fn()
  const binding = {
    principalDid: 'did:fides:principal-contract-01',
    credentialId: 'credential-contract-01',
    publicKey: 'provider-public-key',
    relyingPartyId: 'example.com',
    signCount: 1,
    createdAt: '2026-01-01T00:00:00.000Z',
  }
  const anchor = {
    did: 'did:fides:anchor-contract-01',
    name: 'Contract Anchor',
    publicKey: '44'.repeat(32),
    attestation: {
      payload: { did: 'did:fides:anchor-contract-01' },
      proof: {
        type: 'Ed25519Signature2024',
        created: '2026-01-01T00:00:00.000Z',
        verificationMethod: 'did:fides:issuer-contract-01#key-1',
        proofPurpose: 'assertionMethod',
        canonicalizationAlgorithm: 'https://fides.dev/canonical-json/v1',
        proofValue: 'signature',
      },
    },
    status: 'active' as const,
    scopes: ['identity.organization'],
    issuerDid: 'did:fides:issuer-contract-01',
    createdAt: '2026-01-01T00:00:00.000Z',
  }

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
  })

  it('documents every PlatformClient route and method', async () => {
    const client = new PlatformClient({ baseUrl: 'http://platform.test/', apiKey: 'contract-key' })

    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          service: 'platform-api',
          components: {
            discovery: 'http://localhost:3100',
            trustGraph: 'http://localhost:3200',
            policyEngine: 'http://localhost:3300',
            registry: 'http://localhost:7346',
            relay: 'http://localhost:7347',
            agentd: 'http://localhost:7345',
          },
        }),
      })
      .mockResolvedValueOnce({ ok: true, status: 201, text: async () => JSON.stringify({ binding }) })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          principalDid: binding.principalDid,
          credentials: [{ credentialId: binding.credentialId, relyingPartyId: binding.relyingPartyId, signCount: 1, createdAt: binding.createdAt }],
          count: 1,
        }),
      })
      .mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ binding }) })
      .mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ success: true }) })
      .mockResolvedValueOnce({ ok: true, status: 201, text: async () => JSON.stringify({ anchor }) })
      .mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ anchors: [anchor], count: 1 }) })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          distribution: {
            version: 'fides.trust-anchors.v1',
            generatedAt: '2026-01-01T00:00:00.000Z',
            anchors: [{
              did: anchor.did,
              name: anchor.name,
              publicKey: anchor.publicKey,
              scopes: anchor.scopes,
              issuerDid: anchor.issuerDid,
              createdAt: anchor.createdAt,
            }],
          },
        }),
      })
      .mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ anchor }) })
      .mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ anchor: { ...anchor, status: 'revoked' } }) })
      .mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ success: true }) })

    await client.topology()
    await client.storePasskeyBinding(binding)
    await client.listPasskeyCredentials(binding.principalDid)
    await client.getPasskeyBinding(binding.credentialId)
    await client.deletePasskeyBinding(binding.credentialId)
    await client.storeTrustAnchor(anchor)
    await client.listTrustAnchors('active')
    await client.trustAnchorDistribution({ requiredScope: 'identity.organization', trustedIssuerDids: [anchor.issuerDid] })
    await client.getTrustAnchor(anchor.did)
    await client.updateTrustAnchorStatus(anchor.did, { status: 'revoked', reason: 'key compromise' })
    await client.deleteTrustAnchor(anchor.did)

    const calls = fetchMock.mock.calls.map(([url, init]) => ({
      method: ((init as RequestInit).method || 'GET').toLowerCase(),
      path: normalizePlatformPath(String(url)),
    }))

    for (const call of calls) {
      expect(platformPaths.get(call.path), `${call.method.toUpperCase()} ${call.path}`).toContain(call.method)
    }
  })

  it('keeps platform schemas documented', () => {
    expect(openApi).toContain('PlatformTopologyResponse:')
    expect(openApi).toContain('PasskeyCredentialBinding:')
    expect(openApi).toContain('PasskeyCredentialsResponse:')
    expect(openApi).toContain('TrustAnchorRecord:')
    expect(openApi).toContain('TrustAnchorDistribution:')
    expect(openApi).toContain('TrustAnchorStatusUpdate:')
    expect(openApi).toContain('ApiKeyAuth:')
  })

  it('documents API key auth on protected v1 operations', () => {
    const protectedOperations = [
      'get /v1/topology',
      'post /v1/passkeys/bindings',
      'get /v1/passkeys/principals/{did}/credentials',
      'get /v1/passkeys/credentials/{credentialId}',
      'delete /v1/passkeys/credentials/{credentialId}',
      'get /v1/trust-anchors',
      'post /v1/trust-anchors',
      'get /v1/trust-anchors/distribution',
      'get /v1/trust-anchors/{did}',
      'delete /v1/trust-anchors/{did}',
      'patch /v1/trust-anchors/{did}/status',
    ]

    for (const operation of protectedOperations) {
      expect(securedOperations, operation).toContain(operation)
    }
  })
})

function normalizePlatformPath(url: string): string {
  const parsed = new URL(url)
  const decoded = decodeURIComponent(parsed.pathname)
  if (decoded.startsWith('/v1/passkeys/principals/did:')) return '/v1/passkeys/principals/{did}/credentials'
  if (decoded.startsWith('/v1/passkeys/credentials/')) return '/v1/passkeys/credentials/{credentialId}'
  if (decoded.startsWith('/v1/trust-anchors/did:') && decoded.endsWith('/status')) return '/v1/trust-anchors/{did}/status'
  if (decoded.startsWith('/v1/trust-anchors/did:')) return '/v1/trust-anchors/{did}'
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
