import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const ORIGINAL_SERVICE_API_KEY = process.env.SERVICE_API_KEY
const ORIGINAL_AGENTD_API_KEYS = process.env.AGENTD_API_KEYS
const ORIGINAL_NODE_ENV = process.env.NODE_ENV
const ORIGINAL_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION = process.env.AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION

beforeEach(() => {
  delete process.env.SERVICE_API_KEY
  delete process.env.AGENTD_API_KEYS
  delete process.env.AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION
  process.env.NODE_ENV = 'test'
  vi.restoreAllMocks()
})

afterEach(() => {
  if (ORIGINAL_SERVICE_API_KEY) {
    process.env.SERVICE_API_KEY = ORIGINAL_SERVICE_API_KEY
  } else {
    delete process.env.SERVICE_API_KEY
  }
  if (ORIGINAL_AGENTD_API_KEYS) {
    process.env.AGENTD_API_KEYS = ORIGINAL_AGENTD_API_KEYS
  } else {
    delete process.env.AGENTD_API_KEYS
  }
  if (ORIGINAL_NODE_ENV) {
    process.env.NODE_ENV = ORIGINAL_NODE_ENV
  } else {
    delete process.env.NODE_ENV
  }
  if (ORIGINAL_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION) {
    process.env.AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION = ORIGINAL_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION
  } else {
    delete process.env.AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION
  }
})

vi.stubGlobal('fetch', vi.fn())

vi.mock('node:dns/promises', () => ({
  resolveTxt: vi.fn(),
}))

import { app } from '../src/index.js'
import {
  createDelegationToken,
  createIdentityKeyPair,
  createIncidentRecord,
  createInvocationRequest,
  createRevocationRecord,
  hashProtocolPayload,
  signDelegationToken,
  signIncidentRecord,
  signInvocationRequest,
  signRevocationRecord,
} from '@fides/core'
import * as ed from '@noble/ed25519'
import { bytesToHex } from '@noble/hashes/utils'
import { fullDemoSteps as fullDemoContractSteps } from '../../../examples/full-demo/run.js'

const mockFetch = fetch as ReturnType<typeof vi.fn>

describe('Agentd Service Routes', () => {
  const TEST_DID = 'did:fides:agentd-test-01'

  function makeDelegationToken(overrides: Record<string, unknown> = {}) {
    return {
      ...createDelegationToken({
        delegator: 'did:fides:principal',
        delegatee: TEST_DID,
        capabilities: ['payments.execute', 'files.read'],
        constraints: {},
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        audience: ['agentd'],
      }),
      signature: '00'.repeat(64),
      ...overrides,
    }
  }

  function createMockResponse(body: unknown, status = 200) {
    const bodyStr = JSON.stringify(body)
    return Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(bodyStr),
      headers: new Headers(),
    })
  }

  async function signedRevocationRecord(did: string) {
    const privateKey = Buffer.from('01'.repeat(32), 'hex')
    return signRevocationRecord(createRevocationRecord({
      did,
      reason: 'principal revoked delegation',
      revokedBy: 'did:fides:principal',
    }), privateKey)
  }

  async function signedDelegationToken(delegatee: string) {
    const privateKey = Buffer.from('01'.repeat(32), 'hex')
    const token = createDelegationToken({
      delegator: 'did:fides:principal',
      delegatee,
      capabilities: ['payments.execute'],
      constraints: {},
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      audience: ['agentd'],
    })
    return {
      publicKey: bytesToHex(await ed.getPublicKeyAsync(privateKey)),
      token: await signDelegationToken(token, privateKey),
    }
  }

  async function signedIncidentRecord(actor: string) {
    const privateKey = Buffer.from('01'.repeat(32), 'hex')
    return signIncidentRecord(createIncidentRecord({
      actor,
      reportedBy: 'did:fides:principal',
      type: 'policy_violation',
      severity: 'critical',
      description: 'Repeated unauthorized payment attempts',
      capabilitiesRevoked: ['payments.execute'],
    }), privateKey)
  }

  describe('API Key Authentication', () => {
    it('fails closed for mutations in production when API key is not configured', async () => {
      process.env.NODE_ENV = 'production'
      delete process.env.SERVICE_API_KEY

      const res = await app.request('/v1/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: TEST_DID,
          action: 'test',
          payload: {},
        }),
      })
      expect(res.status).toBe(503)
      const data = await res.json()
      expect(data.error).toContain('SERVICE_API_KEY is required in production')
    })

    it('fails closed for root identity creation in production when API key is not configured', async () => {
      process.env.NODE_ENV = 'production'
      delete process.env.SERVICE_API_KEY

      const res = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Blocked Agent' }),
      })

      expect(res.status).toBe(503)
      expect((await res.json()).error).toContain('SERVICE_API_KEY is required in production')
    })

    it('fails closed for root AgentCard creation in production when API key is not configured', async () => {
      process.env.NODE_ENV = 'production'
      delete process.env.SERVICE_API_KEY

      const res = await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identity: { did: 'did:fides:agent' }, capabilities: [] }),
      })

      expect(res.status).toBe(503)
      expect((await res.json()).error).toContain('SERVICE_API_KEY is required in production')
    })

    it('fails closed for root evidence creation in production when API key is not configured', async () => {
      process.env.NODE_ENV = 'production'
      delete process.env.SERVICE_API_KEY

      const res = await app.request('/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'capability.invoked',
          actor: TEST_DID,
          input: { secret: 'blocked' },
        }),
      })

      expect(res.status).toBe(503)
      expect((await res.json()).error).toContain('SERVICE_API_KEY is required in production')
    })

    it('fails closed for root discovery and delegation mutations in production when API key is not configured', async () => {
      process.env.NODE_ENV = 'production'
      delete process.env.SERVICE_API_KEY

      const requests = [
        app.request('/delegations', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ delegator: 'did:fides:principal', delegatee: TEST_DID, capabilities: ['invoice.reconcile'] }),
        }),
        app.request('/registry/start', { method: 'POST' }),
        app.request('/relay/start', { method: 'POST' }),
      ]

      const responses = await Promise.all(requests)
      for (const res of responses) {
        expect(res.status).toBe(503)
        expect((await res.json()).error).toContain('SERVICE_API_KEY is required in production')
      }
    })

    it('enforces scoped agentd API keys when configured', async () => {
      process.env.AGENTD_API_KEYS = JSON.stringify([
        { key: 'evidence-key', scopes: ['agentd:evidence:write'] },
        { key: 'kill-key', scopes: ['agentd:killswitch:write'] },
      ])

      const accepted = await app.request('/v1/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'evidence-key' },
        body: JSON.stringify({
          actor: TEST_DID,
          action: 'scoped-write',
          payload: {},
        }),
      })
      expect(accepted.status).toBe(201)

      const rootAccepted = await app.request('/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'evidence-key' },
        body: JSON.stringify({
          type: 'capability.invoked',
          actor: TEST_DID,
          input: { redacted: true },
        }),
      })
      expect(rootAccepted.status).toBe(201)

      const forbidden = await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'evidence-key' },
        body: JSON.stringify({ global: true }),
      })
      expect(forbidden.status).toBe(403)
      expect((await forbidden.json()).error).toContain('agentd:killswitch:write')
    })

    it('fails closed when scoped agentd API keys are malformed', async () => {
      delete process.env.SERVICE_API_KEY
      process.env.AGENTD_API_KEYS = '{bad-json'

      const res = await app.request('/v1/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'evidence-key' },
        body: JSON.stringify({
          actor: TEST_DID,
          action: 'test',
          payload: {},
        }),
      })

      expect(res.status).toBe(503)
      expect((await res.json()).error).toContain('AGENTD_API_KEYS must be a JSON array')
    })
  })

  describe('GET /health', () => {
    it('returns health status with checks for all upstream services', async () => {
      mockFetch.mockImplementation((url: string) => {
        if (url.includes('health')) {
          return createMockResponse({ status: 'healthy' })
        }
        return Promise.reject(new Error('unreachable'))
      })

      const res = await app.request('/health')
      const data = await res.json()

      expect(data.service).toBe('agentd')
      expect(data.timestamp).toBeDefined()
      expect(data.checks).toBeDefined()
      expect(data.checks.discovery).toBe('connected')
      expect(data.checks.trustGraph).toBe('connected')
      expect(data.checks.registry).toBe('connected')
      expect(data.checks.authorityStore).toBe('ready')
      expect(data.checks.localStateStore).toBe('ready')
      expect(data.authorityStore.kind).toBe('memory')
      expect(data.localStateStore.kind).toBe('memory')
      expect(data.status).toBe('healthy')
    })

    it('returns degraded when upstream services are unreachable', async () => {
      mockFetch.mockRejectedValue(new Error('connection refused'))

      const res = await app.request('/health')
      const data = await res.json()

      expect(data.status).toBe('degraded')
      expect(data.checks.discovery).toBe('unreachable')
      expect(data.checks.trustGraph).toBe('unreachable')
      expect(data.checks.registry).toBe('unreachable')
      expect(data.checks.authorityStore).toBe('ready')
      expect(data.checks.localStateStore).toBe('ready')
    })
  })

  describe('FIDES v2 local API aliases', () => {
    it('creates, lists, and shows local identities without returning private keys', async () => {
      const created = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Calendar Agent' }),
      })
      expect(created.status).toBe(201)
      const createdData = await created.json()
      expect(createdData.identity.did).toMatch(/^did:fides:/)
      expect(createdData.privateKeyHex).toBeUndefined()
      expect(createdData.identity.metadata.name).toBe('Calendar Agent')

      const listed = await app.request('/identities')
      expect(listed.status).toBe(200)
      const listedData = await listed.json()
      expect(listedData.identities).toEqual(expect.arrayContaining([
        expect.objectContaining({ did: createdData.identity.did, type: 'agent' }),
      ]))
      expect(JSON.stringify(listedData)).not.toContain('privateKeyHex')

      const shown = await app.request(`/identities/${encodeURIComponent(createdData.identity.did)}`)
      expect(shown.status).toBe(200)
      const shownData = await shown.json()
      expect(shownData.identity.did).toBe(createdData.identity.did)
      expect(shownData.privateKeyHex).toBeUndefined()
    })

    it('creates, signs, verifies, and reads local AgentCards', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Invoice Agent' }),
      })
      const { identity } = await identityResponse.json()
      const publisherResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'publisher', name: 'Invoice Publisher' }),
      })
      const { identity: publisher } = await publisherResponse.json()
      await app.request('/attestations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity: identity.did,
          type: 'github',
          handle: 'invoice-agent',
        }),
      })
      const runtimeAttestation = await app.request('/attestations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentId: identity.did,
          codeHash: `sha256:${'a'.repeat(64)}`,
          runtimeHash: `sha256:${'b'.repeat(64)}`,
          policyHash: `sha256:${'c'.repeat(64)}`,
        }),
      })
      const runtimeAttestationData = await runtimeAttestation.json()

      const created = await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          name: 'Invoice Agent',
          publisherId: publisher.did,
          capabilities: [{ id: 'invoice.reconcile', requiredScopes: ['invoice:read'] }],
          endpoints: [{
            url: 'https://invoice.example.test/invoke',
            protocol: 'https',
            capabilities: ['invoice.reconcile'],
            auth: 'delegation',
          }],
          runtimeAttestationIds: [runtimeAttestationData.attestation.attestation_id],
          revocationUrl: 'https://invoice.example.test/revocations',
        }),
      })
      expect(created.status).toBe(201)
      const createdData = await created.json()
      expect(createdData.card.id).toBe(identity.did)
      expect(createdData.card.capabilities[0].id).toBe('invoice.reconcile')
      expect(createdData.card.publisher.did).toBe(publisher.did)
      expect(createdData.card.publicKeys[0]).toEqual(expect.objectContaining({
        id: `${identity.did}#ed25519`,
        type: 'Ed25519',
      }))
      expect(createdData.card.transports[0]).toMatchObject({
        protocol: 'https',
        url: 'https://invoice.example.test/invoke',
        auth: 'delegation',
      })
      expect(createdData.card.trustAnchors).toEqual(expect.arrayContaining([
        expect.objectContaining({ type: 'github', value: 'invoice-agent', verified: true }),
      ]))
      expect(createdData.card.runtimeAttestations[0].attestation_id).toBe(runtimeAttestationData.attestation.attestation_id)
      expect(createdData.card.revocationUrl).toBe('https://invoice.example.test/revocations')
      expect(createdData.validation.valid).toBe(true)

      const signed = await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      expect(signed.status).toBe(200)
      const signedData = await signed.json()
      expect(signedData.signed.proof.type).toBe('Ed25519Signature2024')
      expect(signedData.signed.payload.publicKeys[0].id).toBe(`${identity.did}#ed25519`)
      expect(signedData.signed.payload.publisher.did).toBe(publisher.did)

      const verified = await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/verify`, { method: 'POST' })
      expect(verified.status).toBe(200)
      const verifiedData = await verified.json()
      expect(verifiedData.valid).toBe(true)
      expect(verifiedData.canonicalValid).toBe(true)
      expect(verifiedData.identityBound).toBe(true)

      const fetched = await app.request(`/agent-cards/${encodeURIComponent(identity.did)}`)
      expect(fetched.status).toBe(200)
      expect((await fetched.json()).card.id).toBe(identity.did)
    })

    it('registers local agents and discovers candidates by capability without granting authority', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Invoice Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{ id: 'invoice.reconcile', requiredScopes: ['invoice:read'] }],
          endpoints: [],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })

      const registered = await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })
      expect(registered.status).toBe(201)
      const registeredData = await registered.json()
      expect(registeredData).toMatchObject({
        authority: 'candidate_only',
        verified: true,
        authorityGranted: false,
      })
      expect(registeredData.reasons).toEqual(expect.arrayContaining([
        'identity_bound_signed_agent_card_verified',
        'local_registration_candidate_only',
        'discovery_does_not_grant_authority',
      ]))

      const listed = await app.request('/agents')
      expect(listed.status).toBe(200)
      expect((await listed.json()).agents).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agentId: identity.did,
          authority: 'candidate_only',
          verified: true,
          authorityGranted: false,
          reasons: expect.arrayContaining([
            'identity_bound_signed_agent_card_verified',
            'discovery_does_not_grant_authority',
          ]),
        }),
      ]))

      const detail = await app.request(`/agents/${encodeURIComponent(identity.did)}`)
      expect(detail.status).toBe(200)
      expect(await detail.json()).toMatchObject({
        agentId: identity.did,
        authority: 'candidate_only',
        verified: true,
        authorityGranted: false,
        reasons: expect.arrayContaining([
          'local_registration_candidate_only',
          'discovery_does_not_grant_authority',
        ]),
      })

      const discovered = await app.request('/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capability: 'invoice.reconcile' }),
      })
      expect(discovered.status).toBe(200)
      const discoveredData = await discovered.json()
      expect(discoveredData.authorityGranted).toBe(false)
      expect(discoveredData.evidenceRefs).toEqual([expect.any(String)])
      expect(discoveredData.evidence_refs).toEqual(discoveredData.evidenceRefs)
      expect(discoveredData.candidates).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agentId: identity.did,
          capability: 'invoice.reconcile',
          signed: true,
          versionNegotiation: expect.objectContaining({
            compatible: true,
            negotiated_version: 'fides.v2.0',
          }),
          resolution: expect.objectContaining({
            mode: 'local_agent_card',
            urlRequired: false,
            authorityGranted: false,
          }),
        }),
      ]))
      expect(discoveredData.candidates[0].reasons).toContain('url_not_required_for_local_discovery')
      expect(discoveredData.candidates[0].reasons).toContain('protocol_version_compatible')

      const evidence = await app.request('/evidence')
      expect(evidence.status).toBe(200)
      const evidenceData = await evidence.json()
      expect(evidenceData.events).toEqual(expect.arrayContaining([
        expect.objectContaining({
          event_id: discoveredData.evidenceRefs[0],
          type: 'discovery.performed',
          actor: 'did:fides:agentd:local-daemon',
          subject: 'fides.discovery.local',
          capability: 'invoice.reconcile',
          decision: 'candidate_only',
          privacy_mode: 'hash_only',
          metadata: expect.objectContaining({
            provider: 'local',
            candidates: 1,
            authorityGranted: false,
          }),
        }),
      ]))

      const localDiscovered = await app.request('/discover/local', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capability: 'invoice.reconcile' }),
      })
      expect(localDiscovered.status).toBe(200)
      expect(await localDiscovered.json()).toMatchObject({
        provider: 'local',
        authorityGranted: false,
        count: 1,
        evidenceRefs: [expect.any(String)],
      })

      const wellKnownDiscovered = await app.request('/discover/well-known', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capability: 'invoice.reconcile' }),
      })
      expect(wellKnownDiscovered.status).toBe(200)
      expect(await wellKnownDiscovered.json()).toMatchObject({
        provider: 'well-known',
        authorityGranted: false,
        count: 1,
        evidenceRefs: [expect.any(String)],
      })
    })

    it('rejects local agent registration before identity-bound AgentCard signing', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Unsigned Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{ id: 'invoice.reconcile' }],
          endpoints: [],
        }),
      })

      const registered = await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      expect(registered.status).toBe(400)
      expect(await registered.json()).toMatchObject({
        authorityGranted: false,
        error: {
          code: 'AGENT_CARD_INVALID_SIGNATURE',
          category: 'agent_card',
          message: 'Identity-bound signed AgentCard is required before registration',
          details: { cardId: identity.did },
        },
      })
    })

    it('filters discovery candidates with incompatible protocol versions', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Legacy Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{ id: 'legacy.reconcile', requiredScopes: ['invoice:read'] }],
          endpoints: [],
          protocolVersions: ['fides.v1'],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const discovered = await app.request('/discover/local', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          capability: 'legacy.reconcile',
          supported_versions: ['fides.v2.0'],
          required_versions: ['fides.v2.0'],
        }),
      })

      expect(discovered.status).toBe(200)
      const data = await discovered.json()
      expect(data.count).toBe(0)
      expect(data.candidates).toEqual([])
      expect(data.rejectedCandidates).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agentId: identity.did,
          versionNegotiation: expect.objectContaining({
            compatible: false,
            errors: expect.arrayContaining([
              expect.objectContaining({ code: 'VERSION_INCOMPATIBLE' }),
            ]),
          }),
          reasons: expect.arrayContaining(['protocol_version_incompatible']),
        }),
      ]))
      expect(data.authorityGranted).toBe(false)
    })

    it('filters registry relay and dht discovery records with incompatible protocol versions', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Legacy Provider Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{ id: 'legacy.provider', requiredScopes: ['legacy:read'] }],
          endpoints: [],
          protocolVersions: ['fides.v1'],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })
      await app.request('/registry/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })
      await app.request('/relay/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId: identity.did }),
      })
      await app.request('/dht/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          capability: 'legacy.provider',
          agentId: identity.did,
          agentCardUrl: 'local://legacy-provider-card',
        }),
      })

      for (const path of ['/registry/search', '/discover/registry', '/discover/federation', '/relay/discover', '/discover/relay']) {
        const response = await app.request(path, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            capability: 'legacy.provider',
            supported_versions: ['fides.v2.0'],
            required_versions: ['fides.v2.0'],
          }),
        })
        expect(response.status).toBe(200)
        const data = await response.json()
        expect(data.records).toEqual([])
        expect(data.rejectedRecords).toEqual(expect.arrayContaining([
          expect.objectContaining({
            agentId: identity.did,
            versionNegotiation: expect.objectContaining({
              compatible: false,
              errors: expect.arrayContaining([
                expect.objectContaining({ code: 'VERSION_INCOMPATIBLE' }),
              ]),
            }),
          }),
        ]))
        expect(data.authorityGranted).toBe(false)
        if (path.startsWith('/discover/')) {
          expect(data.evidenceRefs).toEqual([expect.any(String)])
          expect(data.evidence_refs).toEqual(data.evidenceRefs)
        }
      }

      const dht = await app.request('/discover/dht', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          capability: 'legacy.provider',
          supported_versions: ['fides.v2.0'],
          required_versions: ['fides.v2.0'],
        }),
      })
      expect(dht.status).toBe(200)
      const dhtData = await dht.json()
      expect(dhtData.pointers).toEqual([])
      expect(dhtData.rejectedPointers).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agentId: identity.did,
          versionNegotiation: expect.objectContaining({
            compatible: false,
            errors: expect.arrayContaining([
              expect.objectContaining({ code: 'VERSION_INCOMPATIBLE' }),
            ]),
          }),
        }),
      ]))
      expect(dhtData.authorityGranted).toBe(false)
      expect(dhtData.evidenceRefs).toEqual([expect.any(String)])
      expect(dhtData.evidence_refs).toEqual(dhtData.evidenceRefs)
    })

    it('returns federated registry candidates without granting authority', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Federated Invoice Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{ id: 'invoice.federated_reconcile', requiredScopes: ['invoice:read'] }],
          endpoints: [],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })
      await app.request('/registry/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const response = await app.request('/discover/federation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capability: 'invoice.federated_reconcile' }),
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data).toMatchObject({
        provider: 'federation',
        mode: 'local_mock_federation',
        authorityGranted: false,
        evidenceRefs: [expect.any(String)],
        federationPeerVerified: true,
      })
      expect(data.evidence_refs).toEqual(data.evidenceRefs)
      expect(data.records).toEqual(expect.arrayContaining([
        expect.objectContaining({
          provider: 'federation',
          agentId: identity.did,
          federationPeerVerified: true,
          authorityGranted: false,
          reasons: expect.arrayContaining([
            'federation_peer_matched_capability',
            'federation_does_not_grant_authority',
          ]),
        }),
      ]))
    })

    it('evaluates root trust, reputation, and policy for a registered local candidate', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Calendar Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{
            id: 'calendar.schedule',
            riskLevel: 'low',
            requiredScopes: ['calendar:write'],
          }],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const trust = await app.request('/trust/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId: identity.did, capability: 'calendar.schedule' }),
      })
      expect(trust.status).toBe(200)
      const trustData = await trust.json()
      expect(trustData.trust.agent_id).toBe(identity.did)
      expect(trustData.trust.capability).toBe('calendar.schedule')
      expect(trustData.authorityGranted).toBe(false)

      const reputation = await app.request('/reputation/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentId: identity.did,
          capability: 'calendar.schedule',
          successfulInvocations: 3,
          failedInvocations: 1,
        }),
      })
      expect(reputation.status).toBe(200)
      expect((await reputation.json()).reputation.capability).toBe('calendar.schedule')

      const reputationRecord = await app.request(`/reputation/${encodeURIComponent(identity.did)}`)
      expect(reputationRecord.status).toBe(200)
      expect((await reputationRecord.json()).reputations).toEqual(expect.arrayContaining([
        expect.objectContaining({ capability: 'calendar.schedule' }),
      ]))

      const policy = await app.request('/policy/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: 'did:fides:requester',
          agentId: identity.did,
          capability: 'calendar.schedule',
          requestedScopes: ['calendar:write'],
        }),
      })
      expect(policy.status).toBe(200)
      const policyData = await policy.json()
      expect(policyData.policy.decision).toBe('allow')
      expect(policyData.authorityGranted).toBe(false)
      expect(policyData.requiresSessionGrant).toBe(true)
    })

    it('creates signed local delegation tokens without granting invocation authority', async () => {
      const principalResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'principal', name: 'Local Principal' }),
      })
      const { identity: principal } = await principalResponse.json()

      const delegation = await app.request('/delegations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          delegator: principal.did,
          delegatee: 'did:fides:requester:local',
          capabilities: ['invoice.reconcile'],
          constraints: { maxActions: 1 },
          audience: ['did:fides:invoice-agent'],
        }),
      })
      expect(delegation.status).toBe(201)
      const data = await delegation.json()
      expect(data.authorityGranted).toBe(false)
      expect(data.signed).toBe(true)
      expect(data.token).toMatchObject({
        delegator: principal.did,
        delegatee: 'did:fides:requester:local',
        capabilities: ['invoice.reconcile'],
        audience: ['did:fides:invoice-agent'],
      })
      expect(data.token.signature).toMatch(/^[0-9a-f]{128}$/)

      const externalDelegation = await app.request('/delegations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          delegator: 'did:fides:external-principal',
          delegatee: 'did:fides:requester:local',
          capabilities: ['invoice.reconcile'],
        }),
      })
      expect(externalDelegation.status).toBe(201)
      const externalData = await externalDelegation.json()
      expect(externalData.signed).toBe(false)
      expect(externalData.token.signature).toBe('')

      const invalid = await app.request('/delegations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ delegator: 'did:fides:principal:local' }),
      })
      expect(invalid.status).toBe(400)
    })

    it('issues root scoped sessions and invokes capabilities through policy preflight', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Invoice Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{
            id: 'invoice.reconcile',
            riskLevel: 'medium',
            requiredScopes: ['invoice:read'],
          }],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const session = await app.request('/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: 'did:fides:requester',
          agentId: identity.did,
          capability: 'invoice.reconcile',
          requestedScopes: ['invoice:read'],
        }),
      })
      expect(session.status).toBe(201)
      const sessionData = await session.json()
      expect(sessionData.authorityGranted).toBe(true)
      expect(sessionData.authorityMode).toBe('full')
      expect(sessionData.allowedActions).toEqual(['execute', 'dry_run'])
      expect(sessionData.session.capability).toBe('invoice.reconcile')
      expect(sessionData.session.supported_versions).toEqual(expect.arrayContaining(['fides.v2.0']))
      expect(sessionData.session.negotiated_version).toBe('fides.v2.0')
      expect(sessionData.versionNegotiation).toMatchObject({
        compatible: true,
        negotiated_version: 'fides.v2.0',
      })
      expect(sessionData.signedSession.payload).toEqual(sessionData.session)
      expect(sessionData.signedSession.proof.proofPurpose).toBe('delegation')
      expect(sessionData.signedSession.proof.verificationMethod).toBe(sessionData.session.issuer)
      expect(sessionData.signedSessionVerified).toBe(true)

      const fetched = await app.request(`/sessions/${sessionData.session.session_id}`)
      expect(fetched.status).toBe(200)
      const fetchedData = await fetched.json()
      expect(fetchedData.session.session_id).toBe(sessionData.session.session_id)
      expect(fetchedData.signedSessionVerified).toBe(true)

      const verified = await app.request(`/sessions/${sessionData.session.session_id}/verify`, { method: 'POST' })
      expect(verified.status).toBe(200)
      expect(await verified.json()).toMatchObject({
        valid: true,
        signatureValid: true,
        notExpired: true,
      })

      const invocation = await app.request('/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: sessionData.session.session_id,
          input: { invoiceId: 'inv_123' },
        }),
      })
      expect(invocation.status).toBe(200)
      const invocationData = await invocation.json()
      expect(invocationData.preflight.can_execute).toBe(true)
      expect(invocationData.result.status).toBe('completed')
      expect(invocationData.authorityGranted).toBe(true)
      expect(invocationData.signedSessionVerified).toBe(true)
      expect(invocationData.signedSession.payload.session_id).toBe(sessionData.session.session_id)
      expect(invocationData.result.evidence_refs).toHaveLength(2)
      expect(invocationData.signedResult.payload).toEqual(invocationData.result)
      expect(invocationData.signedResult.proof.proofPurpose).toBe('capabilityInvocation')
      expect(invocationData.signedResult.proof.verificationMethod).toBe(identity.did)
      expect(invocationData.signedResultVerified).toBe(true)

      const evidence = await app.request('/evidence')
      expect(evidence.status).toBe(200)
      const evidenceData = await evidence.json()
      expect(evidenceData.valid).toBe(true)
      expect(evidenceData.events).toEqual(expect.arrayContaining([
        expect.objectContaining({
          event_id: invocationData.result.evidence_refs[0],
          type: 'capability.invoked',
          input_hash: expect.stringMatching(/^sha256:/),
        }),
        expect.objectContaining({
          event_id: invocationData.result.evidence_refs[1],
          type: 'capability.completed',
          output_hash: expect.stringMatching(/^sha256:/),
        }),
      ]))
    })

    it('refuses to issue SessionGrants for incompatible protocol versions', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Legacy Session Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{
            id: 'legacy.session',
            riskLevel: 'low',
            requiredScopes: ['legacy:read'],
          }],
          protocolVersions: ['fides.v1'],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const session = await app.request('/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: 'did:fides:requester',
          agentId: identity.did,
          capability: 'legacy.session',
          requestedScopes: ['legacy:read'],
          supported_versions: ['fides.v2.0'],
          required_versions: ['fides.v2.0'],
        }),
      })

      expect(session.status).toBe(409)
      const data = await session.json()
      expect(data.authorityGranted).toBe(false)
      expect(data.error.code).toBe('VERSION_INCOMPATIBLE')
      expect(data.versionNegotiation).toMatchObject({
        compatible: false,
        peer_supported_versions: ['fides.v1'],
      })
    })

    it('verifies caller-supplied signed invocation requests before execution', async () => {
      const requester = await createIdentityKeyPair()
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Signed Invoice Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{
            id: 'invoice.signed_reconcile',
            riskLevel: 'medium',
            requiredScopes: ['invoice:read'],
          }],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const session = await app.request('/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: requester.did,
          agentId: identity.did,
          capability: 'invoice.signed_reconcile',
          requestedScopes: ['invoice:read'],
        }),
      })
      expect(session.status).toBe(201)
      const sessionData = await session.json()
      const input = { invoiceId: 'inv_signed' }
      const request = createInvocationRequest({
        issuer: requester.did,
        sessionGrant: sessionData.session,
        input,
      })
      const signedRequest = await signInvocationRequest(request, requester.privateKey, requester.did)

      const accepted = await app.request('/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: sessionData.session.session_id,
          input,
          signedRequest,
        }),
      })
      expect(accepted.status).toBe(200)
      const acceptedData = await accepted.json()
      expect(acceptedData.signedRequestVerified).toBe(true)
      expect(acceptedData.request).toEqual(request)
      expect(acceptedData.signedResultVerified).toBe(true)

      const rejected = await app.request('/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: sessionData.session.session_id,
          input: { invoiceId: 'inv_tampered' },
          signedRequest,
        }),
      })
      expect(rejected.status).toBe(401)
      await expect(rejected.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'IDENTITY_INVALID_SIGNATURE',
          category: 'identity',
        },
      })
    })

    it('rejects signed invocation requests that exceed SessionGrant scopes', async () => {
      const requester = await createIdentityKeyPair()
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Scoped Invoice Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{
            id: 'invoice.scoped_reconcile',
            riskLevel: 'medium',
            requiredScopes: ['invoice:read'],
          }],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const session = await app.request('/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: requester.did,
          agentId: identity.did,
          capability: 'invoice.scoped_reconcile',
          requestedScopes: ['invoice:read'],
        }),
      })
      expect(session.status).toBe(201)
      const sessionData = await session.json()
      const input = { invoiceId: 'inv_scoped' }
      const request = createInvocationRequest({
        issuer: requester.did,
        sessionGrant: sessionData.session,
        input,
      })
      const elevatedPayload = {
        ...request,
        scopes: ['invoice:read', 'payments:execute'],
      }
      const { payload_hash: _oldPayloadHash, ...payloadForHash } = elevatedPayload
      const signedRequest = await signInvocationRequest({
        ...elevatedPayload,
        payload_hash: hashProtocolPayload(payloadForHash),
      }, requester.privateKey, requester.did)

      const rejected = await app.request('/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: sessionData.session.session_id,
          input,
          signedRequest,
        }),
      })
      expect(rejected.status).toBe(401)
      const rejectedData = await rejected.json()
      expect(rejectedData.authorityGranted).toBe(false)
      expect(rejectedData.error.code).toBe('IDENTITY_INVALID_SIGNATURE')
      expect(rejectedData.error.details.grantValidation.errors).toContain(
        'InvocationRequest.scope payments:execute is not granted by SessionGrant',
      )
    })

    it('rejects signed invocation requests whose proof is not bound to the issuer', async () => {
      const requester = await createIdentityKeyPair()
      const attacker = await createIdentityKeyPair()
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Issuer Bound Invoice Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{
            id: 'invoice.issuer_bound_reconcile',
            riskLevel: 'medium',
            requiredScopes: ['invoice:read'],
          }],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const session = await app.request('/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: requester.did,
          agentId: identity.did,
          capability: 'invoice.issuer_bound_reconcile',
          requestedScopes: ['invoice:read'],
        }),
      })
      expect(session.status).toBe(201)
      const sessionData = await session.json()
      const input = { invoiceId: 'inv_issuer_bound' }
      const request = createInvocationRequest({
        issuer: requester.did,
        sessionGrant: sessionData.session,
        input,
      })
      const signedRequest = await signInvocationRequest(request, attacker.privateKey, attacker.did)

      const rejected = await app.request('/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: sessionData.session.session_id,
          input,
          signedRequest,
        }),
      })
      expect(rejected.status).toBe(401)
      const rejectedData = await rejected.json()
      expect(rejectedData.authorityGranted).toBe(false)
      expect(rejectedData.error.code).toBe('IDENTITY_INVALID_SIGNATURE')
      expect(rejectedData.error.details.signedRequestVerified).toBe(false)
      expect(rejectedData.error.details.grantValidation.valid).toBe(true)
    })

    it('rejects invocation inputs and outputs that do not satisfy capability schemas', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Schema Invoice Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{
            id: 'invoice.schema_reconcile',
            riskLevel: 'medium',
            requiredScopes: ['invoice:read'],
            inputSchema: {
              type: 'object',
              required: ['invoiceId'],
              properties: { invoiceId: { type: 'string' } },
              additionalProperties: false,
            },
            outputSchema: {
              type: 'object',
              required: ['resultId'],
              properties: { resultId: { type: 'string' } },
              additionalProperties: false,
            },
          }],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const session = await app.request('/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: 'did:fides:requester',
          agentId: identity.did,
          capability: 'invoice.schema_reconcile',
          requestedScopes: ['invoice:read'],
        }),
      })
      expect(session.status).toBe(201)
      const sessionData = await session.json()

      const invalidInput = await app.request('/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: sessionData.session.session_id,
          input: { invoiceId: 123, unexpected: true },
        }),
      })
      expect(invalidInput.status).toBe(400)
      await expect(invalidInput.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'CAPABILITY_SCHEMA_INVALID',
          details: {
            errors: expect.arrayContaining([
              '$.invoiceId must be string',
              '$.unexpected is not allowed',
            ]),
          },
        },
      })

      const invalidOutput = await app.request('/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: sessionData.session.session_id,
          input: { invoiceId: 'inv_123' },
        }),
      })
      expect(invalidOutput.status).toBe(422)
      const invalidOutputData = await invalidOutput.json()
      expect(invalidOutputData.authorityGranted).toBe(false)
      expect(invalidOutputData.error.code).toBe('CAPABILITY_SCHEMA_INVALID')
      expect(invalidOutputData.result.status).toBe('failed')
      expect(invalidOutputData.signedResultVerified).toBe(true)
    })

    it('returns typed error envelopes for root session and invocation failures', async () => {
      const missingCapability = await app.request('/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentId: 'did:fides:agent:missing',
          capability: 'invoice.reconcile',
        }),
      })
      expect(missingCapability.status).toBe(404)
      await expect(missingCapability.json()).resolves.toMatchObject({
        error: {
          code: 'CAPABILITY_NOT_FOUND',
          category: 'capability',
          retryable: false,
        },
      })

      const missingSession = await app.request('/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: 'sess_missing' }),
      })
      expect(missingSession.status).toBe(404)
      await expect(missingSession.json()).resolves.toMatchObject({
        error: {
          code: 'SESSION_NOT_FOUND',
          category: 'session',
          retryable: false,
        },
        sessionId: 'sess_missing',
      })

      const invalidIdentity = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'service' }),
      })
      expect(invalidIdentity.status).toBe(400)
      await expect(invalidIdentity.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'REQUEST_INVALID',
          category: 'request',
          details: { field: 'type' },
        },
      })

      const missingIdentity = await app.request('/identities/did:fides:missing')
      expect(missingIdentity.status).toBe(404)
      await expect(missingIdentity.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'IDENTITY_NOT_FOUND',
          category: 'identity',
          details: { id: 'did:fides:missing' },
        },
      })

      const invalidAgentCard = await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      expect(invalidAgentCard.status).toBe(400)
      await expect(invalidAgentCard.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'REQUEST_INVALID',
          category: 'request',
          details: { fields: ['identity.did', 'agentId'] },
        },
      })

      const missingAgentCard = await app.request('/agent-cards/card_missing')
      expect(missingAgentCard.status).toBe(404)
      await expect(missingAgentCard.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'AGENT_CARD_NOT_FOUND',
          category: 'agent_card',
          details: { id: 'card_missing' },
        },
      })

      const missingAgent = await app.request('/agents/did:fides:agent:missing')
      expect(missingAgent.status).toBe(404)
      await expect(missingAgent.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'AGENT_NOT_REGISTERED',
          category: 'discovery',
        },
      })

      const invalidDiscovery = await app.request('/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      expect(invalidDiscovery.status).toBe(400)
      await expect(invalidDiscovery.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'REQUEST_INVALID',
          category: 'request',
          details: { field: 'capability' },
        },
      })

      const invalidTrust = await app.request('/trust/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId: 'did:fides:agent' }),
      })
      expect(invalidTrust.status).toBe(400)
      await expect(invalidTrust.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'REQUEST_INVALID',
          category: 'request',
        },
      })

      const invalidAttestation = await app.request('/attestations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      expect(invalidAttestation.status).toBe(400)
      await expect(invalidAttestation.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'REQUEST_INVALID',
          category: 'request',
          details: { field: 'agentId' },
        },
      })

      const missingAttestation = await app.request('/attestations/att_missing')
      expect(missingAttestation.status).toBe(404)
      await expect(missingAttestation.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'ATTESTATION_NOT_FOUND',
          category: 'attestation',
          details: { id: 'att_missing' },
        },
      })

      const invalidRegistryPublish = await app.request('/registry/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      expect(invalidRegistryPublish.status).toBe(400)
      await expect(invalidRegistryPublish.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'REQUEST_INVALID',
          category: 'request',
          details: { field: 'agentCardId' },
        },
      })

      const invalidRelayRegister = await app.request('/relay/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      expect(invalidRelayRegister.status).toBe(400)
      await expect(invalidRelayRegister.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'REQUEST_INVALID',
          category: 'request',
          details: { field: 'agentId' },
        },
      })

      const missingApprovalCapability = await app.request('/approvals', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      expect(missingApprovalCapability.status).toBe(400)
      await expect(missingApprovalCapability.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'REQUEST_INVALID',
          category: 'request',
          retryable: false,
          details: { field: 'capability' },
        },
      })

      const missingApproval = await app.request('/approvals/app_missing/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      expect(missingApproval.status).toBe(404)
      await expect(missingApproval.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'APPROVAL_NOT_FOUND',
          category: 'approval',
          retryable: false,
          details: { id: 'app_missing' },
        },
      })

      const invalidKillSwitch = await app.request('/killswitch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetType: 'service', target: 'did:fides:agent:test' }),
      })
      expect(invalidKillSwitch.status).toBe(400)
      await expect(invalidKillSwitch.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'REQUEST_INVALID',
          category: 'request',
          details: { field: 'targetType' },
        },
      })

      const missingKillSwitch = await app.request('/killswitch/rule_missing', {
        method: 'DELETE',
      })
      expect(missingKillSwitch.status).toBe(404)
      await expect(missingKillSwitch.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'KILL_SWITCH_RULE_NOT_FOUND',
          category: 'kill_switch',
          details: { id: 'rule_missing' },
        },
      })

      const invalidRevocation = await app.request('/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetType: 'unknown', targetId: 'did:fides:agent:test' }),
      })
      expect(invalidRevocation.status).toBe(400)
      await expect(invalidRevocation.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'REQUEST_INVALID',
          category: 'request',
          details: { field: 'targetType' },
        },
      })

      const missingRevocation = await app.request('/revocations/rev_missing')
      expect(missingRevocation.status).toBe(404)
      await expect(missingRevocation.json()).resolves.toMatchObject({
        authorityGranted: false,
        revoked: false,
        error: {
          code: 'REVOCATION_NOT_FOUND',
          category: 'revocation',
          details: { id: 'rev_missing' },
        },
      })

      const invalidIncident = await app.request('/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ severity: 'urgent' }),
      })
      expect(invalidIncident.status).toBe(400)
      await expect(invalidIncident.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'INCIDENT_INVALID',
          category: 'incident',
          details: { field: 'severity' },
        },
      })

      const missingIncident = await app.request('/incidents/inc_missing/resolve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      expect(missingIncident.status).toBe(404)
      await expect(missingIncident.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'INCIDENT_NOT_FOUND',
          category: 'incident',
          details: { id: 'inc_missing' },
        },
      })

      const invalidEvidenceAppend = await app.request('/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'policy.evaluated' }),
      })
      expect(invalidEvidenceAppend.status).toBe(400)
      await expect(invalidEvidenceAppend.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'REQUEST_INVALID',
          category: 'request',
        },
      })

      const invalidEvidenceExport = await app.request('/evidence/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ privacy_mode: 'raw' }),
      })
      expect(invalidEvidenceExport.status).toBe(400)
      await expect(invalidEvidenceExport.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'EVIDENCE_PRIVACY_MODE_INVALID',
          category: 'evidence',
          details: { field: 'privacy_mode' },
        },
      })

      const missingEvidence = await app.request('/evidence/evt_missing')
      expect(missingEvidence.status).toBe(404)
      await expect(missingEvidence.json()).resolves.toMatchObject({
        authorityGranted: false,
        error: {
          code: 'EVIDENCE_EVENT_NOT_FOUND',
          category: 'evidence',
          details: { eventId: 'evt_missing' },
        },
      })
    })

    it('serves root approval request and decision lifecycle', async () => {
      const request = await app.request('/approvals', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: 'did:fides:requester',
          agentId: 'did:fides:agent',
          capability: 'payments.prepare',
          requestedScopes: ['payments:prepare'],
          riskLevel: 'high',
        }),
      })
      expect(request.status).toBe(201)
      const requestData = await request.json()
      expect(requestData.approval.status).toBe('pending')
      expect(requestData.authorityGranted).toBe(false)
      expect(requestData.evidenceRefs).toHaveLength(1)

      const listed = await app.request('/approvals')
      expect(listed.status).toBe(200)
      expect((await listed.json()).approvals).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: requestData.approval.id, status: 'pending' }),
      ]))

      const approved = await app.request(`/approvals/${requestData.approval.id}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approverId: 'did:fides:approver', reason: 'Manual approval for dry-run payment preparation.' }),
      })
      expect(approved.status).toBe(200)
      const approvedData = await approved.json()
      expect(approvedData.approval.status).toBe('approved')
      expect(approvedData.decision.decision).toBe('approved')
      expect(approvedData.authorityGranted).toBe(false)
      expect(approvedData.evidenceRefs).toHaveLength(1)

      const denyRequest = await app.request('/approvals', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: 'did:fides:requester',
          agentId: 'did:fides:agent',
          capability: 'deploy.production',
          riskLevel: 'critical',
        }),
      })
      const denyRequestData = await denyRequest.json()
      const denied = await app.request(`/approvals/${denyRequestData.approval.id}/deny`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approverId: 'did:fides:approver', reason: 'No production deploy window.' }),
      })
      expect(denied.status).toBe(200)
      const deniedData = await denied.json()
      expect(deniedData.approval.status).toBe('denied')
      expect(deniedData.decision.decision).toBe('denied')
      expect(deniedData.evidenceRefs).toHaveLength(1)

      const evidence = await app.request('/evidence')
      const evidenceData = await evidence.json()
      expect(evidenceData.events).toEqual(expect.arrayContaining([
        expect.objectContaining({
          event_id: requestData.evidenceRefs[0],
          type: 'approval.requested',
          subject: 'did:fides:agent',
          capability: 'payments.prepare',
          privacy_mode: 'hash_only',
        }),
        expect.objectContaining({
          event_id: approvedData.evidenceRefs[0],
          type: 'approval.granted',
          actor: 'did:fides:approver',
          decision: 'approved',
          privacy_mode: 'hash_only',
        }),
        expect.objectContaining({
          event_id: deniedData.evidenceRefs[0],
          type: 'approval.denied',
          actor: 'did:fides:approver',
          decision: 'denied',
          privacy_mode: 'hash_only',
        }),
      ]))
    })

    it('serves root kill switch rules and blocks scoped session issuance', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Deploy Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{ id: 'deploy.preview', riskLevel: 'medium', requiredScopes: ['deploy:preview'] }],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const enabled = await app.request('/killswitch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          issuer: 'did:fides:operator',
          targetType: 'capability',
          target: 'deploy.preview',
          reason: 'Pause preview deploys during incident response.',
        }),
      })
      expect(enabled.status).toBe(201)
      const enabledData = await enabled.json()
      expect(enabledData.rule.enabled).toBe(true)
      expect(enabledData.evidenceRefs).toHaveLength(1)

      const blocked = await app.request('/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: 'did:fides:requester',
          agentId: identity.did,
          capability: 'deploy.preview',
          requestedScopes: ['deploy:preview'],
        }),
      })
      expect(blocked.status).toBe(409)
      const blockedData = await blocked.json()
      expect(blockedData.policy.reason_codes).toContain('KILL_SWITCH_ACTIVE')
      expect(blockedData.error.code).toBe('KILL_SWITCH_ACTIVE')
      expect(blockedData.authorityGranted).toBe(false)

      const disabled = await app.request(`/killswitch/${enabledData.rule.id}`, { method: 'DELETE' })
      expect(disabled.status).toBe(200)
      expect((await disabled.json()).rule.enabled).toBe(false)

      const evidence = await app.request('/evidence')
      const evidenceData = await evidence.json()
      expect(evidenceData.events).toEqual(expect.arrayContaining([
        expect.objectContaining({
          event_id: enabledData.evidenceRefs[0],
          type: 'kill_switch.triggered',
          actor: 'did:fides:operator',
          subject: 'deploy.preview',
          privacy_mode: 'hash_only',
        }),
      ]))
    })

    it('serves root revocation records and blocks scoped session issuance', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Revoked File Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{ id: 'file.delete', riskLevel: 'high', requiredScopes: ['file:delete'] }],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const revocation = await app.request('/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          issuer: 'did:fides:operator',
          targetType: 'agent',
          targetId: identity.did,
          reason: 'Compromised deployment key.',
        }),
      })
      expect(revocation.status).toBe(201)
      const revocationData = await revocation.json()
      expect(revocationData.record.status).toBe('active')
      expect(revocationData.evidenceRefs).toHaveLength(1)

      const listed = await app.request('/revocations')
      expect(listed.status).toBe(200)
      expect((await listed.json()).records).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: revocationData.record.id, target_id: identity.did }),
      ]))

      const shown = await app.request(`/revocations/${revocationData.record.id}`)
      expect(shown.status).toBe(200)
      expect((await shown.json()).record.target_id).toBe(identity.did)

      const blocked = await app.request('/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: 'did:fides:requester',
          agentId: identity.did,
          capability: 'file.delete',
          requestedScopes: ['file:delete'],
          approvalGranted: true,
          runtimeAttestationValid: true,
        }),
      })
      expect(blocked.status).toBe(409)
      const blockedData = await blocked.json()
      expect(blockedData.policy.reason_codes).toContain('REVOCATION_ACTIVE')
      expect(blockedData.error.code).toBe('REVOCATION_ACTIVE')

      const evidence = await app.request('/evidence')
      const evidenceData = await evidence.json()
      expect(evidenceData.events).toEqual(expect.arrayContaining([
        expect.objectContaining({
          event_id: revocationData.evidenceRefs[0],
          type: 'revocation.recorded',
          actor: 'did:fides:operator',
          subject: identity.did,
          privacy_mode: 'hash_only',
        }),
      ]))
    })

    it('serves root incident records and blocks scoped session issuance until resolved', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Incident Code Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{ id: 'code.merge', riskLevel: 'critical', requiredScopes: ['code:merge'] }],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const incident = await app.request('/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reporter: 'did:fides:principal',
          targetAgentId: identity.did,
          severity: 'critical',
          category: 'unauthorized_action',
          description: 'Attempted to merge without delegated authority.',
          evidenceRefs: ['evidence:merge-attempt'],
        }),
      })
      expect(incident.status).toBe(201)
      const incidentData = await incident.json()
      expect(incidentData.record.resolution_status).toBe('open')
      expect(incidentData.evidenceRefs).toHaveLength(1)

      const listed = await app.request('/incidents')
      expect(listed.status).toBe(200)
      expect((await listed.json()).records).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: incidentData.record.id, target_agent_id: identity.did }),
      ]))

      const blocked = await app.request('/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: 'did:fides:requester',
          agentId: identity.did,
          capability: 'code.merge',
          requestedScopes: ['code:merge'],
          approvalGranted: true,
          runtimeAttestationValid: true,
        }),
      })
      expect(blocked.status).toBe(409)
      const blockedData = await blocked.json()
      expect(blockedData.policy.reason_codes).toContain('INCIDENT_REQUIRES_REVIEW')
      expect(blockedData.error.code).toBe('POLICY_DENIED')

      const resolved = await app.request(`/incidents/${incidentData.record.id}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'resolved' }),
      })
      expect(resolved.status).toBe(200)
      expect((await resolved.json()).record.resolution_status).toBe('resolved')

      const evidence = await app.request('/evidence')
      const evidenceData = await evidence.json()
      expect(evidenceData.events).toEqual(expect.arrayContaining([
        expect.objectContaining({
          event_id: incidentData.evidenceRefs[0],
          type: 'incident.reported',
          actor: 'did:fides:principal',
          subject: identity.did,
          risk_level: 'critical',
          privacy_mode: 'hash_only',
        }),
      ]))
    })

    it('serves root runtime attestations and uses valid attestations for high-risk session issuance', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Attested Payment Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{ id: 'payments.prepare', riskLevel: 'high', requiredScopes: ['payments:prepare'] }],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const withoutAttestation = await app.request('/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: 'did:fides:requester',
          agentId: identity.did,
          capability: 'payments.prepare',
          requestedScopes: ['payments:prepare'],
        }),
      })
      expect(withoutAttestation.status).toBe(409)
      const withoutAttestationData = await withoutAttestation.json()
      expect(withoutAttestationData.policy.reason_codes).toContain('HIGH_RISK_REQUIRES_ATTESTATION_OR_APPROVAL')
      expect(withoutAttestationData.error.code).toBe('APPROVAL_REQUIRED')

      const attestation = await app.request('/attestations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentId: identity.did,
          codeHash: `sha256:${'a'.repeat(64)}`,
          runtimeHash: `sha256:${'b'.repeat(64)}`,
          policyHash: `sha256:${'c'.repeat(64)}`,
        }),
      })
      expect(attestation.status).toBe(201)
      const attestationData = await attestation.json()
      expect(attestationData.attestation.agent_id).toBe(identity.did)
      expect(attestationData.authorityGranted).toBe(false)
      expect(attestationData.evidenceRefs).toHaveLength(1)

      const shown = await app.request(`/attestations/${attestationData.attestation.attestation_id}`)
      expect(shown.status).toBe(200)
      expect((await shown.json()).attestation.provider).toBe('mock-tee')

      const verified = await app.request(`/attestations/${attestationData.attestation.attestation_id}/verify`, { method: 'POST' })
      expect(verified.status).toBe(200)
      const verifiedData = await verified.json()
      expect(verifiedData.valid).toBe(true)
      expect(verifiedData.authorityGranted).toBe(false)
      expect(verifiedData.evidenceRefs).toHaveLength(1)

      const session = await app.request('/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          principalId: 'did:fides:principal',
          requesterAgentId: 'did:fides:requester',
          agentId: identity.did,
          capability: 'payments.prepare',
          requestedScopes: ['payments:prepare'],
          attestationId: attestationData.attestation.attestation_id,
        }),
      })
      expect(session.status).toBe(201)
      expect((await session.json()).policy.reason_codes).toContain('POLICY_ALLOWED')

      const evidence = await app.request('/evidence')
      const evidenceData = await evidence.json()
      expect(evidenceData.events).toEqual(expect.arrayContaining([
        expect.objectContaining({
          event_id: attestationData.evidenceRefs[0],
          type: 'attestation.issued',
          subject: identity.did,
          privacy_mode: 'hash_only',
        }),
        expect.objectContaining({
          event_id: verifiedData.evidenceRefs[0],
          type: 'attestation.verified',
          subject: identity.did,
          privacy_mode: 'hash_only',
        }),
      ]))
    })

    it('adds local mock identity trust anchors without granting authority', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'publisher', name: 'Anchor Publisher' }),
      })
      const { identity } = await identityResponse.json()

      const attestation = await app.request('/attestations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity: identity.did,
          type: 'github',
          handle: 'fides-publisher',
        }),
      })

      expect(attestation.status).toBe(201)
      const data = await attestation.json()
      expect(data.authorityGranted).toBe(false)
      expect(data.attestation).toMatchObject({
        schema_version: 'fides.identity_attestation.v1',
        identity: identity.did,
        mode: 'local_mock',
        trust_anchor: {
          type: 'github',
          value: 'fides-publisher',
          verified: true,
        },
      })
      expect(data.identity.identity.trustAnchors).toEqual(expect.arrayContaining([
        expect.objectContaining({
          type: 'github',
          value: 'fides-publisher',
          verified: true,
        }),
      ]))

      const evidence = await app.request('/evidence')
      const evidenceData = await evidence.json()
      expect(evidenceData.events).toEqual(expect.arrayContaining([
        expect.objectContaining({
          event_id: data.evidenceRefs[0],
          type: 'attestation.issued',
          subject: identity.did,
          privacy_mode: 'hash_only',
        }),
      ]))
    })

    it('records failed attestation verification evidence for missing attestations', async () => {
      const verified = await app.request('/attestations/att_missing/verify', { method: 'POST' })
      expect(verified.status).toBe(404)
      const verifiedData = await verified.json()
      expect(verifiedData).toMatchObject({
        id: 'att_missing',
        valid: false,
        authorityGranted: false,
      })
      expect(verifiedData.evidenceRefs).toHaveLength(1)

      const evidence = await app.request('/evidence')
      const evidenceData = await evidence.json()
      expect(evidenceData.events).toEqual(expect.arrayContaining([
        expect.objectContaining({
          event_id: verifiedData.evidenceRefs[0],
          type: 'attestation.failed',
          subject: 'att_missing',
          privacy_mode: 'hash_only',
        }),
      ]))
    })

    it('serves local DHT publish and find endpoints', async () => {
      const publish = await app.request('/dht/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          capability: 'invoice.reconcile',
          agentId: 'did:fides:agent',
          agentCardUrl: 'file://agent-card.json',
        }),
      })
      expect(publish.status).toBe(201)
      expect((await publish.json()).authorityGranted).toBe(false)

      const find = await app.request('/dht/find?capability=invoice.reconcile')
      expect(find.status).toBe(200)
      const data = await find.json()
      expect(data.capability).toBe('invoice.reconcile')
      expect(data.pointers).toEqual(expect.arrayContaining([
        expect.objectContaining({ agentId: 'did:fides:agent' }),
      ]))

      const postFind = await app.request('/dht/find', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capability: 'invoice.reconcile' }),
      })
      expect(postFind.status).toBe(200)
      expect((await postFind.json()).pointers).toEqual(expect.arrayContaining([
        expect.objectContaining({ agentId: 'did:fides:agent' }),
      ]))

      const discoverDht = await app.request('/discover/dht', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capability: 'invoice.reconcile' }),
      })
      expect(discoverDht.status).toBe(200)
      expect(await discoverDht.json()).toMatchObject({
        provider: 'dht',
        authorityGranted: false,
        pointers: [],
        rejectedPointers: expect.arrayContaining([
          expect.objectContaining({
            agentId: 'did:fides:agent',
            protocolCompatibility: 'card_unresolved',
            reasons: expect.arrayContaining([
              'provider_record_card_unresolved',
              'discovery_does_not_grant_authority',
            ]),
          }),
        ]),
      })
    })

    it('publishes signed local DHT pointer records without requiring a caller URL', async () => {
      const capability = `signed.dht.${crypto.randomUUID()}`
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Signed DHT Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{ id: capability, requiredScopes: ['signed:dht'] }],
          endpoints: [],
          protocolVersions: ['fides.v2.0'],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const publish = await app.request('/dht/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          capability,
          agentId: identity.did,
        }),
      })
      expect(publish.status).toBe(201)
      const published = await publish.json()
      expect(published.authorityGranted).toBe(false)
      expect(published.pointer).toMatchObject({
        schema_version: 'fides.dht.pointer.v1',
        record_type: 'capability_pointer',
        agent_id: identity.did,
        agentId: identity.did,
        agentCardUrl: `local://agent-cards/${encodeURIComponent(identity.did)}`,
        signed: true,
      })
      expect(published.pointer.agent_card_hash).toMatch(/^sha256:/)
      expect(published.pointer.signature).toEqual(expect.any(String))

      const find = await app.request(`/dht/find?capability=${encodeURIComponent(capability)}`)
      expect(find.status).toBe(200)
      const found = await find.json()
      expect(found.pointers).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agent_id: identity.did,
          verification: expect.objectContaining({ valid: true }),
        }),
      ]))

      const discoverDht = await app.request('/discover/dht', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          capability,
          supported_versions: ['fides.v2.0'],
          required_versions: ['fides.v2.0'],
        }),
      })
      expect(discoverDht.status).toBe(200)
      const discovery = await discoverDht.json()
      expect(discovery.pointers).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agent_id: identity.did,
          verification: expect.objectContaining({ valid: true }),
          versionNegotiation: expect.objectContaining({ compatible: true }),
        }),
      ]))
      expect(discovery.rejectedPointers).toEqual([])
      expect(discovery.authorityGranted).toBe(false)
      expect(discovery.evidenceRefs).toEqual([expect.any(String)])
      expect(discovery.evidence_refs).toEqual(discovery.evidenceRefs)
    })

    it('rejects expired signed local DHT pointer records during discovery', async () => {
      const capability = `expired.dht.${crypto.randomUUID()}`
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Expired DHT Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{ id: capability, requiredScopes: ['expired:dht'] }],
          endpoints: [],
          protocolVersions: ['fides.v2.0'],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const publish = await app.request('/dht/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          capability,
          agentId: identity.did,
          expiresAt: '2026-01-01T00:00:00.000Z',
        }),
      })
      expect(publish.status).toBe(201)

      const discoverDht = await app.request('/discover/dht', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capability }),
      })
      expect(discoverDht.status).toBe(200)
      const discovery = await discoverDht.json()
      expect(discovery.pointers).toEqual([])
      expect(discovery.rejectedPointers).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agent_id: identity.did,
          verification: expect.objectContaining({
            valid: false,
            errors: expect.arrayContaining(['DHT pointer is expired']),
          }),
        }),
      ]))
      expect(discovery.authorityGranted).toBe(false)
      expect(discovery.evidenceRefs).toEqual([expect.any(String)])
      expect(discovery.evidence_refs).toEqual(discovery.evidenceRefs)
    })

    it('serves local registry, relay, and well-known discovery aliases without authority', async () => {
      const identityResponse = await app.request('/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'agent', name: 'Calendar Agent' }),
      })
      const { identity } = await identityResponse.json()
      await app.request('/agent-cards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity,
          capabilities: [{ id: 'calendar.schedule', requiredScopes: ['calendar:write'] }],
        }),
      })
      await app.request(`/agent-cards/${encodeURIComponent(identity.did)}/sign`, { method: 'POST' })
      await app.request('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })

      const publish = await app.request('/registry/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardId: identity.did }),
      })
      expect(publish.status).toBe(201)
      const publishedRegistry = await publish.json()
      expect(publishedRegistry.authorityGranted).toBe(false)
      expect(publishedRegistry.record).toMatchObject({
        agentId: identity.did,
        agentCardUrl: `local://agent-cards/${encodeURIComponent(identity.did)}`,
        registryIndexVerified: true,
        authorityGranted: false,
        registryIndexRecord: expect.objectContaining({
          schema_version: 'fides.registry.index.v1',
          issuer: identity.did,
          agent_card_id: identity.did,
          agent_id: identity.did,
          capability_ids: ['calendar.schedule'],
          registry_url: 'local://registry',
        }),
      })
      expect(publishedRegistry.record.agentCardHash).toMatch(/^sha256:/)
      expect(publishedRegistry.record.registryIndexProof).toMatchObject({
        type: 'Ed25519Signature2024',
        verificationMethod: identity.did,
      })

      const search = await app.request('/registry/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capability: 'calendar.schedule' }),
      })
      expect(search.status).toBe(200)
      const searchData = await search.json()
      expect(searchData.authorityGranted).toBe(false)
      expect(searchData.rejectedRecords).toEqual([])
      expect(searchData.records).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agentId: identity.did,
          registryIndexVerified: true,
          agentCardHash: expect.stringMatching(/^sha256:/),
        }),
      ]))

      const discoverRegistry = await app.request('/discover/registry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capability: 'calendar.schedule' }),
      })
      expect(discoverRegistry.status).toBe(200)
      const discoverRegistryData = await discoverRegistry.json()
      expect(discoverRegistryData).toMatchObject({
        provider: 'registry',
        authorityGranted: false,
        evidenceRefs: [expect.any(String)],
        rejectedRecords: [],
        records: expect.arrayContaining([
          expect.objectContaining({
            agentId: identity.did,
            registryIndexVerified: true,
            agentCardHash: expect.stringMatching(/^sha256:/),
          }),
        ]),
      })
      expect(discoverRegistryData.evidence_refs).toEqual(discoverRegistryData.evidenceRefs)

      const index = await app.request('/registry/index')
      expect(index.status).toBe(200)
      const indexData = await index.json()
      expect(indexData.rejectedRecords).toEqual([])
      expect(indexData.records).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agentId: identity.did,
          registryIndexVerified: true,
          registryIndexRecord: expect.objectContaining({ schema_version: 'fides.registry.index.v1' }),
        }),
      ]))

      const registryStart = await app.request('/registry/start', { method: 'POST' })
      expect(registryStart.status).toBe(200)
      expect((await registryStart.json()).authorityGranted).toBe(false)

      const relayStart = await app.request('/relay/start', { method: 'POST' })
      expect(relayStart.status).toBe(200)
      expect((await relayStart.json()).authorityGranted).toBe(false)

      const relayRegister = await app.request('/relay/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId: identity.did, endpointHints: ['local://calendar-agent'] }),
      })
      expect(relayRegister.status).toBe(201)
      const relayRegistration = await relayRegister.json()
      expect(relayRegistration.authorityGranted).toBe(false)
      expect(relayRegistration.record).toMatchObject({
        agentId: identity.did,
        agentCardUrl: `local://agent-cards/${encodeURIComponent(identity.did)}`,
        signedAgentCard: true,
        endpointHints: ['local://calendar-agent'],
        authorityGranted: false,
      })
      expect(relayRegistration.record.agentCardHash).toMatch(/^sha256:/)
      expect(relayRegistration.record.agentCardProof).toMatchObject({
        type: 'Ed25519Signature2024',
        verificationMethod: identity.did,
      })

      const relayDiscover = await app.request('/relay/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capability: 'calendar.schedule' }),
      })
      expect(relayDiscover.status).toBe(200)
      expect((await relayDiscover.json()).records).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agentId: identity.did,
          agentCardHash: expect.stringMatching(/^sha256:/),
          signedAgentCard: true,
        }),
      ]))

      const discoverRelay = await app.request('/discover/relay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capability: 'calendar.schedule' }),
      })
      expect(discoverRelay.status).toBe(200)
      const discoverRelayData = await discoverRelay.json()
      expect(discoverRelayData).toMatchObject({
        provider: 'relay',
        authorityGranted: false,
        evidenceRefs: [expect.any(String)],
        records: expect.arrayContaining([
          expect.objectContaining({
            agentId: identity.did,
            agentCardHash: expect.stringMatching(/^sha256:/),
            signedAgentCard: true,
            versionNegotiation: expect.objectContaining({ compatible: true }),
          }),
        ]),
      })
      expect(discoverRelayData.evidence_refs).toEqual(discoverRelayData.evidenceRefs)

      const wellKnown = await app.request('/.well-known/fides.json')
      expect(wellKnown.status).toBe(200)
      expect((await wellKnown.json()).endpoints.discovery).toBe('/discover')

      const agents = await app.request('/.well-known/agents.json')
      expect(agents.status).toBe(200)
      expect((await agents.json()).agents).toEqual(expect.arrayContaining([
        expect.objectContaining({ agentId: identity.did, authorityGranted: false }),
      ]))

      const agentCard = await app.request(`/.well-known/agents/${encodeURIComponent(identity.did)}.json`)
      expect(agentCard.status).toBe(200)
      expect((await agentCard.json()).card.id).toBe(identity.did)
    })

    it('serves demo and adversarial simulation endpoints', async () => {
      const demo = await app.request('/demo/run', { method: 'POST' })
      expect(demo.status).toBe(200)
      const demoData = await demo.json()
      expect(demoData.status).toBe('executed')
      expect(demoData.steps).toEqual(fullDemoContractSteps)
      expect(demoData.steps).toContain('discover_payment_through_dht')
      expect(demoData.steps).toContain('verify_evidence_hash_chain')
      expect(demoData.authority).toMatchObject({
        discoveryGrantsAuthority: false,
        policyBeforeExecution: true,
      })
      expect(demoData.verification).toMatchObject({
        agentCardsVerified: true,
        evidenceHashChainValid: true,
      })
      expect(demoData.policy.paymentWithoutAttestation.decision).toBe('require_approval')
      expect(demoData.policy.revokedMalicious.decision).toBe('deny')
      expect(demoData.discovery.registry.records).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agentId: demoData.identities.invoice,
          registryIndexVerified: true,
          agentCardHash: expect.stringMatching(/^sha256:/),
        }),
      ]))
      expect(demoData.discovery.relay.records).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agentId: demoData.identities.calendar,
          signedAgentCard: true,
          agentCardHash: expect.stringMatching(/^sha256:/),
        }),
      ]))
      expect(demoData.discovery.dht.pointers).toEqual(expect.arrayContaining([
        expect.objectContaining({
          agentId: demoData.identities.payment,
          signed: true,
          verification: expect.objectContaining({ valid: true }),
        }),
      ]))
      expect(demoData.invocation.invoice.preflight.can_execute).toBe(true)
      expect(demoData.verification.evidenceEventCount).toBeGreaterThan(0)

      const sim = await app.request('/simulate/adversarial', { method: 'POST' })
      expect(sim.status).toBe(200)
      const data = await sim.json()
      expect(data.status).toBe('detected')
      expect(data.scenarios.map((scenario: any) => scenario.name)).toContain('tampered_agent_card')
      expect(data.scenarios.every((scenario: any) => scenario.detected)).toBe(true)
      expect(data.detections).toContain('context_laundering')
      expect(data.scenarios.find((scenario: any) => scenario.name === 'fake_agent').policy.decision).toBe('dry_run_only')
      expect(data.scenarios.find((scenario: any) => scenario.name === 'malicious_dht_pointer').errors).toContain('DHT pointer signature is invalid')
      expect(data.scenarios.find((scenario: any) => scenario.name === 'tampered_agent_card').outcome).toBe('signature_rejected')
      expect(data.scenarios.find((scenario: any) => scenario.name === 'broken_evidence_chain').outcome).toBe('evidence_verification_failed')
      expect(data.evidence.rootChainValid).toBe(true)
      expect(data.evidence.brokenEvidenceChainValid).toBe(false)
      expect(data.preflight.status).toBe('denied')
    })

    it('serves root evidence append, inspect, verify, and export aliases', async () => {
      const appended = await app.request('/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'capability.invoked',
          actor: 'did:fides:requester:evidence-root',
          subject: 'did:fides:agent:evidence-root',
          principal: 'did:fides:principal:evidence-root',
          capability: 'invoice.reconcile',
          input: { invoiceId: 'inv_123', secret: 'do-not-store' },
          decision: 'allow',
          metadata: { rawPrompt: 'also-do-not-export' },
        }),
      })
      expect(appended.status).toBe(201)
      const appendedData = await appended.json()
      expect(appendedData.authorityGranted).toBe(false)
      expect(appendedData.event.input_hash).toMatch(/^sha256:/)
      expect(JSON.stringify(appendedData)).not.toContain('do-not-store')

      const listed = await app.request('/evidence')
      expect(listed.status).toBe(200)
      const listedData = await listed.json()
      expect(listedData.valid).toBe(true)
      expect(listedData.events).toEqual(expect.arrayContaining([
        expect.objectContaining({ event_id: appendedData.event.event_id }),
      ]))

      const inspected = await app.request(`/evidence/${encodeURIComponent(appendedData.event.event_id)}`)
      expect(inspected.status).toBe(200)
      expect((await inspected.json()).event.event_hash).toBe(appendedData.event.event_hash)

      const verify = await app.request('/evidence/verify', { method: 'POST' })
      expect(verify.status).toBe(200)
      const verified = await verify.json()
      expect(verified.valid).toBe(true)
      expect(verified.count).toBeGreaterThanOrEqual(1)

      const exported = await app.request('/evidence/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ privacy_mode: 'private', include_metadata: false }),
      })
      expect(exported.status).toBe(200)
      const exportedData = await exported.json()
      expect(exportedData.format).toBe('json')
      expect(exportedData.valid).toBe(true)
      expect(exportedData.privacyMode).toBe('private')
      const exportedEvent = exportedData.events.find((event: any) => event.event_id === appendedData.event.event_id)
      expect(exportedEvent).toBeDefined()
      expect(exportedEvent.input_hash).toBeUndefined()
      expect(exportedEvent.decision).toBeUndefined()
      expect(exportedEvent.metadata).toBeUndefined()
      expect(JSON.stringify(exportedData)).not.toContain('also-do-not-export')

      const invalidExport = await app.request('/evidence/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ privacy_mode: 'raw' }),
      })
      expect(invalidExport.status).toBe(400)
    })
  })

  describe('GET /v1/identities/:did', () => {
    it('resolves identity via discovery proxy', async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse({
          did: TEST_DID,
          publicKey: 'aa'.repeat(32),
          metadata: { name: 'Test Agent' },
        })
      )

      const res = await app.request(`/v1/identities/${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.did).toBe(TEST_DID)
      expect(data.status).toBe('resolved')
      expect(data.data).toBeDefined()
    })

    it('returns 404 when identity not found upstream', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: 'Not found' }),
        text: () => Promise.resolve(''),
        headers: new Headers(),
      } as any)

      const res = await app.request(`/v1/identities/${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(404)
      const data = await res.json()
      expect(data.status).toBe('not-found')
    })

    it('returns 502 when discovery is unreachable', async () => {
      mockFetch.mockRejectedValue(new Error('ECONNREFUSED'))

      const res = await app.request(`/v1/identities/${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(502)
      const data = await res.json()
      expect(data.status).toBe('unreachable')
    })
  })

  describe('GET /v1/identities/domain/verify', () => {
    it('verifies a domain DID binding through DNS TXT records', async () => {
      const dns = await import('node:dns/promises')
      vi.mocked(dns.resolveTxt).mockResolvedValue([['fides-did=', TEST_DID]])

      const res = await app.request(`/v1/identities/domain/verify?domain=Example.COM.&did=${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(200)

      const data = await res.json()
      expect(dns.resolveTxt).toHaveBeenCalledWith('_fides.example.com')
      expect(data).toEqual({
        domain: 'example.com',
        did: TEST_DID,
        recordName: '_fides.example.com',
        verified: true,
      })
    })

    it('returns 422 when the domain DID binding is not present', async () => {
      const dns = await import('node:dns/promises')
      vi.mocked(dns.resolveTxt).mockResolvedValue(['other=value'])

      const res = await app.request(`/v1/identities/domain/verify?domain=example.com&did=${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(422)

      const data = await res.json()
      expect(data).toEqual({
        domain: 'example.com',
        did: TEST_DID,
        recordName: '_fides.example.com',
        verified: false,
        reason: 'record-not-found',
      })
    })

    it('requires domain and did query parameters', async () => {
      const res = await app.request('/v1/identities/domain/verify?domain=example.com')
      expect(res.status).toBe(400)

      const data = await res.json()
      expect(data.error).toContain('domain and did')
    })
  })

  describe('GET /v1/cards/:did', () => {
    it('returns agent card from registry', async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse({ id: TEST_DID, name: 'Test Card', version: '1.0' })
      )

      const res = await app.request(`/v1/cards/${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.did).toBe(TEST_DID)
      expect(data.card).toBeDefined()
      expect(data.card.id).toBe(TEST_DID)
    })

    it('returns 404 when card not found in registry', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: 'Not found' }),
        text: () => Promise.resolve(''),
        headers: new Headers(),
      } as any)

      const res = await app.request(`/v1/cards/${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(404)
      const data = await res.json()
      expect(data.error).toBe('not found')
    })

    it('preserves private card denial from registry', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: () => Promise.resolve({ error: 'Private card - access denied' }),
        text: () => Promise.resolve(''),
        headers: new Headers(),
      } as any)

      const res = await app.request(`/v1/cards/${encodeURIComponent(TEST_DID)}`)
      expect(res.status).toBe(403)
      const data = await res.json()
      expect(data.did).toBe(TEST_DID)
      expect(data.card).toBeNull()
      expect(data.error).toContain('private card')
    })
  })

  describe('GET /v1/trust/:did/score', () => {
    it('returns trust score from trust-graph', async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse({ score: 0.85, directTrusters: 5, transitiveTrusters: 12 })
      )

      const res = await app.request(`/v1/trust/${encodeURIComponent(TEST_DID)}/score`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.did).toBe(TEST_DID)
      expect(data.score).toBe(0.85)
      expect(data.directTrusters).toBe(5)
    })

    it('returns fallback score when trust-graph is unreachable', async () => {
      mockFetch.mockRejectedValue(new Error('ECONNREFUSED'))

      const res = await app.request(`/v1/trust/${encodeURIComponent(TEST_DID)}/score`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.did).toBe(TEST_DID)
      expect(data.score).toBe(0.5)
      expect(data.source).toBe('fallback')
    })
  })

  describe('POST /v1/policy/evaluate', () => {
    it('evaluates policy and returns decision', async () => {
      const res = await app.request('/v1/policy/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: TEST_DID,
          capabilityId: 'web:search',
          policy: {
            id: 'policy-1',
            version: '1.0',
            rules: [],
            defaultAction: 'allow',
          },
          context: {},
        }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.decision).toBe('allow')
    })

    it('denies when a policy deny rule matches', async () => {
      const res = await app.request('/v1/policy/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: TEST_DID,
          capabilityId: 'payments:transfer',
          policy: {
            id: 'policy-2',
            version: '1.0',
            rules: [
              {
                id: 'deny-critical-capability',
                condition: { operator: 'eq', field: 'capabilityId', value: 'payments:transfer' },
                action: 'deny',
                explanation: 'Critical payment transfer requires a separate approval flow',
              },
            ],
            defaultAction: 'allow',
          },
          context: {},
        }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.decision).toBe('deny')
      expect(data.matchedRules).toEqual(['deny-critical-capability'])
    })

    it('returns default allow when no policy provided', async () => {
      const res = await app.request('/v1/policy/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: TEST_DID,
          capabilityId: 'web:search',
        }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.decision).toBe('allow')
      expect(data.explanation.decision).toContain('No policy provided')
    })
  })

  describe('Evidence Ledger', () => {
    it('submits evidence and returns 201', async () => {
      const did = `evidence-${Date.now()}`
      const res = await app.request('/v1/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: did,
          action: 'capability:invoke',
          type: 'execution',
          payload: { capability: 'web:search', params: { q: 'test' } },
        }),
      })
      expect(res.status).toBe(201)
      const data = await res.json()
      expect(data.accepted).toBe(true)
      expect(data.id).toBeDefined()
    })

    it('returns 400 when actor is missing', async () => {
      const res = await app.request('/v1/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'log',
          payload: {},
        }),
      })
      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('actor')
    })

    it('retrieves evidence chain for a DID', async () => {
      const did = `evidence-chain-${Date.now()}`
      await app.request('/v1/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: did,
          action: 'event1',
          payload: {},
        }),
      })
      await app.request('/v1/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: did,
          action: 'event2',
          payload: {},
        }),
      })

      const res = await app.request(`/v1/evidence/${encodeURIComponent(did)}`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.did).toBe(did)
      expect(data.events).toHaveLength(2)
      expect(data.valid).toBe(true)
      expect(data.merkleRoot).toBeDefined()
      expect(data.count).toBe(2)
    })

    it('returns empty chain for unknown DID', async () => {
      const did = `empty-chain-${Date.now()}`
      const res = await app.request(`/v1/evidence/${encodeURIComponent(did)}`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.events).toHaveLength(0)
      expect(data.valid).toBe(true)
    })
  })

  describe('Delegation Sessions and Authorization', () => {
    it('creates a session from a delegated capability', async () => {
      const res = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: makeDelegationToken({ delegatee: `${TEST_DID}:session-create` }),
          capabilityId: 'payments.execute',
          audience: 'agentd',
        }),
      })

      expect(res.status).toBe(201)
      const data = await res.json()
      expect(data.authorized).toBe(true)
      expect(data.session.id).toBeDefined()
      expect(data.session.sessionKey).toBe('redacted')
    })

    it('rejects replayed delegation nonces', async () => {
      const token = makeDelegationToken({ delegatee: `${TEST_DID}:session-replay` })

      await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, capabilityId: 'payments.execute', audience: 'agentd' }),
      })
      const res = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, capabilityId: 'payments.execute', audience: 'agentd' }),
      })

      expect(res.status).toBe(409)
      const data = await res.json()
      expect(data.errors).toContain('DelegationToken nonce has already been used')
    })

    it('rejects tampered delegation tokens when a delegator public key is supplied', async () => {
      const { token, publicKey } = await signedDelegationToken(`${TEST_DID}:tampered-session`)
      const tampered = { ...token, capabilities: ['payments.refund'] }

      const res = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: tampered,
          delegatorPublicKey: publicKey,
          capabilityId: 'payments.refund',
          audience: 'agentd',
        }),
      })

      expect(res.status).toBe(409)
      const data = await res.json()
      expect(data.errors).toContain('DelegationToken signature verification failed')
    })

    it('requires a delegator public key when signature verification is mandatory', async () => {
      process.env.AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION = 'true'
      const { token } = await signedDelegationToken(`${TEST_DID}:required-signature-session`)

      const res = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          capabilityId: 'payments.execute',
          audience: 'agentd',
        }),
      })

      expect(res.status).toBe(409)
      const data = await res.json()
      expect(data.errors).toContain('DelegationToken public key is required')
    })

    it('requires a delegator public key by default in production', async () => {
      process.env.NODE_ENV = 'production'
      process.env.SERVICE_API_KEY = 'agentd-prod-key'
      const { token } = await signedDelegationToken(`${TEST_DID}:production-required-signature-session`)

      const res = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'agentd-prod-key' },
        body: JSON.stringify({
          token,
          capabilityId: 'payments.execute',
          audience: 'agentd',
        }),
      })

      expect(res.status).toBe(409)
      const data = await res.json()
      expect(data.errors).toContain('DelegationToken public key is required')
    })

    it('rejects sessions for missing capabilities and audience mismatches', async () => {
      const missingCapability = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: makeDelegationToken({ delegatee: `${TEST_DID}:missing-capability` }),
          capabilityId: 'wallets.sign',
          audience: 'agentd',
        }),
      })
      expect(missingCapability.status).toBe(409)

      const audienceMismatch = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: makeDelegationToken({ delegatee: `${TEST_DID}:audience-mismatch` }),
          capabilityId: 'payments.execute',
          audience: 'registry',
        }),
      })
      expect(audienceMismatch.status).toBe(409)
    })

    it('authorizes an allowed session invocation and appends evidence', async () => {
      const did = `did:fides:authorize-${Date.now()}`
      const sessionRes = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: makeDelegationToken({ delegatee: did }),
          capabilityId: 'payments.execute',
          audience: 'agentd',
        }),
      })
      const { session } = await sessionRes.json()

      const res = await app.request('/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: did,
          capabilityId: 'payments.execute',
          sessionId: session.id,
          audience: 'agentd',
        }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.decision).toBe('allow')

      const evidenceRes = await app.request(`/v1/evidence/${encodeURIComponent(did)}`)
      const evidence = await evidenceRes.json()
      expect(evidence.count).toBe(1)
      expect(evidence.events[0].action).toBe('authorization.allow')
    })

    it('ignores caller-supplied approval grants in production authorization', async () => {
      process.env.NODE_ENV = 'production'
      process.env.SERVICE_API_KEY = 'agentd-key'
      const did = `did:fides:production-approval-${Date.now()}`
      mockFetch
        .mockResolvedValueOnce(await createMockResponse({ score: 0.9 }))
        .mockResolvedValueOnce(await createMockResponse({ score: 0.8 }))

      const res = await app.request('/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'agentd-key' },
        body: JSON.stringify({
          agentDid: did,
          capabilityId: 'payments.execute',
          requiresApproval: true,
          approvalGranted: true,
        }),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.decision).toBe('approve-required')
      expect(data.factors).toEqual(expect.arrayContaining([
        expect.objectContaining({ source: 'approval', factor: 'approval-required' }),
      ]))
    })

    it('uses trust-graph scores instead of caller-supplied reputation in production authorization', async () => {
      process.env.NODE_ENV = 'production'
      process.env.SERVICE_API_KEY = 'agentd-key'
      const did = `did:fides:production-trust-${Date.now()}`
      mockFetch
        .mockResolvedValueOnce(await createMockResponse({ score: 0.05 }))
        .mockResolvedValueOnce(await createMockResponse({ score: 0.9 }))

      const res = await app.request('/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'agentd-key' },
        body: JSON.stringify({
          agentDid: did,
          capabilityId: 'payments.execute',
          reputationScore: 0.99,
          capabilityScore: 0.99,
        }),
      })

      expect(res.status).toBe(403)
      const data = await res.json()
      expect(data.decision).toBe('deny')
      expect(data.explanation).toContain('Blocked by trust threshold guard')
      expect(mockFetch).toHaveBeenCalledWith(`http://localhost:3200/v1/trust/${encodeURIComponent(did)}/score`)
      expect(mockFetch).toHaveBeenCalledWith(`http://localhost:3200/v1/trust/${encodeURIComponent(did)}/capability/${encodeURIComponent('payments.execute')}`)
    })

    it('fails closed when production trust-graph score lookup is unavailable', async () => {
      process.env.NODE_ENV = 'production'
      process.env.SERVICE_API_KEY = 'agentd-key'
      const did = `did:fides:production-trust-unavailable-${Date.now()}`
      mockFetch
        .mockRejectedValueOnce(new Error('trust graph unavailable'))
        .mockResolvedValueOnce(await createMockResponse({ score: 0.9 }))

      const res = await app.request('/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'agentd-key' },
        body: JSON.stringify({
          agentDid: did,
          capabilityId: 'payments.execute',
          reputationScore: 0.99,
        }),
      })

      expect(res.status).toBe(503)
      const data = await res.json()
      expect(data.decision).toBe('deny')
      expect(data.explanation).toContain('Trust graph score lookup failed')
    })

    it('denies authorization after session revocation', async () => {
      const did = `did:fides:session-revoked-${Date.now()}`
      const sessionRes = await app.request('/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: makeDelegationToken({ delegatee: did }),
          capabilityId: 'payments.execute',
          audience: 'agentd',
        }),
      })
      const { session } = await sessionRes.json()

      await app.request(`/v1/sessions/${session.id}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'manual revoke' }),
      })

      const res = await app.request('/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: did,
          capabilityId: 'payments.execute',
          sessionId: session.id,
          audience: 'agentd',
        }),
      })

      expect(res.status).toBe(403)
      const data = await res.json()
      expect(data.explanation).toContain('SessionGrant is revoked')
    })

    it('records revocations and denies future authorization', async () => {
      const did = `did:fides:revoked-${Date.now()}`
      mockFetch.mockResolvedValueOnce(createMockResponse({ id: 'trust-graph-revocation' }, 201))
      const record = await signedRevocationRecord(did)
      const revokeRes = await app.request('/v1/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ record }),
      })
      expect(revokeRes.status).toBe(201)
      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3200/v1/revocations', expect.objectContaining({ method: 'POST' }))

      const statusRes = await app.request(`/v1/revocations/${encodeURIComponent(did)}`)
      const status = await statusRes.json()
      expect(status.revoked).toBe(true)

      const authRes = await app.request('/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: did,
          capabilityId: 'payments.execute',
        }),
      })
      expect(authRes.status).toBe(403)
      const auth = await authRes.json()
      expect(auth.decision).toBe('deny')
      expect(auth.explanation).toContain('Agent authority revoked')
    })

    it('rejects tampered revocation records when a revoker public key is supplied', async () => {
      const did = `did:fides:tampered-revocation-${Date.now()}`
      const privateKey = Buffer.from('01'.repeat(32), 'hex')
      const publicKey = bytesToHex(await ed.getPublicKeyAsync(privateKey))
      const record = await signedRevocationRecord(did)

      const res = await app.request('/v1/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          record: { ...record, reason: 'tampered reason' },
          revokerPublicKey: publicKey,
        }),
      })

      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('revocation signature verification failed')
    })

    it('requires a revoker public key when signature verification is mandatory', async () => {
      process.env.AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION = 'true'
      const did = `did:fides:required-revocation-${Date.now()}`
      const record = await signedRevocationRecord(did)

      const res = await app.request('/v1/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ record }),
      })

      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('revocation public key is required')
    })

    it('requires a revoker public key by default in production', async () => {
      process.env.NODE_ENV = 'production'
      process.env.SERVICE_API_KEY = 'agentd-prod-key'
      const did = `did:fides:production-required-revocation-${Date.now()}`
      const record = await signedRevocationRecord(did)

      const res = await app.request('/v1/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'agentd-prod-key' },
        body: JSON.stringify({ record }),
      })

      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('revocation public key is required')
    })

    it('audits failed revocation propagation to local evidence', async () => {
      const did = `did:fides:revocation-audit-${Date.now()}`
      mockFetch.mockRejectedValueOnce(new Error('trust graph unavailable'))
      const record = await signedRevocationRecord(did)

      const revokeRes = await app.request('/v1/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ record }),
      })

      expect(revokeRes.status).toBe(201)
      const revoke = await revokeRes.json()
      expect(revoke.propagation.ok).toBe(false)
      expect(revoke.propagation.target).toBe('trust-graph')
      expect(revoke.propagation.error).toContain('trust graph unavailable')
      expect(revoke.propagation.queued).toBe(true)
      expect(revoke.propagation.outboxId).toBeDefined()

      const pendingRes = await app.request('/v1/authority/propagations/pending?limit=10')
      const pending = await pendingRes.json()
      expect(pending.propagations.some((record: any) => record.id === revoke.propagation.outboxId)).toBe(true)

      mockFetch.mockResolvedValueOnce(createMockResponse({ id: 'trust-graph-revocation' }, 201))
      const retryRes = await app.request('/v1/authority/propagations/retry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit: 10 }),
      })
      const retry = await retryRes.json()
      const retried = retry.results.find((record: any) => record.id === revoke.propagation.outboxId)
      expect(retried.ok).toBe(true)
      expect(retried.outboxStatus).toBe('confirmed')

      const clearedRes = await app.request('/v1/authority/propagations/pending?limit=10')
      const cleared = await clearedRes.json()
      expect(cleared.propagations.some((record: any) => record.id === revoke.propagation.outboxId)).toBe(false)

      const evidenceRes = await app.request(`/v1/evidence/${encodeURIComponent(did)}`)
      const evidence = await evidenceRes.json()
      expect(evidence.valid).toBe(true)
      expect(evidence.events.map((event: any) => event.action)).toContain('authority.revocation.propagation.failed')
      expect(evidence.events.at(-1).action).toBe('authority.revocation.propagation.confirmed')
    })

    it('records incidents and uses their impact in authorization', async () => {
      const did = `did:fides:incident-${Date.now()}`
      mockFetch.mockResolvedValueOnce(createMockResponse({ id: 'trust-graph-incident' }, 201))
      const record = await signedIncidentRecord(did)
      const incidentRes = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ record }),
      })
      expect(incidentRes.status).toBe(201)
      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3200/v1/incidents', expect.objectContaining({ method: 'POST' }))
      const propagationBody = JSON.parse(mockFetch.mock.calls[0][1].body)
      expect(propagationBody.actorDid).toBe(did)
      expect(propagationBody.capabilitiesRevoked).toContain('payments.execute')
      expect(propagationBody.record.actor).toBe(did)

      const listRes = await app.request(`/v1/incidents/${encodeURIComponent(did)}`)
      const list = await listRes.json()
      expect(list.impact.incidentCount).toBe(1)
      expect(list.impact.allRevokedCapabilities).toContain('payments.execute')

      const authRes = await app.request('/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentDid: did,
          capabilityId: 'payments.execute',
          requiresApproval: true,
        }),
      })
      expect(authRes.status).toBe(200)
      const auth = await authRes.json()
      expect(auth.decision).toBe('approve-required')
    })

    it('rejects tampered incident records when a reporter public key is supplied', async () => {
      const did = `did:fides:tampered-incident-${Date.now()}`
      const privateKey = Buffer.from('01'.repeat(32), 'hex')
      const publicKey = bytesToHex(await ed.getPublicKeyAsync(privateKey))
      const record = await signedIncidentRecord(did)

      const res = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          record: {
            ...record,
            impact: { ...record.impact, trustPenalty: 0 },
          },
          reporterPublicKey: publicKey,
        }),
      })

      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('incident signature verification failed')
    })

    it('requires a reporter public key when signature verification is mandatory', async () => {
      process.env.AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION = 'true'
      const did = `did:fides:required-incident-${Date.now()}`
      const record = await signedIncidentRecord(did)

      const res = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ record }),
      })

      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('incident public key is required')
    })

    it('requires a reporter public key by default in production', async () => {
      process.env.NODE_ENV = 'production'
      process.env.SERVICE_API_KEY = 'agentd-prod-key'
      const did = `did:fides:production-required-incident-${Date.now()}`
      const record = await signedIncidentRecord(did)

      const res = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'agentd-prod-key' },
        body: JSON.stringify({ record }),
      })

      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('incident public key is required')
    })

    it('rejects unsigned revocation payloads', async () => {
      const res = await app.request('/v1/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          did: 'did:fides:unsigned-revocation',
          reason: 'missing canonical record',
          revokedBy: 'did:fides:principal',
        }),
      })

      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('signed revocation record')
    })

    it('rejects unsigned incident payloads', async () => {
      const res = await app.request('/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: 'did:fides:unsigned-incident',
          type: 'policy_violation',
          severity: 'critical',
          description: 'missing canonical record',
        }),
      })

      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('signed incident record')
    })
  })

  describe('Evidence Verification', () => {
    it('verifies an evidence chain without returning full event payloads', async () => {
      const did = `did:fides:evidence-verify-${Date.now()}`
      const submitRes = await app.request('/v1/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: did,
          type: 'authorization',
          action: 'authorization.allow',
          payload: { capabilityId: 'payments.execute' },
        }),
      })
      expect(submitRes.status).toBe(201)

      const verifyRes = await app.request(`/v1/evidence/${encodeURIComponent(did)}/verify`)
      expect(verifyRes.status).toBe(200)
      const verification = await verifyRes.json()
      expect(verification.valid).toBe(true)
      expect(verification.count).toBe(1)
      expect(verification.lastHash).toBeTruthy()
      expect(verification).not.toHaveProperty('events')
    })
  })

  describe('Kill Switch', () => {
    it('returns kill switch status', async () => {
      const res = await app.request('/v1/killswitch/status')
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data).toHaveProperty('global')
    })

    it('engages global kill switch', async () => {
      const res = await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ global: true }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.engaged).toBe(true)
      expect(data.scope).toBe('global')
    })

    it('engages agent-specific kill switch', async () => {
      const res = await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ did: TEST_DID }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.engaged).toBe(true)
      expect(data.scope).toBe('agent')
      expect(data.did).toBe(TEST_DID)
    })

    it('engages capability-specific kill switch', async () => {
      const res = await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capabilityId: 'payment:charge' }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.engaged).toBe(true)
      expect(data.scope).toBe('capability')
      expect(data.id).toBe('payment:charge')
    })

    it('disengages kill switch', async () => {
      await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ global: true }),
      })

      const res = await app.request('/v1/killswitch/disengage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ global: true }),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.engaged).toBe(false)
      expect(data.scope).toBe('global')
    })

    it('disengages all kill switches when no scope specified', async () => {
      const did = `${TEST_DID}:killswitch-all`
      const capabilityId = 'payment:refund:killswitch-all'

      await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ global: true }),
      })
      await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ did }),
      })
      await app.request('/v1/killswitch/engage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capabilityId }),
      })

      const res = await app.request('/v1/killswitch/disengage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.engaged).toBe(false)
      expect(data.scope).toBe('all')

      const authRes = await app.request('/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentDid: did, capabilityId }),
      })
      expect(authRes.status).toBe(200)
      const auth = await authRes.json()
      expect(auth.decision).toBe('allow')
    })
  })

  describe('POST /v1/attest', () => {
    it('creates runtime attestation', async () => {
      const res = await app.request('/v1/attest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ did: TEST_DID }),
      })
      expect(res.status).toBe(201)
      const data = await res.json()
      expect(data.agentDid).toBe(TEST_DID)
      expect(data.provider).toBe('mock-tee')
      expect(data.measurement).toBeDefined()
      expect(data.signature).toMatch(/^local-attestation:/)
    })

    it('returns 400 when did is missing', async () => {
      const res = await app.request('/v1/attest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('did')
    })
  })
})
