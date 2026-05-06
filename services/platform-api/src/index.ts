import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { bodyLimit } from 'hono/body-limit'
import { cors } from 'hono/cors'
import type { MiddlewareHandler } from 'hono'
import {
  createTrustAnchorDistribution,
  isValidFidesDid,
  type GovernedTrustAnchor,
  type PasskeyCredentialBinding,
  type TrustAnchorStatus,
} from '@fides/core'
import { evaluateApiKeyAuth, MetricsCollector, metricsMiddleware, type ScopedApiKey } from '@fides/shared'
import { createPlatformStore, type PlatformTrustAnchorRecord } from './storage.js'

const app = new Hono()
const startTime = Date.now()
const collector = new MetricsCollector()
const store = createPlatformStore()

const SERVICE_PORTS = {
  discovery: 3100,
  trustGraph: 3200,
  policyEngine: 3300,
  registry: 7346,
  relay: 7347,
  agentd: 7345,
} as const
const PASSKEY_TRANSPORTS = ['ble', 'hybrid', 'internal', 'nfc', 'usb'] as const
const PLATFORM_API_SCOPES = {
  topologyRead: 'platform:topology:read',
  passkeysRead: 'platform:passkeys:read',
  passkeysWrite: 'platform:passkeys:write',
  trustAnchorsRead: 'platform:trust-anchors:read',
  trustAnchorsWrite: 'platform:trust-anchors:write',
} as const

app.use('*', metricsMiddleware(collector))
app.use('*', cors({ origin: getCorsOrigin() }))
app.use('*', bodyLimit({ maxSize: 1024 * 1024 }))

app.get('/health', async (c) => {
  const persistence = await store.healthCheck()
  return c.json({
    status: persistence.ok ? 'healthy' : 'degraded',
    service: 'platform-api',
    uptime: Math.floor((Date.now() - startTime) / 1000),
    timestamp: new Date().toISOString(),
    checks: {
      persistence: persistence.ok ? 'ok' : 'fail',
      store: persistence,
    },
  }, persistence.ok ? 200 : 503)
})

app.get('/v1/version', (c) => c.json({
  service: 'platform-api',
  version: '0.1.0',
  protocol: 'fides-v2',
}))

app.get('/metrics', (c) => {
  return c.text(collector.toPrometheus(), 200, { 'Content-Type': 'text/plain; version=0.0.4' })
})

app.get('/v1/topology', apiKeyAuth('topology metadata', PLATFORM_API_SCOPES.topologyRead), (c) => c.json({
  service: 'platform-api',
  components: {
    discovery: serviceUrl('DISCOVERY_URL', SERVICE_PORTS.discovery),
    trustGraph: serviceUrl('TRUST_GRAPH_URL', SERVICE_PORTS.trustGraph),
    policyEngine: serviceUrl('POLICY_ENGINE_URL', SERVICE_PORTS.policyEngine),
    registry: serviceUrl('REGISTRY_URL', SERVICE_PORTS.registry),
    relay: serviceUrl('RELAY_URL', SERVICE_PORTS.relay),
    agentd: serviceUrl('AGENTD_URL', SERVICE_PORTS.agentd),
  },
}))

app.post('/v1/passkeys/bindings', apiKeyAuth('passkey credential bindings', PLATFORM_API_SCOPES.passkeysWrite), async (c) => {
  const body = await c.req.json()
  const binding = parsePasskeyBinding(body)
  if (!binding.ok) {
    return c.json({ error: binding.error }, 400)
  }

  const existing = await store.getPasskeyBinding(binding.value.credentialId)
  if (existing && existing.principalDid !== binding.value.principalDid) {
    return c.json({ error: 'credential is already bound to a different principal' }, 409)
  }
  if (existing && binding.value.signCount < existing.signCount) {
    return c.json({ error: 'credential signCount cannot move backwards' }, 409)
  }

  const now = new Date().toISOString()
  const stored: PasskeyCredentialBinding = {
    ...binding.value,
    createdAt: existing?.createdAt ?? binding.value.createdAt,
    lastVerifiedAt: now,
  }
  await store.putPasskeyBinding(stored)

  return c.json({ binding: stored }, existing ? 200 : 201)
})

app.get('/v1/passkeys/principals/:did/credentials', apiKeyAuth('passkey credential bindings', PLATFORM_API_SCOPES.passkeysRead), async (c) => {
  const principalDid = c.req.param('did')
  if (!isValidFidesDid(principalDid)) {
    return c.json({ error: 'invalid principal DID' }, 400)
  }

  const credentials = (await store.listPasskeyBindings(principalDid)).map(toCredentialDescriptor)

  return c.json({ principalDid, credentials, count: credentials.length })
})

app.get('/v1/passkeys/credentials/:credentialId', apiKeyAuth('passkey credential bindings', PLATFORM_API_SCOPES.passkeysRead), async (c) => {
  const credentialId = c.req.param('credentialId')
  const binding = await store.getPasskeyBinding(credentialId)
  if (!binding) {
    return c.json({ error: 'passkey credential binding not found' }, 404)
  }
  return c.json({ binding })
})

app.delete('/v1/passkeys/credentials/:credentialId', apiKeyAuth('passkey credential bindings', PLATFORM_API_SCOPES.passkeysWrite), async (c) => {
  const credentialId = c.req.param('credentialId')
  const deleted = await store.deletePasskeyBinding(credentialId)
  if (!deleted) {
    return c.json({ error: 'passkey credential binding not found' }, 404)
  }
  return c.json({ success: true })
})

app.post('/v1/trust-anchors', apiKeyAuth('trust-anchor governance', PLATFORM_API_SCOPES.trustAnchorsWrite), async (c) => {
  const body = await c.req.json()
  const parsed = parseTrustAnchorRecord(body)
  if (!parsed.ok) {
    return c.json({ error: parsed.error }, 400)
  }

  const existing = await store.getTrustAnchor(parsed.value.did)
  const now = new Date().toISOString()
  const anchor: PlatformTrustAnchorRecord = {
    ...parsed.value,
    createdAt: existing?.createdAt ?? parsed.value.createdAt,
    updatedAt: now,
  }
  await store.putTrustAnchor(anchor)

  return c.json({ anchor }, existing ? 200 : 201)
})

app.get('/v1/trust-anchors', apiKeyAuth('trust-anchor governance', PLATFORM_API_SCOPES.trustAnchorsRead), async (c) => {
  const status = c.req.query('status')
  if (status !== undefined && !isTrustAnchorStatus(status)) {
    return c.json({ error: 'status must be active, suspended, or revoked' }, 400)
  }
  const anchors = await store.listTrustAnchors()
  const filtered = status
    ? anchors.filter(anchor => anchor.status === status)
    : anchors

  return c.json({ anchors: filtered, count: filtered.length })
})

app.get('/v1/trust-anchors/distribution', apiKeyAuth('trust-anchor governance', PLATFORM_API_SCOPES.trustAnchorsRead), async (c) => {
  const requiredScope = c.req.query('requiredScope')
  const trustedIssuerDids = parseCsv(c.req.query('trustedIssuerDids'))
  const anchors = await store.listTrustAnchors()
  const distribution = createTrustAnchorDistribution(
    anchors.map(toGovernedTrustAnchor),
    {
      issuerDid: c.req.query('issuerDid'),
      policy: {
        requiredScope,
        trustedIssuerDids,
      },
    }
  )

  return c.json({ distribution })
})

app.get('/v1/trust-anchors/:did', apiKeyAuth('trust-anchor governance', PLATFORM_API_SCOPES.trustAnchorsRead), async (c) => {
  const did = c.req.param('did')
  const anchor = await store.getTrustAnchor(did)
  if (!anchor) {
    return c.json({ error: 'trust anchor not found' }, 404)
  }
  return c.json({ anchor })
})

app.patch('/v1/trust-anchors/:did/status', apiKeyAuth('trust-anchor governance', PLATFORM_API_SCOPES.trustAnchorsWrite), async (c) => {
  const did = c.req.param('did')
  const existing = await store.getTrustAnchor(did)
  if (!existing) {
    return c.json({ error: 'trust anchor not found' }, 404)
  }

  const body = await c.req.json()
  const statusUpdate = parseTrustAnchorStatusUpdate(body)
  if (!statusUpdate.ok) {
    return c.json({ error: statusUpdate.error }, 400)
  }

  const now = new Date().toISOString()
  const updated: PlatformTrustAnchorRecord = {
    ...existing,
    status: statusUpdate.value.status,
    reason: statusUpdate.value.reason,
    revokedAt: statusUpdate.value.status === 'revoked' ? statusUpdate.value.revokedAt ?? now : undefined,
    updatedAt: now,
  }
  await store.putTrustAnchor(updated)

  return c.json({ anchor: updated })
})

app.delete('/v1/trust-anchors/:did', apiKeyAuth('trust-anchor governance', PLATFORM_API_SCOPES.trustAnchorsWrite), async (c) => {
  const did = c.req.param('did')
  const deleted = await store.deleteTrustAnchor(did)
  if (!deleted) {
    return c.json({ error: 'trust anchor not found' }, 404)
  }
  return c.json({ success: true })
})

export { app }

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.PLATFORM_API_PORT || process.env.PORT || '3600', 10)
  console.log(`FIDES platform-api starting on port ${port}`)
  serve({ fetch: app.fetch, port })
}

function serviceUrl(envName: string, port: number): string {
  return process.env[envName] || `http://localhost:${port}`
}

function getCorsOrigin(): string {
  if (process.env.NODE_ENV === 'production') {
    return process.env.CORS_ORIGIN || 'https://localhost'
  }
  return process.env.CORS_ORIGIN || '*'
}

function apiKeyAuth(productionRequirement: string, requiredScope: string): MiddlewareHandler {
  return async (c, next) => {
    const scopedKeys = parsePlatformApiKeys(process.env.PLATFORM_API_KEYS)
    if (!scopedKeys.ok) {
      return c.json({ error: scopedKeys.error }, 503)
    }

    const decision = evaluateApiKeyAuth({
      configuredKey: process.env.SERVICE_API_KEY,
      configuredKeys: scopedKeys.value,
      providedKey: c.req.header('X-API-Key'),
      nodeEnv: process.env.NODE_ENV,
      productionRequirement,
      requiredScope,
    })
    if (!decision.ok) {
      return c.json({ error: decision.error }, decision.status)
    }

    return next()
  }
}

function parsePlatformApiKeys(raw: string | undefined): { ok: true; value?: ScopedApiKey[] } | { ok: false; error: string } {
  if (raw === undefined || raw.trim().length === 0) {
    return { ok: true, value: undefined }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return { ok: false, error: 'PLATFORM_API_KEYS must be a JSON array of scoped API keys' }
  }

  if (!Array.isArray(parsed)) {
    return { ok: false, error: 'PLATFORM_API_KEYS must be a JSON array of scoped API keys' }
  }

  const keys: ScopedApiKey[] = []
  for (const entry of parsed) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      return { ok: false, error: 'PLATFORM_API_KEYS entries must include a non-empty key and scopes array' }
    }
    const candidate = entry as { key?: unknown; scopes?: unknown }
    if (typeof candidate.key !== 'string' || candidate.key.trim().length === 0) {
      return { ok: false, error: 'PLATFORM_API_KEYS entries must include a non-empty key and scopes array' }
    }
    if (!Array.isArray(candidate.scopes) || candidate.scopes.length === 0) {
      return { ok: false, error: 'PLATFORM_API_KEYS entries must include a non-empty key and scopes array' }
    }
    if (candidate.scopes.some(scope => typeof scope !== 'string' || scope.trim().length === 0)) {
      return { ok: false, error: 'PLATFORM_API_KEYS scopes must be non-empty strings' }
    }

    keys.push({
      key: candidate.key.trim(),
      scopes: [...new Set(candidate.scopes.map(scope => scope.trim()))].sort(),
    })
  }

  if (keys.length === 0) {
    return { ok: false, error: 'PLATFORM_API_KEYS must contain at least one scoped API key' }
  }

  return { ok: true, value: keys }
}

function parsePasskeyBinding(body: unknown): { ok: true; value: PasskeyCredentialBinding } | { ok: false; error: string } {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, error: 'request body must be a passkey credential binding' }
  }
  const input = body as Partial<PasskeyCredentialBinding>
  if (typeof input.principalDid !== 'string' || !isValidFidesDid(input.principalDid)) {
    return { ok: false, error: 'principalDid must be a valid did:fides DID' }
  }
  if (typeof input.credentialId !== 'string' || input.credentialId.trim().length === 0) {
    return { ok: false, error: 'credentialId is required' }
  }
  if (typeof input.publicKey !== 'string' || input.publicKey.trim().length === 0) {
    return { ok: false, error: 'publicKey is required' }
  }
  if (typeof input.relyingPartyId !== 'string' || input.relyingPartyId.trim().length === 0) {
    return { ok: false, error: 'relyingPartyId is required' }
  }
  const signCount = input.signCount
  if (!Number.isInteger(signCount) || signCount === undefined || signCount < 0) {
    return { ok: false, error: 'signCount must be a non-negative integer' }
  }
  if (typeof input.createdAt !== 'string' || Number.isNaN(Date.parse(input.createdAt))) {
    return { ok: false, error: 'createdAt must be an ISO 8601 timestamp' }
  }
  if (input.lastVerifiedAt !== undefined && (typeof input.lastVerifiedAt !== 'string' || Number.isNaN(Date.parse(input.lastVerifiedAt)))) {
    return { ok: false, error: 'lastVerifiedAt must be an ISO 8601 timestamp' }
  }
  const transports = parsePasskeyTransports(input.transports)
  if (!transports.ok) {
    return transports
  }
  if (input.backedUp !== undefined && typeof input.backedUp !== 'boolean') {
    return { ok: false, error: 'backedUp must be a boolean' }
  }

  return {
    ok: true,
    value: {
      principalDid: input.principalDid,
      credentialId: input.credentialId.trim(),
      publicKey: input.publicKey.trim(),
      relyingPartyId: input.relyingPartyId.trim().toLowerCase(),
      signCount,
      transports: transports.value,
      backedUp: input.backedUp,
      createdAt: input.createdAt,
      lastVerifiedAt: input.lastVerifiedAt,
    },
  }
}

function parsePasskeyTransports(input: unknown): { ok: true; value?: PasskeyCredentialBinding['transports'] } | { ok: false; error: string } {
  if (input === undefined) {
    return { ok: true, value: undefined }
  }
  if (!Array.isArray(input)) {
    return { ok: false, error: 'transports must be an array of WebAuthn transport strings' }
  }
  if (input.some(transport => typeof transport !== 'string' || !isPasskeyTransport(transport))) {
    return { ok: false, error: `transports must only contain ${PASSKEY_TRANSPORTS.join(', ')}` }
  }
  return { ok: true, value: [...new Set(input)].sort() as PasskeyCredentialBinding['transports'] }
}

function isPasskeyTransport(value: string): value is NonNullable<PasskeyCredentialBinding['transports']>[number] {
  return PASSKEY_TRANSPORTS.some(transport => transport === value)
}

function parseTrustAnchorRecord(body: unknown): { ok: true; value: PlatformTrustAnchorRecord } | { ok: false; error: string } {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, error: 'request body must be a trust anchor record' }
  }

  const input = body as Partial<PlatformTrustAnchorRecord>
  if (typeof input.did !== 'string' || !isValidFidesDid(input.did)) {
    return { ok: false, error: 'did must be a valid did:fides DID' }
  }
  if (typeof input.name !== 'string' || input.name.trim().length === 0) {
    return { ok: false, error: 'name is required' }
  }
  if (typeof input.publicKey !== 'string' || !isHexPublicKey(input.publicKey)) {
    return { ok: false, error: 'publicKey must be a 32-byte hex string' }
  }
  if (!input.attestation || typeof input.attestation !== 'object' || Array.isArray(input.attestation)) {
    return { ok: false, error: 'attestation must be an object' }
  }
  if (!isSignedObject(input.attestation)) {
    return { ok: false, error: 'attestation must include payload and proof' }
  }
  if (!isTrustAnchorStatus(input.status)) {
    return { ok: false, error: 'status must be active, suspended, or revoked' }
  }
  if (!Array.isArray(input.scopes) || input.scopes.length === 0 || input.scopes.some(scope => typeof scope !== 'string' || scope.trim().length === 0)) {
    return { ok: false, error: 'scopes must contain at least one non-empty string' }
  }
  if (input.issuerDid !== undefined && (typeof input.issuerDid !== 'string' || !isValidFidesDid(input.issuerDid))) {
    return { ok: false, error: 'issuerDid must be a valid did:fides DID' }
  }
  if (typeof input.createdAt !== 'string' || Number.isNaN(Date.parse(input.createdAt))) {
    return { ok: false, error: 'createdAt must be an ISO 8601 timestamp' }
  }
  if (input.updatedAt !== undefined && (typeof input.updatedAt !== 'string' || Number.isNaN(Date.parse(input.updatedAt)))) {
    return { ok: false, error: 'updatedAt must be an ISO 8601 timestamp' }
  }
  if (input.expiresAt !== undefined && (typeof input.expiresAt !== 'string' || Number.isNaN(Date.parse(input.expiresAt)))) {
    return { ok: false, error: 'expiresAt must be an ISO 8601 timestamp' }
  }
  if (input.revokedAt !== undefined && (typeof input.revokedAt !== 'string' || Number.isNaN(Date.parse(input.revokedAt)))) {
    return { ok: false, error: 'revokedAt must be an ISO 8601 timestamp' }
  }
  if (input.status === 'revoked' && !input.revokedAt) {
    return { ok: false, error: 'revoked trust anchors must include revokedAt' }
  }
  if (input.reason !== undefined && typeof input.reason !== 'string') {
    return { ok: false, error: 'reason must be a string' }
  }
  if (input.metadata !== undefined && (typeof input.metadata !== 'object' || Array.isArray(input.metadata))) {
    return { ok: false, error: 'metadata must be an object' }
  }

  return {
    ok: true,
    value: {
      did: input.did,
      name: input.name.trim(),
      publicKey: input.publicKey.toLowerCase(),
      attestation: input.attestation,
      status: input.status,
      scopes: [...new Set(input.scopes.map(scope => scope.trim()))].sort(),
      issuerDid: input.issuerDid,
      createdAt: input.createdAt,
      updatedAt: input.updatedAt,
      expiresAt: input.expiresAt,
      revokedAt: input.revokedAt,
      reason: input.reason,
      metadata: input.metadata,
    },
  }
}

function parseTrustAnchorStatusUpdate(body: unknown): { ok: true; value: { status: TrustAnchorStatus; revokedAt?: string; reason?: string } } | { ok: false; error: string } {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, error: 'request body must be a trust anchor status update' }
  }

  const input = body as { status?: unknown; revokedAt?: unknown; reason?: unknown }
  if (!isTrustAnchorStatus(input.status)) {
    return { ok: false, error: 'status must be active, suspended, or revoked' }
  }
  if (input.revokedAt !== undefined && (typeof input.revokedAt !== 'string' || Number.isNaN(Date.parse(input.revokedAt)))) {
    return { ok: false, error: 'revokedAt must be an ISO 8601 timestamp' }
  }
  if (input.reason !== undefined && typeof input.reason !== 'string') {
    return { ok: false, error: 'reason must be a string' }
  }

  return {
    ok: true,
    value: {
      status: input.status,
      revokedAt: input.revokedAt,
      reason: input.reason,
    },
  }
}

function isSignedObject(value: unknown): value is PlatformTrustAnchorRecord['attestation'] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const candidate = value as { payload?: unknown; proof?: unknown }
  if (!('payload' in candidate)) return false
  if (!candidate.proof || typeof candidate.proof !== 'object' || Array.isArray(candidate.proof)) return false
  const proof = candidate.proof as Record<string, unknown>
  return (
    proof.type === 'Ed25519Signature2024' &&
    typeof proof.created === 'string' &&
    typeof proof.verificationMethod === 'string' &&
    isProofPurpose(proof.proofPurpose) &&
    proof.canonicalizationAlgorithm === 'https://fides.dev/canonical-json/v1' &&
    typeof proof.proofValue === 'string'
  )
}

function isProofPurpose(value: unknown): value is PlatformTrustAnchorRecord['attestation']['proof']['proofPurpose'] {
  return value === 'assertionMethod' ||
    value === 'authentication' ||
    value === 'delegation' ||
    value === 'capabilityInvocation'
}

function toGovernedTrustAnchor(anchor: PlatformTrustAnchorRecord): GovernedTrustAnchor {
  return {
    ...anchor,
    publicKey: hexToBytes(anchor.publicKey),
  }
}

function isTrustAnchorStatus(value: unknown): value is TrustAnchorStatus {
  return value === 'active' || value === 'suspended' || value === 'revoked'
}

function isHexPublicKey(value: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(value)
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function parseCsv(value: string | undefined): string[] | undefined {
  if (!value) return undefined
  const entries = value.split(',').map(entry => entry.trim()).filter(Boolean)
  return entries.length > 0 ? entries : undefined
}

function toCredentialDescriptor(binding: PasskeyCredentialBinding): {
  credentialId: string
  relyingPartyId: string
  signCount: number
  transports?: PasskeyCredentialBinding['transports']
  backedUp?: boolean
  createdAt: string
  lastVerifiedAt?: string
} {
  return {
    credentialId: binding.credentialId,
    relyingPartyId: binding.relyingPartyId,
    signCount: binding.signCount,
    transports: binding.transports,
    backedUp: binding.backedUp,
    createdAt: binding.createdAt,
    lastVerifiedAt: binding.lastVerifiedAt,
  }
}
