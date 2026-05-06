import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { bodyLimit } from 'hono/body-limit'
import { cors } from 'hono/cors'
import type { MiddlewareHandler } from 'hono'
import { isValidFidesDid, type PasskeyCredentialBinding } from '@fides/core'
import { evaluateApiKeyAuth, MetricsCollector, metricsMiddleware } from '@fides/shared'
import { createPlatformStore } from './storage.js'

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

app.get('/v1/topology', apiKeyAuth(), (c) => c.json({
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

app.post('/v1/passkeys/bindings', apiKeyAuth(), async (c) => {
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

app.get('/v1/passkeys/principals/:did/credentials', apiKeyAuth(), async (c) => {
  const principalDid = c.req.param('did')
  if (!isValidFidesDid(principalDid)) {
    return c.json({ error: 'invalid principal DID' }, 400)
  }

  const credentials = (await store.listPasskeyBindings(principalDid)).map(toCredentialDescriptor)

  return c.json({ principalDid, credentials, count: credentials.length })
})

app.get('/v1/passkeys/credentials/:credentialId', apiKeyAuth(), async (c) => {
  const credentialId = c.req.param('credentialId')
  const binding = await store.getPasskeyBinding(credentialId)
  if (!binding) {
    return c.json({ error: 'passkey credential binding not found' }, 404)
  }
  return c.json({ binding })
})

app.delete('/v1/passkeys/credentials/:credentialId', apiKeyAuth(), async (c) => {
  const credentialId = c.req.param('credentialId')
  const deleted = await store.deletePasskeyBinding(credentialId)
  if (!deleted) {
    return c.json({ error: 'passkey credential binding not found' }, 404)
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

function apiKeyAuth(): MiddlewareHandler {
  return async (c, next) => {
    const decision = evaluateApiKeyAuth({
      configuredKey: process.env.SERVICE_API_KEY,
      providedKey: c.req.header('X-API-Key'),
      nodeEnv: process.env.NODE_ENV,
      productionRequirement: 'topology metadata',
    })
    if (!decision.ok) {
      return c.json({ error: decision.error }, decision.status)
    }

    return next()
  }
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

  return {
    ok: true,
    value: {
      principalDid: input.principalDid,
      credentialId: input.credentialId.trim(),
      publicKey: input.publicKey.trim(),
      relyingPartyId: input.relyingPartyId.trim().toLowerCase(),
      signCount,
      transports: input.transports,
      backedUp: input.backedUp,
      createdAt: input.createdAt,
      lastVerifiedAt: input.lastVerifiedAt,
    },
  }
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
