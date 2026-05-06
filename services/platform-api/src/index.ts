import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { bodyLimit } from 'hono/body-limit'
import { cors } from 'hono/cors'
import type { MiddlewareHandler } from 'hono'
import { timingSafeEqual } from 'node:crypto'

const app = new Hono()
const startTime = Date.now()

const SERVICE_PORTS = {
  discovery: 3100,
  trustGraph: 3200,
  policyEngine: 3300,
  registry: 7346,
  relay: 7347,
  agentd: 7345,
} as const

app.use('*', cors({ origin: getCorsOrigin() }))
app.use('*', bodyLimit({ maxSize: 1024 * 1024 }))

app.get('/health', (c) => c.json({
  status: 'healthy',
  service: 'platform-api',
  uptime: Math.floor((Date.now() - startTime) / 1000),
  timestamp: new Date().toISOString(),
}))

app.get('/v1/version', (c) => c.json({
  service: 'platform-api',
  version: '0.1.0',
  protocol: 'fides-v2',
}))

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
    const apiKey = process.env.SERVICE_API_KEY
    if (!apiKey) {
      if (process.env.NODE_ENV === 'production') {
        return c.json({ error: 'SERVICE_API_KEY is required in production for topology metadata' }, 503)
      }
      return next()
    }

    const providedKey = c.req.header('X-API-Key')
    if (!providedKey || !timingSafeStringEqual(providedKey, apiKey)) {
      return c.json({ error: 'Unauthorized - invalid or missing API key' }, 401)
    }

    return next()
  }
}

function timingSafeStringEqual(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a)
  const bBuffer = Buffer.from(b)
  if (aBuffer.length !== bBuffer.length) return false
  return timingSafeEqual(aBuffer, bBuffer)
}
