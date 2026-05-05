/**
 * FIDES v2 Registry Service
 *
 * Hosted registry for AgentCards with file-based persistence,
 * public/private mode, and search.
 */

import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { cors } from 'hono/cors'
import { bodyLimit } from 'hono/body-limit'
import { rateLimitMiddleware, MetricsCollector, metricsMiddleware } from '@fides/sdk'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { logger } from './middleware/logger.js'
import { securityHeaders } from './middleware/security.js'
import { errorHandler } from './middleware/error-handler.js'
import { apiKeyAuth } from './middleware/auth.js'

const app = new Hono()
const collector = new MetricsCollector()

const REGISTRY_DIR = join(homedir(), '.fides', 'registry')
const REGISTRY_FILE = join(REGISTRY_DIR, 'registry.json')

interface RegistryEntry {
  card: Record<string, unknown>
  mode: 'public' | 'private'
  registeredAt: string
  updatedAt: string
  metadata: Record<string, unknown>
}

function ensureDir(): void {
  if (!existsSync(REGISTRY_DIR)) {
    mkdirSync(REGISTRY_DIR, { recursive: true })
  }
}

function loadRegistry(): Map<string, RegistryEntry> {
  ensureDir()
  if (!existsSync(REGISTRY_FILE)) {
    return new Map()
  }
  const data = JSON.parse(readFileSync(REGISTRY_FILE, 'utf-8'))
  return new Map(Object.entries(data))
}

function saveRegistry(reg: Map<string, RegistryEntry>): void {
  ensureDir()
  const obj: Record<string, RegistryEntry> = {}
  for (const [did, entry] of reg) {
    obj[did] = entry
  }
  writeFileSync(REGISTRY_FILE, JSON.stringify(obj, null, 2))
}

const registry = loadRegistry()

function getCorsOrigin(): string {
  const corsOrigin = process.env.CORS_ORIGIN
  if (process.env.NODE_ENV === 'production') {
    if (!corsOrigin) {
      console.warn('CORS_ORIGIN not set in production — using restrictive default')
    }
    return corsOrigin || 'https://localhost'
  }
  return corsOrigin || '*'
}

// Global middleware stack
app.use('*', metricsMiddleware(collector))
app.use('*', logger())
app.use('*', securityHeaders())
app.use('*', cors({
  origin: getCorsOrigin(),
  exposeHeaders: ['X-Request-Id'],
}))
// Auth on mutating endpoints (skip GET /health)
app.use('/v1/*', async (c, next) => {
  if (c.req.method === 'GET') return next()
  const auth = apiKeyAuth()
  return auth(c, next)
})
app.post('*', rateLimitMiddleware({ maxRequests: 100, windowMs: 60_000 }))
app.get('*', rateLimitMiddleware({ maxRequests: 300, windowMs: 60_000 }))
app.use('*', bodyLimit({ maxSize: 1024 * 1024 }))

app.onError(errorHandler)

// Metrics endpoint
app.get('/metrics', (c) => {
  return c.text(collector.toPrometheus(), 200, { 'Content-Type': 'text/plain; version=0.0.4' })
})

// ─── Health ───────────────────────────────────────────────────────
app.get('/health', (c) => {
  let persistenceOk = false
  try {
    const testPath = join(REGISTRY_DIR, '.healthcheck')
    writeFileSync(testPath, JSON.stringify({ ts: Date.now() }))
    const data = JSON.parse(readFileSync(testPath, 'utf-8'))
    persistenceOk = !!data.ts
  } catch {
    // persistence broken
  }

  const status = persistenceOk ? 'healthy' : 'degraded'
  return c.json({
    status,
    service: 'registry',
    count: registry.size,
    timestamp: new Date().toISOString(),
    checks: {
      persistence: persistenceOk ? 'ok' : 'fail',
    },
  }, persistenceOk ? 200 : 503)
})

/**
 * Register an AgentCard.
 */
app.post('/v1/cards', async (c) => {
  const body = await c.req.json()
  const did = body.id || body.payload?.id
  if (!did) {
    return c.json({ error: 'id is required' }, 400)
  }

  const now = new Date().toISOString()
  registry.set(did, {
    card: body,
    mode: 'public',
    registeredAt: now,
    updatedAt: now,
    metadata: {},
  })
  saveRegistry(registry)

  return c.json({ success: true, did, registeredAt: now }, 201)
})

/**
 * Get an AgentCard by DID.
 */
app.get('/v1/cards/:did', (c) => {
  const did = c.req.param('did')
  const entry = registry.get(did)
  if (!entry) {
    return c.json({ error: 'Not found' }, 404)
  }
  if (entry.mode === 'private') {
    return c.json({ error: 'Private card — access denied' }, 403)
  }
  return c.json(entry.card)
})

/**
 * Search AgentCards.
 */
app.get('/v1/search', (c) => {
  const query = c.req.query('q')?.toLowerCase() || ''
  const results: Array<{ did: string; name?: string; capabilities?: string[] }> = []

  for (const [did, entry] of registry) {
    if (entry.mode === 'private') continue

    const card = entry.card as Record<string, unknown>
    const payload = card.payload as Record<string, unknown> | undefined
    const name = ((card.name as string) || (payload?.name as string) || '') as string
    const capsRaw = (card.capabilities || payload?.capabilities || []) as unknown[]

    if (!query || name.toLowerCase().includes(query) || did.toLowerCase().includes(query)) {
      const capabilities: string[] = Array.isArray(capsRaw)
        ? capsRaw.map(c => typeof c === 'string' ? c : (c as Record<string, unknown>).id as string)
        : []
      results.push({ did, name, capabilities })
    }
  }

  return c.json({ results, count: results.length, query })
})

/**
 * Delete an AgentCard.
 */
app.delete('/v1/cards/:did', (c) => {
  const did = c.req.param('did')
  if (!registry.has(did)) {
    return c.json({ error: 'Not found' }, 404)
  }
  registry.delete(did)
  saveRegistry(registry)
  return c.json({ success: true })
})

/**
 * Update visibility mode.
 */
app.post('/v1/cards/:did/mode', async (c) => {
  const did = c.req.param('did')
  const entry = registry.get(did)
  if (!entry) return c.json({ error: 'Not found' }, 404)

  const { mode } = await c.req.json<{ mode: 'public' | 'private' }>()
  if (mode !== 'public' && mode !== 'private') {
    return c.json({ error: 'mode must be public or private' }, 400)
  }

  entry.mode = mode
  entry.updatedAt = new Date().toISOString()
  saveRegistry(registry)

  return c.json({ success: true, mode })
})

/**
 * Update metadata.
 */
app.patch('/v1/cards/:did/metadata', async (c) => {
  const did = c.req.param('did')
  const entry = registry.get(did)
  if (!entry) return c.json({ error: 'Not found' }, 404)

  const metadata = await c.req.json()
  entry.metadata = { ...entry.metadata, ...metadata }
  entry.updatedAt = new Date().toISOString()
  saveRegistry(registry)

  return c.json({ success: true })
})

/**
 * Get registry stats.
 */
app.get('/v1/stats', (c) => {
  let publicCount = 0
  let privateCount = 0
  for (const entry of registry.values()) {
    if (entry.mode === 'public') publicCount++
    else privateCount++
  }
  return c.json({ total: registry.size, public: publicCount, private: privateCount })
})

export { app }

// Start server only when not imported as module
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.REGISTRY_PORT || '7346', 10)

  let inFlightRequests = 0
  let isShuttingDown = false

  const originalFetch = app.fetch
  const wrappedFetch: typeof originalFetch = async (req, ...args) => {
    if (isShuttingDown) {
      return new Response(JSON.stringify({ error: 'Service shutting down' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    inFlightRequests++
    try {
      return await originalFetch.call(app, req, ...args)
    } finally {
      inFlightRequests--
    }
  }

  console.log(`FIDES Registry starting on port ${port}`)

  const server = serve({
    fetch: wrappedFetch,
    port,
  })

  const shutdown = async () => {
    if (isShuttingDown) return
    isShuttingDown = true
    console.log('Shutting down registry service...')

    const deadline = Date.now() + 10_000
    while (inFlightRequests > 0 && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 100))
    }

    if (inFlightRequests > 0) {
      console.warn(`Force closing with ${inFlightRequests} in-flight requests`)
    }

    server.close()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}
