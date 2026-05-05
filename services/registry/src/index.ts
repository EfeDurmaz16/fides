/**
 * FIDES v2 Registry Service
 *
 * Hosted registry for AgentCards with file-based persistence,
 * public/private mode, and search.
 */

import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'

const app = new Hono()

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

function saveRegistry(registry: Map<string, RegistryEntry>): void {
  ensureDir()
  const obj: Record<string, RegistryEntry> = {}
  for (const [did, entry] of registry) {
    obj[did] = entry
  }
  writeFileSync(REGISTRY_FILE, JSON.stringify(obj, null, 2))
}

const registry = loadRegistry()

app.get('/health', (c) => c.json({
  status: 'ok',
  service: 'registry',
  count: registry.size,
  persistent: true,
}))

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

const port = Number(process.env.REGISTRY_PORT) || 7346
serve({ fetch: app.fetch, port })
console.log(`FIDES Registry running on port ${port}`)
