import { Hono } from 'hono'
import { eq, sql, and } from 'drizzle-orm'
import { db } from '../db/client.js'
import { agents, identities } from '../db/schema.js'
import { DID_PREFIX, ALGORITHM } from '@fides/shared'
import type { RegisterAgentRequest, AgentResponse } from '../types.js'

const agentsRouter = new Hono()

function toAgentResponse(agent: typeof agents.$inferSelect, identity: typeof identities.$inferSelect): AgentResponse {
  return {
    did: agent.did,
    name: agent.name,
    description: agent.description,
    url: agent.url,
    version: agent.version,
    publicKey: identity.publicKey,
    algorithm: ALGORITHM,
    provider: agent.provider,
    capabilities: agent.capabilities as Record<string, unknown>,
    skills: agent.skills as Array<Record<string, unknown>>,
    defaultInputModes: agent.defaultInputModes as string[] | null,
    defaultOutputModes: agent.defaultOutputModes as string[] | null,
    status: agent.status,
    heartbeatAt: agent.heartbeatAt.toISOString(),
    createdAt: agent.createdAt.toISOString(),
    updatedAt: agent.updatedAt.toISOString(),
  }
}

// GET /agents - Search agents by capability, status, tag, provider
agentsRouter.get('/', async (c) => {
  try {
    const capability = c.req.query('capability')
    const status = c.req.query('status')
    const tag = c.req.query('tag')
    const provider = c.req.query('provider')
    const limit = Math.min(parseInt(c.req.query('limit') || '50', 10), 100)
    const offset = parseInt(c.req.query('offset') || '0', 10)

    const conditions = []

    if (status) {
      conditions.push(eq(agents.status, status))
    }

    if (capability) {
      // Search skills by id matching
      conditions.push(
        sql`EXISTS (SELECT 1 FROM jsonb_array_elements(${agents.skills}) AS s WHERE s->>'id' = ${capability})`
      )
    }

    if (tag) {
      // Search skills by tag
      conditions.push(
        sql`EXISTS (SELECT 1 FROM jsonb_array_elements(${agents.skills}) AS s, jsonb_array_elements_text(COALESCE(s->'tags', '[]'::jsonb)) AS t WHERE t = ${tag})`
      )
    }

    if (provider) {
      conditions.push(
        sql`${agents.provider}->>'organization' = ${provider}`
      )
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined

    const results = await db
      .select()
      .from(agents)
      .innerJoin(identities, eq(agents.did, identities.did))
      .where(whereClause)
      .limit(limit)
      .offset(offset)

    const response = results.map(({ agents: agent, identities: identity }) =>
      toAgentResponse(agent, identity)
    )

    c.header('Cache-Control', 'public, max-age=30')
    return c.json(response)
  } catch (error) {
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// POST /agents - Register an agent with capabilities
agentsRouter.post('/', async (c) => {
  try {
    const body = await c.req.json<RegisterAgentRequest>()

    if (!body.did || !body.name || !body.url) {
      return c.json({ error: 'Missing required fields: did, name, url' }, 400)
    }

    if (!body.did.startsWith(DID_PREFIX)) {
      return c.json({ error: `Invalid DID format. Must start with ${DID_PREFIX}` }, 400)
    }

    // Verify identity exists
    const [identity] = await db.select().from(identities).where(eq(identities.did, body.did))
    if (!identity) {
      return c.json({ error: 'Identity not found. Register identity first via POST /identities' }, 404)
    }

    const now = new Date()
    const [agent] = await db.insert(agents).values({
      did: body.did,
      name: body.name,
      description: body.description || null,
      url: body.url,
      version: body.version || '1.0.0',
      provider: body.provider || null,
      capabilities: body.capabilities || {},
      skills: body.skills || [],
      defaultInputModes: body.defaultInputModes || [],
      defaultOutputModes: body.defaultOutputModes || [],
      status: 'online',
      heartbeatAt: now,
      createdAt: now,
      updatedAt: now,
    }).returning()

    c.header('Cache-Control', 'no-store')
    return c.json(toAgentResponse(agent, identity), 201)
  } catch (error) {
    if (error instanceof Error && error.message.includes('duplicate key')) {
      return c.json({ error: 'Agent already registered' }, 409)
    }
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /agents/:did - Get agent by DID
agentsRouter.get('/:did', async (c) => {
  try {
    const did = c.req.param('did')

    const results = await db
      .select()
      .from(agents)
      .innerJoin(identities, eq(agents.did, identities.did))
      .where(eq(agents.did, did))

    if (results.length === 0) {
      return c.json({ error: 'Agent not found' }, 404)
    }

    const { agents: agent, identities: identity } = results[0]
    c.header('Cache-Control', 'public, max-age=60')
    return c.json(toAgentResponse(agent, identity))
  } catch (error) {
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// PUT /agents/:did - Update agent registration
agentsRouter.put('/:did', async (c) => {
  try {
    const did = c.req.param('did')
    const body = await c.req.json<Partial<RegisterAgentRequest>>()

    const updateData: Record<string, unknown> = { updatedAt: new Date() }
    if (body.name !== undefined) updateData.name = body.name
    if (body.description !== undefined) updateData.description = body.description
    if (body.url !== undefined) updateData.url = body.url
    if (body.version !== undefined) updateData.version = body.version
    if (body.provider !== undefined) updateData.provider = body.provider
    if (body.capabilities !== undefined) updateData.capabilities = body.capabilities
    if (body.skills !== undefined) updateData.skills = body.skills
    if (body.defaultInputModes !== undefined) updateData.defaultInputModes = body.defaultInputModes
    if (body.defaultOutputModes !== undefined) updateData.defaultOutputModes = body.defaultOutputModes

    const [updated] = await db
      .update(agents)
      .set(updateData)
      .where(eq(agents.did, did))
      .returning()

    if (!updated) {
      return c.json({ error: 'Agent not found' }, 404)
    }

    const [identity] = await db.select().from(identities).where(eq(identities.did, did))
    c.header('Cache-Control', 'no-store')
    return c.json(toAgentResponse(updated, identity))
  } catch (error) {
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// DELETE /agents/:did - Deregister agent
agentsRouter.delete('/:did', async (c) => {
  try {
    const did = c.req.param('did')

    const [deleted] = await db
      .delete(agents)
      .where(eq(agents.did, did))
      .returning()

    if (!deleted) {
      return c.json({ error: 'Agent not found' }, 404)
    }

    return c.json({ message: 'Agent deregistered' })
  } catch (error) {
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default agentsRouter
