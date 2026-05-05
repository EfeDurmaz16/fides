import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const ORIGINAL_SERVICE_API_KEY = process.env.SERVICE_API_KEY
const ORIGINAL_NODE_ENV = process.env.NODE_ENV

beforeEach(() => {
  delete process.env.SERVICE_API_KEY
  process.env.NODE_ENV = 'test'
})

afterEach(() => {
  if (ORIGINAL_SERVICE_API_KEY) {
    process.env.SERVICE_API_KEY = ORIGINAL_SERVICE_API_KEY
  } else {
    delete process.env.SERVICE_API_KEY
  }
  if (ORIGINAL_NODE_ENV) {
    process.env.NODE_ENV = ORIGINAL_NODE_ENV
  } else {
    delete process.env.NODE_ENV
  }
})

import { app } from '../src/index.js'

describe('Relay Service Routes', () => {
  const SENDER_DID = 'did:fides:sender01'
  const RECEIVER_DID = 'did:fides:receiver01'

  describe('GET /health', () => {
    it('returns 200 with health status', async () => {
      const res = await app.request('/health')
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.service).toBe('relay')
      expect(data.status).toBe('healthy')
      expect(data.timestamp).toBeDefined()
      expect(data.queues).toBeDefined()
      expect(data.uptime).toBeDefined()
    })
  })

  describe('POST /v1/relay', () => {
    it('fails closed in production when API key is not configured', async () => {
      process.env.NODE_ENV = 'production'
      delete process.env.SERVICE_API_KEY

      const res = await app.request('/v1/relay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: RECEIVER_DID,
          from: SENDER_DID,
          payload: { content: 'Hello from sender' },
        }),
      })
      expect(res.status).toBe(503)
      const data = await res.json()
      expect(data.error).toContain('SERVICE_API_KEY is required in production')
    })

    it('submits a message and returns 201', async () => {
      const res = await app.request('/v1/relay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: RECEIVER_DID,
          from: SENDER_DID,
          payload: { content: 'Hello from sender' },
        }),
      })
      expect(res.status).toBe(201)
      const data = await res.json()
      expect(data.accepted).toBe(true)
      expect(data.relayId).toBeDefined()
      expect(data.expiresAt).toBeDefined()
    })

    it('returns 400 when required fields are missing', async () => {
      const res = await app.request('/v1/relay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: SENDER_DID }),
      })
      expect(res.status).toBe(400)
      const data = await res.json()
      expect(data.error).toContain('to and payload are required')
    })

    it('returns 400 when to is missing', async () => {
      const res = await app.request('/v1/relay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: { test: true } }),
      })
      expect(res.status).toBe(400)
    })
  })

  describe('GET /v1/relay/:did/messages', () => {
    it('polls pending messages for a DID', async () => {
      const did = `loadtest-poller-${Date.now()}`

      const submit = await app.request('/v1/relay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: did,
          from: SENDER_DID,
          payload: { content: 'Message 1' },
        }),
      })
      expect(submit.status).toBe(201)

      const res = await app.request(`/v1/relay/${encodeURIComponent(did)}/messages`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.messages).toHaveLength(1)
      expect(data.messages[0].to).toBe(did)
      expect(data.messages[0].status).toBe('delivered')
      expect(data.messages[0].deliveredAt).toBeDefined()
    })

    it('returns empty array when no messages pending', async () => {
      const res = await app.request(`/v1/relay/${encodeURIComponent(`empty-${Date.now()}`)}/messages`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.messages).toHaveLength(0)
    })
  })

  describe('Message delivery marks as delivered', () => {
    it('message is delivered only once on poll', async () => {
      const uniqueDid = `did:fides:delivery-${Date.now()}`

      const submit = await app.request('/v1/relay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: uniqueDid,
          from: SENDER_DID,
          payload: { content: 'Deliver once' },
        }),
      })
      expect(submit.status).toBe(201)

      const first = await app.request(`/v1/relay/${encodeURIComponent(uniqueDid)}/messages`)
      const firstData = await first.json()
      expect(firstData.messages).toHaveLength(1)
      expect(firstData.messages[0].status).toBe('delivered')

      const second = await app.request(`/v1/relay/${encodeURIComponent(uniqueDid)}/messages`)
      const secondData = await second.json()
      expect(secondData.messages).toHaveLength(0)
    })
  })

  describe('GET /v1/relay/:id', () => {
    it('returns message by relay ID', async () => {
      const did = `byid-${Date.now()}`
      const submit = await app.request('/v1/relay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: did,
          from: SENDER_DID,
          payload: { content: 'By ID' },
        }),
      })
      const { relayId } = await submit.json()

      const res = await app.request(`/v1/relay/${relayId}`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.to).toBe(did)
      expect(data.payload).toEqual({ content: 'By ID' })
    })

    it('returns 404 for unknown relay ID', async () => {
      const res = await app.request('/v1/relay/nonexistent-id')
      expect(res.status).toBe(404)
      const data = await res.json()
      expect(data.error).toBe('Not found')
    })
  })

  describe('DELETE /v1/relay/:id', () => {
    it('deletes a message by relay ID', async () => {
      const did = `del-${Date.now()}`
      const submit = await app.request('/v1/relay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: did,
          from: SENDER_DID,
          payload: { content: 'Delete me' },
        }),
      })
      const { relayId } = await submit.json()

      const del = await app.request(`/v1/relay/${relayId}`, { method: 'DELETE' })
      expect(del.status).toBe(200)
      expect((await del.json()).deleted).toBe(true)

      const get = await app.request(`/v1/relay/${relayId}`)
      expect(get.status).toBe(404)
    })

    it('returns 404 for non-existent message', async () => {
      const res = await app.request('/v1/relay/nonexistent', { method: 'DELETE' })
      expect(res.status).toBe(404)
    })
  })

  describe('Message TTL expiry', () => {
    it('message with short TTL has expiry timestamp in the past', async () => {
      const did = `ttl-${Date.now()}`
      const submit = await app.request('/v1/relay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: did,
          from: SENDER_DID,
          payload: { content: 'Short lived' },
          ttlMs: 10,
        }),
      })
      const { relayId } = await submit.json()

      await new Promise(resolve => setTimeout(resolve, 50))

      const res = await app.request(`/v1/relay/${relayId}`)
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(new Date(data.expiresAt).getTime()).toBeLessThan(Date.now())
      expect(data.status).toBe('pending')
    })
  })

  describe('GET /v1/relay/stats', () => {
    it('returns relay statistics', async () => {
      const did = `stats-${Date.now()}`
      await app.request('/v1/relay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: did,
          from: SENDER_DID,
          payload: { content: 'Stats test' },
        }),
      })

      const res = await app.request('/v1/relay/stats')
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.total).toBeGreaterThanOrEqual(1)
      expect(typeof data.pending).toBe('number')
      expect(typeof data.delivered).toBe('number')
      expect(typeof data.expired).toBe('number')
      expect(typeof data.queues).toBe('number')
    })
  })
})
