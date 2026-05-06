import { describe, expect, it } from 'vitest'
import { app } from '../src/index.js'

describe('platform-api service', () => {
  it('returns health status', async () => {
    const res = await app.request('/health')

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.status).toBe('healthy')
    expect(data.service).toBe('platform-api')
    expect(data.timestamp).toBeDefined()
  })

  it('returns version metadata', async () => {
    const res = await app.request('/v1/version')

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data).toMatchObject({
      service: 'platform-api',
      version: '0.1.0',
      protocol: 'fides-v2',
    })
  })

  it('returns default service topology', async () => {
    const res = await app.request('/v1/topology')

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.components).toMatchObject({
      discovery: 'http://localhost:3100',
      trustGraph: 'http://localhost:3200',
      policyEngine: 'http://localhost:3300',
      registry: 'http://localhost:7346',
      relay: 'http://localhost:7347',
      agentd: 'http://localhost:7345',
    })
  })

  it('requires an API key for topology metadata in production', async () => {
    const previousNodeEnv = process.env.NODE_ENV
    const previousApiKey = process.env.SERVICE_API_KEY
    process.env.NODE_ENV = 'production'
    delete process.env.SERVICE_API_KEY

    try {
      const res = await app.request('/v1/topology')

      expect(res.status).toBe(503)
      const data = await res.json()
      expect(data.error).toContain('SERVICE_API_KEY is required')
    } finally {
      restoreEnv('NODE_ENV', previousNodeEnv)
      restoreEnv('SERVICE_API_KEY', previousApiKey)
    }
  })

  it('rejects invalid API keys when topology auth is configured', async () => {
    const previousApiKey = process.env.SERVICE_API_KEY
    process.env.SERVICE_API_KEY = 'expected-key'

    try {
      const res = await app.request('/v1/topology', {
        headers: { 'X-API-Key': 'wrong-key' },
      })

      expect(res.status).toBe(401)
    } finally {
      restoreEnv('SERVICE_API_KEY', previousApiKey)
    }
  })

  it('accepts valid API keys when topology auth is configured', async () => {
    const previousApiKey = process.env.SERVICE_API_KEY
    process.env.SERVICE_API_KEY = 'expected-key'

    try {
      const res = await app.request('/v1/topology', {
        headers: { 'X-API-Key': 'expected-key' },
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.components.agentd).toBe('http://localhost:7345')
    } finally {
      restoreEnv('SERVICE_API_KEY', previousApiKey)
    }
  })
})

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name]
  } else {
    process.env[name] = value
  }
}
