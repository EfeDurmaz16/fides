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
      registry: 'http://localhost:3400',
      relay: 'http://localhost:3500',
      agentd: 'http://localhost:7345',
    })
  })
})
