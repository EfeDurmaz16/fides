import { describe, expect, it } from 'vitest'
import { app } from '../src/index.js'

const policy = {
  id: 'payments-policy',
  version: '1.0.0',
  rules: [
    {
      id: 'deny-large-transfer',
      condition: { operator: 'gt', field: 'amount', value: 1000 },
      action: 'deny',
      explanation: 'Large transfers are blocked',
    },
    {
      id: 'approve-high-risk',
      condition: { operator: 'eq', field: 'risk', value: 'high' },
      action: 'approve-required',
      explanation: 'High-risk actions require approval',
    },
    {
      id: 'dry-run-new-merchant',
      condition: { operator: 'eq', field: 'merchantSeen', value: false },
      action: 'dry-run',
      explanation: 'New merchants start in dry-run',
    },
  ],
  defaultAction: 'allow',
}

describe('policy-engine service', () => {
  it('returns health status', async () => {
    const res = await app.request('/health')
    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.service).toBe('policy-engine')
  })

  it('allows by default when no rules match', async () => {
    const res = await app.request('/v1/policies/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policy, context: { amount: 20, risk: 'low', merchantSeen: true } }),
    })

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.decision).toBe('allow')
  })

  it('denies matching deny rules', async () => {
    const res = await app.request('/v1/policies/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policy, context: { amount: 5000 } }),
    })

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.decision).toBe('deny')
    expect(data.matchedRules).toEqual(['deny-large-transfer'])
  })

  it('returns approve-required when approval rule matches', async () => {
    const res = await app.request('/v1/policies/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policy, context: { risk: 'high' } }),
    })

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.decision).toBe('approve-required')
  })

  it('returns dry-run when dry-run rule matches', async () => {
    const res = await app.request('/v1/policies/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policy, context: { merchantSeen: false } }),
    })

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.decision).toBe('dry-run')
  })

  it('rejects invalid policy bundles', async () => {
    const res = await app.request('/v1/policies/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policy: { id: 'broken' }, context: {} }),
    })

    expect(res.status).toBe(400)
    const data = await res.json()
    expect(data.error).toBe('invalid policy bundle')
    expect(data.details).toContain('policy.rules must be an array')
  })

  it('requires an API key for policy evaluation in production', async () => {
    const previousNodeEnv = process.env.NODE_ENV
    const previousApiKey = process.env.SERVICE_API_KEY
    process.env.NODE_ENV = 'production'
    delete process.env.SERVICE_API_KEY

    try {
      const res = await app.request('/v1/policies/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ policy, context: {} }),
      })

      expect(res.status).toBe(503)
      const data = await res.json()
      expect(data.error).toContain('SERVICE_API_KEY is required')
    } finally {
      restoreEnv('NODE_ENV', previousNodeEnv)
      restoreEnv('SERVICE_API_KEY', previousApiKey)
    }
  })

  it('rejects invalid API keys when policy auth is configured', async () => {
    const previousApiKey = process.env.SERVICE_API_KEY
    process.env.SERVICE_API_KEY = 'expected-key'

    try {
      const res = await app.request('/v1/policies/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'wrong-key' },
        body: JSON.stringify({ policy, context: {} }),
      })

      expect(res.status).toBe(401)
    } finally {
      restoreEnv('SERVICE_API_KEY', previousApiKey)
    }
  })

  it('accepts valid API keys when policy auth is configured', async () => {
    const previousApiKey = process.env.SERVICE_API_KEY
    process.env.SERVICE_API_KEY = 'expected-key'

    try {
      const res = await app.request('/v1/policies/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'expected-key' },
        body: JSON.stringify({ policy, context: { amount: 20 } }),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.decision).toBe('allow')
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
