import { describe, expect, it } from 'vitest'
import { evaluateApiKeyAuth } from '../src/service-auth.js'

describe('evaluateApiKeyAuth', () => {
  it('allows unconfigured API keys outside production', () => {
    expect(evaluateApiKeyAuth({
      nodeEnv: 'test',
      productionRequirement: 'mutating endpoints',
    })).toEqual({ ok: true })
  })

  it('fails closed when production does not configure an API key', () => {
    expect(evaluateApiKeyAuth({
      nodeEnv: 'production',
      productionRequirement: 'policy evaluation',
    })).toEqual({
      ok: false,
      status: 503,
      error: 'SERVICE_API_KEY is required in production for policy evaluation',
    })
  })

  it('rejects missing or invalid keys when configured', () => {
    expect(evaluateApiKeyAuth({
      configuredKey: 'expected-key',
      providedKey: 'wrong-key',
      nodeEnv: 'production',
      productionRequirement: 'topology metadata',
    })).toEqual({
      ok: false,
      status: 401,
      error: 'Unauthorized - invalid or missing API key',
    })
  })

  it('accepts matching keys when configured', () => {
    expect(evaluateApiKeyAuth({
      configuredKey: 'expected-key',
      providedKey: 'expected-key',
      nodeEnv: 'production',
      productionRequirement: 'topology metadata',
    })).toEqual({ ok: true })
  })
})
