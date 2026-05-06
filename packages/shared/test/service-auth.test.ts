import { describe, expect, it } from 'vitest'
import { evaluateApiKeyAuth, parseScopedApiKeys } from '../src/service-auth.js'

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

  it('accepts scoped API keys when they include the required scope', () => {
    expect(evaluateApiKeyAuth({
      configuredKeys: [
        { key: 'topology-key', scopes: ['platform:topology:read'] },
        { key: 'trust-key', scopes: ['platform:trust-anchors:write'] },
      ],
      providedKey: 'trust-key',
      nodeEnv: 'production',
      productionRequirement: 'trust-anchor governance',
      requiredScope: 'platform:trust-anchors:write',
    })).toEqual({ ok: true })
  })

  it('rejects scoped API keys missing the required scope', () => {
    expect(evaluateApiKeyAuth({
      configuredKeys: [
        { key: 'topology-key', scopes: ['platform:topology:read'] },
      ],
      providedKey: 'topology-key',
      nodeEnv: 'production',
      productionRequirement: 'trust-anchor governance',
      requiredScope: 'platform:trust-anchors:write',
    })).toEqual({
      ok: false,
      status: 403,
      error: 'Forbidden - API key is missing required scope platform:trust-anchors:write',
    })
  })

  it('keeps legacy SERVICE_API_KEY as full access when scoped keys are absent', () => {
    expect(evaluateApiKeyAuth({
      configuredKey: 'legacy-key',
      providedKey: 'legacy-key',
      nodeEnv: 'production',
      productionRequirement: 'trust-anchor governance',
      requiredScope: 'platform:trust-anchors:write',
    })).toEqual({ ok: true })
  })

  it('parses scoped API keys from JSON env values', () => {
    expect(parseScopedApiKeys(JSON.stringify([
      { key: ' operator-key ', scopes: ['agentd:evidence:write', 'agentd:evidence:write', ' * '] },
    ]), 'AGENTD_API_KEYS')).toEqual({
      ok: true,
      value: [{ key: 'operator-key', scopes: ['*', 'agentd:evidence:write'] }],
    })
  })

  it('rejects malformed scoped API key JSON', () => {
    expect(parseScopedApiKeys('{bad-json', 'AGENTD_API_KEYS')).toEqual({
      ok: false,
      error: 'AGENTD_API_KEYS must be a JSON array of scoped API keys',
    })
  })
})
