import { evaluateApiKeyAuth, parseScopedApiKeys } from '@fides/shared'
import type { MiddlewareHandler } from 'hono'

const AGENTD_API_SCOPES = {
  policyEvaluate: 'agentd:policy:evaluate',
  sessionsWrite: 'agentd:sessions:write',
  authorityWrite: 'agentd:authority:write',
  authorizeWrite: 'agentd:authorize:write',
  evidenceWrite: 'agentd:evidence:write',
  attestWrite: 'agentd:attest:write',
  killSwitchWrite: 'agentd:killswitch:write',
  write: 'agentd:write',
} as const

export const apiKeyAuth = (requiredScope: string = AGENTD_API_SCOPES.write): MiddlewareHandler => {
  return async (c, next) => {
    const scopedKeys = parseScopedApiKeys(process.env.AGENTD_API_KEYS, 'AGENTD_API_KEYS')
    if (!scopedKeys.ok) {
      return c.json({ error: scopedKeys.error }, 503)
    }

    const decision = evaluateApiKeyAuth({
      configuredKey: process.env.SERVICE_API_KEY,
      configuredKeys: scopedKeys.value,
      providedKey: c.req.header('X-API-Key'),
      nodeEnv: process.env.NODE_ENV,
      productionRequirement: 'mutating endpoints',
      requiredScope,
    })
    if (!decision.ok) {
      return c.json({ error: decision.error }, decision.status)
    }

    return next()
  }
}

export function agentdScopeForRequest(method: string, path: string): string {
  if (method !== 'POST' && method !== 'PUT' && method !== 'PATCH' && method !== 'DELETE') {
    return AGENTD_API_SCOPES.write
  }
  if (path === '/v1/policy/evaluate') return AGENTD_API_SCOPES.policyEvaluate
  if (path === '/v1/sessions' || /^\/v1\/sessions\/[^/]+\/revoke$/.test(path)) {
    return AGENTD_API_SCOPES.sessionsWrite
  }
  if (path === '/v1/revocations' || path === '/v1/incidents' || path === '/v1/authority/propagations/retry') {
    return AGENTD_API_SCOPES.authorityWrite
  }
  if (path === '/v1/authorize') return AGENTD_API_SCOPES.authorizeWrite
  if (path === '/v1/evidence' || path === '/evidence/verify' || path === '/evidence/export') return AGENTD_API_SCOPES.evidenceWrite
  if (path === '/v1/attest') return AGENTD_API_SCOPES.attestWrite
  if (path === '/v1/killswitch/engage' || path === '/v1/killswitch/disengage') {
    return AGENTD_API_SCOPES.killSwitchWrite
  }
  if (path === '/dht/publish' || path === '/dht/start' || path === '/demo/run' || path === '/simulate/adversarial') {
    return AGENTD_API_SCOPES.write
  }
  return AGENTD_API_SCOPES.write
}
