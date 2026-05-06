import { evaluateApiKeyAuth, parseScopedApiKeys } from '@fides/shared'
import type { MiddlewareHandler } from 'hono'

export const DISCOVERY_API_SCOPES = {
  identitiesRegister: 'discovery:identities:register',
  identitiesDomainVerify: 'discovery:identities:domain:verify',
  identitiesOrganizationDomainVerify: 'discovery:identities:organization-domain:verify',
  agentsRegister: 'discovery:agents:register',
  agentsUpdate: 'discovery:agents:update',
  agentsHeartbeat: 'discovery:agents:heartbeat',
  agentsDelete: 'discovery:agents:delete',
  write: 'discovery:write',
} as const

export const apiKeyAuth = (requiredScope: string = DISCOVERY_API_SCOPES.write): MiddlewareHandler => {
  return async (c, next) => {
    const scopedKeys = parseScopedApiKeys(process.env.DISCOVERY_API_KEYS, 'DISCOVERY_API_KEYS')
    if (!scopedKeys.ok) {
      return c.json({ error: scopedKeys.error }, 503)
    }

    const decision = evaluateApiKeyAuth({
      configuredKey: process.env.SERVICE_API_KEY,
      configuredKeys: scopedKeys.value,
      providedKey: c.req.header('X-API-Key'),
      nodeEnv: process.env.NODE_ENV,
      productionRequirement: 'discovery writes',
      requiredScope,
    })
    if (!decision.ok) {
      return c.json({ error: decision.error }, decision.status)
    }

    return next()
  }
}

export function discoveryScopeForRequest(method: string, path: string): string {
  if (method === 'POST' && path === '/identities') return DISCOVERY_API_SCOPES.identitiesRegister
  if (method === 'POST' && /^\/identities\/[^/]+\/domain\/verify$/.test(path)) {
    return DISCOVERY_API_SCOPES.identitiesDomainVerify
  }
  if (method === 'POST' && /^\/identities\/[^/]+\/organization-domain\/verify$/.test(path)) {
    return DISCOVERY_API_SCOPES.identitiesOrganizationDomainVerify
  }
  if (method === 'POST' && path === '/agents') return DISCOVERY_API_SCOPES.agentsRegister
  if (method === 'PUT' && /^\/agents\/[^/]+$/.test(path)) return DISCOVERY_API_SCOPES.agentsUpdate
  if (method === 'PUT' && /^\/agents\/[^/]+\/heartbeat$/.test(path)) return DISCOVERY_API_SCOPES.agentsHeartbeat
  if (method === 'DELETE' && /^\/agents\/[^/]+$/.test(path)) return DISCOVERY_API_SCOPES.agentsDelete
  return DISCOVERY_API_SCOPES.write
}
