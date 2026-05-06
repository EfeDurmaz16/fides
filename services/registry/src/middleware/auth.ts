import { evaluateApiKeyAuth, parseScopedApiKeys } from '@fides/shared'
import type { MiddlewareHandler } from 'hono'

const REGISTRY_API_SCOPES = {
  cardsPublish: 'registry:cards:publish',
  cardsDelete: 'registry:cards:delete',
  cardsModeWrite: 'registry:cards:mode:write',
  cardsMetadataWrite: 'registry:cards:metadata:write',
  write: 'registry:write',
} as const

export const apiKeyAuth = (requiredScope: string = REGISTRY_API_SCOPES.write): MiddlewareHandler => {
  return async (c, next) => {
    const scopedKeys = parseScopedApiKeys(process.env.REGISTRY_API_KEYS, 'REGISTRY_API_KEYS')
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

export function registryScopeForRequest(method: string, path: string): string {
  if (method === 'POST' && path === '/v1/cards') return REGISTRY_API_SCOPES.cardsPublish
  if (method === 'DELETE' && /^\/v1\/cards\/[^/]+$/.test(path)) return REGISTRY_API_SCOPES.cardsDelete
  if (method === 'POST' && /^\/v1\/cards\/[^/]+\/mode$/.test(path)) return REGISTRY_API_SCOPES.cardsModeWrite
  if (method === 'PATCH' && /^\/v1\/cards\/[^/]+\/metadata$/.test(path)) return REGISTRY_API_SCOPES.cardsMetadataWrite
  return REGISTRY_API_SCOPES.write
}
