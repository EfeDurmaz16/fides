import { evaluateApiKeyAuth, parseScopedApiKeys } from '@fides/shared'
import type { MiddlewareHandler } from 'hono'

const RELAY_API_SCOPES = {
  messagesSubmit: 'relay:messages:submit',
  messagesDelete: 'relay:messages:delete',
  write: 'relay:write',
} as const

export const apiKeyAuth = (requiredScope: string = RELAY_API_SCOPES.write): MiddlewareHandler => {
  return async (c, next) => {
    const scopedKeys = parseScopedApiKeys(process.env.RELAY_API_KEYS, 'RELAY_API_KEYS')
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

export function relayScopeForRequest(method: string, path: string): string {
  if (method === 'POST' && path === '/v1/relay') return RELAY_API_SCOPES.messagesSubmit
  if (method === 'DELETE' && /^\/v1\/relay\/[^/]+$/.test(path)) return RELAY_API_SCOPES.messagesDelete
  return RELAY_API_SCOPES.write
}
