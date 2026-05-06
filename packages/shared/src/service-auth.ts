import { timingSafeStringEqual } from './security.js'

export interface ApiKeyAuthOptions {
  configuredKey?: string
  configuredKeys?: ScopedApiKey[]
  providedKey?: string
  nodeEnv?: string
  productionRequirement: string
  requiredScope?: string
}

export type ApiKeyAuthDecision =
  | { ok: true }
  | { ok: false; status: 401 | 403 | 503; error: string }

export interface ScopedApiKey {
  key: string
  scopes: string[]
}

export function evaluateApiKeyAuth(options: ApiKeyAuthOptions): ApiKeyAuthDecision {
  const scopedKeys = options.configuredKeys?.filter(entry => entry.key.length > 0) ?? []
  if (scopedKeys.length > 0) {
    if (!options.providedKey) {
      return { ok: false, status: 401, error: 'Unauthorized - invalid or missing API key' }
    }

    const matched = scopedKeys.find(entry => timingSafeStringEqual(options.providedKey!, entry.key))
    if (!matched) {
      return { ok: false, status: 401, error: 'Unauthorized - invalid or missing API key' }
    }
    if (options.requiredScope && !hasScope(matched.scopes, options.requiredScope)) {
      return {
        ok: false,
        status: 403,
        error: `Forbidden - API key is missing required scope ${options.requiredScope}`,
      }
    }
    return { ok: true }
  }

  if (!options.configuredKey) {
    if (options.nodeEnv === 'production') {
      return {
        ok: false,
        status: 503,
        error: `SERVICE_API_KEY is required in production for ${options.productionRequirement}`,
      }
    }
    return { ok: true }
  }

  if (!options.providedKey || !timingSafeStringEqual(options.providedKey, options.configuredKey)) {
    return { ok: false, status: 401, error: 'Unauthorized - invalid or missing API key' }
  }

  return { ok: true }
}

function hasScope(scopes: string[], requiredScope: string): boolean {
  return scopes.includes('*') || scopes.includes(requiredScope)
}
