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

export type ScopedApiKeyParseResult =
  | { ok: true; value?: ScopedApiKey[] }
  | { ok: false; error: string }

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

export function parseScopedApiKeys(raw: string | undefined, envName: string): ScopedApiKeyParseResult {
  if (raw === undefined || raw.trim().length === 0) {
    return { ok: true, value: undefined }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return { ok: false, error: `${envName} must be a JSON array of scoped API keys` }
  }

  if (!Array.isArray(parsed)) {
    return { ok: false, error: `${envName} must be a JSON array of scoped API keys` }
  }

  const keys: ScopedApiKey[] = []
  for (const entry of parsed) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      return { ok: false, error: `${envName} entries must include a non-empty key and scopes array` }
    }
    const candidate = entry as { key?: unknown; scopes?: unknown }
    if (typeof candidate.key !== 'string' || candidate.key.trim().length === 0) {
      return { ok: false, error: `${envName} entries must include a non-empty key and scopes array` }
    }
    if (!Array.isArray(candidate.scopes) || candidate.scopes.length === 0) {
      return { ok: false, error: `${envName} entries must include a non-empty key and scopes array` }
    }
    if (candidate.scopes.some(scope => typeof scope !== 'string' || scope.trim().length === 0)) {
      return { ok: false, error: `${envName} scopes must be non-empty strings` }
    }

    keys.push({
      key: candidate.key.trim(),
      scopes: [...new Set(candidate.scopes.map(scope => scope.trim()))].sort(),
    })
  }

  if (keys.length === 0) {
    return { ok: false, error: `${envName} must contain at least one scoped API key` }
  }

  return { ok: true, value: keys }
}
