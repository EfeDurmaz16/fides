import { timingSafeStringEqual } from './security.js'

export interface ApiKeyAuthOptions {
  configuredKey?: string
  providedKey?: string
  nodeEnv?: string
  productionRequirement: string
}

export type ApiKeyAuthDecision =
  | { ok: true }
  | { ok: false; status: 401 | 503; error: string }

export function evaluateApiKeyAuth(options: ApiKeyAuthOptions): ApiKeyAuthDecision {
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
