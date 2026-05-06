export interface RegistryClientOptions {
  baseUrl: string
  apiKey?: string
}

export type RegistryMode = 'public' | 'private'

export interface AgentCard {
  id?: string
  payload?: { id?: string; [key: string]: unknown }
  name?: string
  version?: string
  capabilities?: unknown[]
  protocols?: string[]
  endpoints?: unknown[]
  security?: Record<string, unknown>
  metadata?: Record<string, unknown>
  [key: string]: unknown
}

export interface RegistryRegisterResponse {
  success: boolean
  did: string
  registeredAt: string
}

export interface RegistrySearchResult {
  did: string
  name?: string
  capabilities?: string[]
}

export interface RegistrySearchResponse {
  results: RegistrySearchResult[]
  count: number
  query: string
}

export interface RegistryStatsResponse {
  total: number
  public: number
  private: number
}

export interface RegistryModeResponse {
  success: boolean
  mode: RegistryMode
}

export interface RegistryMutationResponse {
  success: boolean
}

export class RegistryError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly payload?: unknown
  ) {
    super(message)
    this.name = 'RegistryError'
  }
}

export class RegistryClient {
  constructor(private options: RegistryClientOptions) {}

  async register(card: AgentCard): Promise<RegistryRegisterResponse> {
    return this.request<RegistryRegisterResponse>('/v1/cards', {
      method: 'POST',
      body: JSON.stringify(card),
    })
  }

  async getCard(did: string): Promise<AgentCard | null> {
    return this.request<AgentCard>(`/v1/cards/${encodeURIComponent(did)}`, {
      method: 'GET',
      nullOn404: true,
    })
  }

  async search(query = ''): Promise<RegistrySearchResponse> {
    const search = query ? `?q=${encodeURIComponent(query)}` : ''
    return this.request<RegistrySearchResponse>(`/v1/search${search}`, { method: 'GET' })
  }

  async deleteCard(did: string): Promise<RegistryMutationResponse> {
    return this.request<RegistryMutationResponse>(`/v1/cards/${encodeURIComponent(did)}`, {
      method: 'DELETE',
    })
  }

  async setMode(did: string, mode: RegistryMode): Promise<RegistryModeResponse> {
    return this.request<RegistryModeResponse>(`/v1/cards/${encodeURIComponent(did)}/mode`, {
      method: 'POST',
      body: JSON.stringify({ mode }),
    })
  }

  async updateMetadata(did: string, metadata: Record<string, unknown>): Promise<RegistryMutationResponse> {
    return this.request<RegistryMutationResponse>(`/v1/cards/${encodeURIComponent(did)}/metadata`, {
      method: 'PATCH',
      body: JSON.stringify(metadata),
    })
  }

  async stats(): Promise<RegistryStatsResponse> {
    return this.request<RegistryStatsResponse>('/v1/stats', { method: 'GET' })
  }

  private async request<T>(
    path: string,
    init: RequestInit & { nullOn404?: false }
  ): Promise<T>
  private async request<T>(
    path: string,
    init: RequestInit & { nullOn404: true }
  ): Promise<T | null>
  private async request<T>(
    path: string,
    init: RequestInit & { nullOn404?: boolean }
  ): Promise<T | null> {
    const headers = new Headers(init.headers)
    if (init.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json')
    }
    if (this.options.apiKey) {
      headers.set('X-API-Key', this.options.apiKey)
    }

    let response: Response
    try {
      response = await fetch(`${this.baseUrl()}${path}`, {
        ...init,
        headers,
      })
    } catch (error) {
      throw new RegistryError(`Registry request failed: ${error instanceof Error ? error.message : String(error)}`)
    }

    const text = await response.text()
    const payload = text ? parseJson(text) : undefined

    if (response.status === 404 && init.nullOn404) {
      return null
    }

    if (!response.ok) {
      const message = typeof payload === 'object' && payload && 'error' in payload
        ? String((payload as { error: unknown }).error)
        : text
      throw new RegistryError(`Registry request failed: ${response.status} ${message}`, response.status, payload)
    }

    return payload as T
  }

  private baseUrl(): string {
    return this.options.baseUrl.replace(/\/+$/, '')
  }
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}
