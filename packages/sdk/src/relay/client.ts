export interface RelayClientOptions {
  baseUrl: string
  apiKey?: string
}

export interface RelayMessageRequest {
  to: string
  from?: string
  payload: unknown
  ttlMs?: number
}

export interface RelayAcceptResponse {
  accepted: boolean
  relayId: string
  expiresAt: string
}

export interface RelayMessage {
  id: string
  to: string
  from: string
  payload: unknown
  status: 'pending' | 'delivered' | 'expired'
  createdAt: string
  expiresAt: string
  deliveredAt?: string
}

export interface RelayPollResponse {
  messages: RelayMessage[]
  count: number
}

export interface RelayDeleteResponse {
  deleted: boolean
}

export interface RelayStatsResponse {
  total: number
  pending: number
  delivered: number
  expired: number
  queues: number
}

export class RelayError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly payload?: unknown
  ) {
    super(message)
    this.name = 'RelayError'
  }
}

export class RelayClient {
  constructor(private options: RelayClientOptions) {}

  async send(message: RelayMessageRequest): Promise<RelayAcceptResponse> {
    return this.request<RelayAcceptResponse>('/v1/relay', {
      method: 'POST',
      body: JSON.stringify(message),
    })
  }

  async poll(did: string): Promise<RelayPollResponse> {
    return this.request<RelayPollResponse>(`/v1/relay/${encodeURIComponent(did)}/messages`, {
      method: 'GET',
    })
  }

  async getMessage(relayId: string): Promise<RelayMessage> {
    return this.request<RelayMessage>(`/v1/relay/${encodeURIComponent(relayId)}`, {
      method: 'GET',
    })
  }

  async deleteMessage(relayId: string): Promise<RelayDeleteResponse> {
    return this.request<RelayDeleteResponse>(`/v1/relay/${encodeURIComponent(relayId)}`, {
      method: 'DELETE',
    })
  }

  async stats(): Promise<RelayStatsResponse> {
    return this.request<RelayStatsResponse>('/v1/relay/stats', {
      method: 'GET',
    })
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
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
      throw new RelayError(`Relay request failed: ${error instanceof Error ? error.message : String(error)}`)
    }

    const text = await response.text()
    const payload = text ? parseJson(text) : undefined

    if (!response.ok) {
      const message = typeof payload === 'object' && payload && 'error' in payload
        ? String((payload as { error: unknown }).error)
        : text
      throw new RelayError(`Relay request failed: ${response.status} ${message}`, response.status, payload)
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
