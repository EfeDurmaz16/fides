export interface PlatformClientOptions {
  baseUrl: string
  apiKey?: string
}

export interface PlatformTopologyResponse {
  service: 'platform-api'
  components: {
    discovery: string
    trustGraph: string
    policyEngine: string
    registry: string
    relay: string
    agentd: string
  }
}

export interface PlatformPasskeyCredentialBinding {
  principalDid: string
  credentialId: string
  publicKey: string
  relyingPartyId: string
  signCount: number
  transports?: Array<'ble' | 'hybrid' | 'internal' | 'nfc' | 'usb'>
  backedUp?: boolean
  createdAt: string
  lastVerifiedAt?: string
}

export interface PlatformPasskeyBindingResponse {
  binding: PlatformPasskeyCredentialBinding
}

export interface PlatformPasskeyCredentialDescriptor {
  credentialId: string
  relyingPartyId: string
  signCount: number
  transports?: PlatformPasskeyCredentialBinding['transports']
  backedUp?: boolean
  createdAt: string
  lastVerifiedAt?: string
}

export interface PlatformPasskeyCredentialsResponse {
  principalDid: string
  credentials: PlatformPasskeyCredentialDescriptor[]
  count: number
}

export interface PlatformMutationResponse {
  success: boolean
}

export class PlatformError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly payload?: unknown
  ) {
    super(message)
    this.name = 'PlatformError'
  }
}

export class PlatformClient {
  constructor(private options: PlatformClientOptions) {}

  async topology(): Promise<PlatformTopologyResponse> {
    return this.request<PlatformTopologyResponse>('/v1/topology', { method: 'GET' })
  }

  async storePasskeyBinding(binding: PlatformPasskeyCredentialBinding): Promise<PlatformPasskeyBindingResponse> {
    return this.request<PlatformPasskeyBindingResponse>('/v1/passkeys/bindings', {
      method: 'POST',
      body: JSON.stringify(binding),
    })
  }

  async listPasskeyCredentials(principalDid: string): Promise<PlatformPasskeyCredentialsResponse> {
    return this.request<PlatformPasskeyCredentialsResponse>(
      `/v1/passkeys/principals/${encodeURIComponent(principalDid)}/credentials`,
      { method: 'GET' }
    )
  }

  async getPasskeyBinding(credentialId: string): Promise<PlatformPasskeyCredentialBinding | null> {
    const response = await this.request<PlatformPasskeyBindingResponse>(
      `/v1/passkeys/credentials/${encodeURIComponent(credentialId)}`,
      { method: 'GET', nullOn404: true }
    )
    return response?.binding ?? null
  }

  async deletePasskeyBinding(credentialId: string): Promise<PlatformMutationResponse> {
    return this.request<PlatformMutationResponse>(
      `/v1/passkeys/credentials/${encodeURIComponent(credentialId)}`,
      { method: 'DELETE' }
    )
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
      throw new PlatformError(`Platform request failed: ${error instanceof Error ? error.message : String(error)}`)
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
      throw new PlatformError(`Platform request failed: ${response.status} ${message}`, response.status, payload)
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
