export interface FidesClientOptions {
  daemonUrl: string
  apiKey?: string
}

export interface FidesRequestOptions {
  headers?: Record<string, string>
}

export class FidesClient {
  readonly identity = {
    createAgent: (body: Record<string, unknown> = {}) => this.post('/identities', { ...body, type: 'agent' }),
    createPublisher: (body: Record<string, unknown> = {}) => this.post('/identities', { ...body, type: 'publisher' }),
    createPrincipal: (body: Record<string, unknown> = {}) => this.post('/identities', { ...body, type: 'principal' }),
    list: () => this.get('/identities'),
    show: (id: string) => this.get(`/identities/${encodeURIComponent(id)}`),
  }

  readonly cards = {
    create: (body: Record<string, unknown>) => this.post('/agent-cards', body),
    sign: (card: { id?: string } & Record<string, unknown>) => this.post(`/agent-cards/${encodeURIComponent(String(card.id))}/sign`, card),
    verify: (id: string) => this.post(`/agent-cards/${encodeURIComponent(id)}/verify`, {}),
    get: (id: string) => this.get(`/agent-cards/${encodeURIComponent(id)}`),
  }

  readonly agents = {
    register: (card: Record<string, unknown>) => this.post('/agents/register', card),
    list: () => this.get('/agents'),
    inspect: (agentId: string) => this.get(`/agents/${encodeURIComponent(agentId)}`),
  }

  readonly discovery = {
    find: (query: Record<string, unknown>) => this.post('/discover', query),
  }

  readonly trust = {
    evaluate: (body: Record<string, unknown>) => this.post('/trust/evaluate', body),
    get: (agentId: string) => this.get(`/trust/${encodeURIComponent(agentId)}`),
  }

  readonly reputation = {
    update: (body: Record<string, unknown>) => this.post('/reputation/update', body),
    get: (agentId: string) => this.get(`/reputation/${encodeURIComponent(agentId)}`),
  }

  readonly policy = {
    evaluate: (body: Record<string, unknown>) => this.post('/policy/evaluate', body),
  }

  readonly approvals = {
    create: (body: Record<string, unknown>) => this.post('/approvals', body),
    list: () => this.get('/approvals'),
    approve: (approvalId: string, body: Record<string, unknown> = {}) => this.post(`/approvals/${encodeURIComponent(approvalId)}/approve`, body),
    deny: (approvalId: string, body: Record<string, unknown> = {}) => this.post(`/approvals/${encodeURIComponent(approvalId)}/deny`, body),
  }

  readonly killSwitch = {
    enable: (body: Record<string, unknown>) => this.post('/killswitch', body),
    list: () => this.get('/killswitch'),
    disable: (ruleId: string) => this.delete(`/killswitch/${encodeURIComponent(ruleId)}`),
  }

  readonly revocations = {
    create: (body: Record<string, unknown>) => this.post('/revocations', body),
    list: () => this.get('/revocations'),
    get: (recordId: string) => this.get(`/revocations/${encodeURIComponent(recordId)}`),
  }

  readonly incidents = {
    report: (body: Record<string, unknown>) => this.post('/incidents', body),
    list: () => this.get('/incidents'),
    get: (recordId: string) => this.get(`/incidents/${encodeURIComponent(recordId)}`),
    resolve: (recordId: string, body: Record<string, unknown> = {}) => this.post(`/incidents/${encodeURIComponent(recordId)}/resolve`, body),
  }

  readonly attestations = {
    create: (body: Record<string, unknown>) => this.post('/attestations', body),
    get: (attestationId: string) => this.get(`/attestations/${encodeURIComponent(attestationId)}`),
    verify: (attestationId: string) => this.post(`/attestations/${encodeURIComponent(attestationId)}/verify`, {}),
  }

  readonly sessions = {
    request: (body: Record<string, unknown>) => this.post('/sessions', body),
    verify: (sessionId: string) => this.post(`/sessions/${encodeURIComponent(sessionId)}/verify`, {}),
    get: (sessionId: string) => this.get(`/sessions/${encodeURIComponent(sessionId)}`),
  }

  constructor(private readonly options: FidesClientOptions) {}

  invoke(body: Record<string, unknown>): Promise<unknown> {
    return this.post('/invoke', body)
  }

  private async get(path: string): Promise<unknown> {
    return this.request(path, { method: 'GET' })
  }

  private async post(path: string, body: unknown): Promise<unknown> {
    return this.request(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  }

  private async delete(path: string): Promise<unknown> {
    return this.request(path, { method: 'DELETE' })
  }

  private async request(path: string, init: RequestInit): Promise<unknown> {
    const headers = new Headers(init.headers)
    if (this.options.apiKey) {
      headers.set('X-API-Key', this.options.apiKey)
    }

    const response = await fetch(`${this.options.daemonUrl.replace(/\/+$/, '')}${path}`, {
      ...init,
      headers,
    })
    const text = await response.text()
    const payload = text ? JSON.parse(text) : {}
    if (!response.ok) {
      throw new Error(`FIDES request failed with HTTP ${response.status}: ${JSON.stringify(payload)}`)
    }
    return payload
  }
}
