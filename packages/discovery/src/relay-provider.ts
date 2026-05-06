import { validateAgentCard, type AgentCard, type SignedAgentCard } from '@fides/core'
import { DiscoveryProvider } from './provider.js'

interface RelayMessage {
  id: string
  to: string
  from: string
  payload: unknown
  status: 'pending' | 'delivered' | 'expired'
  createdAt: string
  expiresAt: string
  deliveredAt?: string
}

interface RelayPollResponse {
  messages: RelayMessage[]
  count: number
}

interface RelayDiscoveryPayload {
  type?: string
  card?: unknown
}

/**
 * RelayDiscoveryProvider resolves AgentCards via a relay server.
 */
export class RelayDiscoveryProvider implements DiscoveryProvider {
  readonly name = 'relay'

  constructor(private options: { relayUrl: string; apiKey?: string; from?: string }) {}

  async resolve(did: string): Promise<AgentCard | null> {
    try {
      const response = await fetch(`${this.baseUrl()}/v1/relay/${encodeURIComponent(did)}/messages`)
      if (!response.ok) return null

      const body = await response.json() as RelayPollResponse
      for (const message of body.messages ?? []) {
        const card = this.extractCard(message.payload)
        if (card?.id === did && card.identity.did === did) {
          return card
        }
      }
    } catch {
      return null
    }

    return null
  }

  async register(card: SignedAgentCard): Promise<void> {
    const did = card.payload.id
    const response = await fetch(`${this.baseUrl()}/v1/relay`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({
        to: did,
        from: this.options.from ?? 'fides-discovery',
        payload: {
          type: 'fides.agent_card',
          card: card.payload,
        },
      }),
    })

    if (!response.ok) {
      throw new Error(`Relay registration failed: ${response.status}`)
    }
  }

  private extractCard(payload: unknown): AgentCard | null {
    const candidate = this.unwrapPayload(payload)
    if (!candidate) return null

    const result = validateAgentCard(candidate)
    return result.valid ? candidate : null
  }

  private unwrapPayload(payload: unknown): AgentCard | null {
    if (!payload || typeof payload !== 'object') return null

    if ('card' in payload) {
      return this.unwrapPayload((payload as RelayDiscoveryPayload).card)
    }

    if ('payload' in payload && typeof (payload as { payload?: unknown }).payload === 'object') {
      return this.unwrapPayload((payload as { payload: unknown }).payload)
    }

    return payload as AgentCard
  }

  private headers(): Headers {
    const headers = new Headers({ 'Content-Type': 'application/json' })
    if (this.options.apiKey) {
      headers.set('X-API-Key', this.options.apiKey)
    }
    return headers
  }

  private baseUrl(): string {
    return this.options.relayUrl.replace(/\/+$/, '')
  }
}
