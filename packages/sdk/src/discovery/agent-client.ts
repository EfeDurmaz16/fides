import type { AgentCard, AgentCardQuery, AgentSkill, AgentCapabilities, AgentProvider } from '@fides/shared'
import { DiscoveryError, DEFAULT_AGENT_CACHE_TTL_MS } from '@fides/shared'

export interface RegisterAgentParams {
  did: string
  name: string
  description?: string
  url: string
  version?: string
  provider?: AgentProvider
  capabilities?: AgentCapabilities
  skills?: AgentSkill[]
  defaultInputModes?: string[]
  defaultOutputModes?: string[]
}

interface CacheEntry {
  agents: AgentCard[]
  timestamp: number
}

export class AgentDiscoveryClient {
  private cache: Map<string, CacheEntry> = new Map()
  private cacheTtlMs: number

  constructor(
    private options: { baseUrl: string; cacheTtlMs?: number }
  ) {
    this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_AGENT_CACHE_TTL_MS
  }

  /**
   * Register an agent with capabilities and skills
   */
  async registerAgent(params: RegisterAgentParams): Promise<AgentCard> {
    try {
      const response = await fetch(`${this.options.baseUrl}/agents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      })

      if (!response.ok) {
        const text = await response.text()
        throw new DiscoveryError(`Failed to register agent: ${response.status} ${text}`)
      }

      return await response.json()
    } catch (error) {
      if (error instanceof DiscoveryError) throw error
      throw new DiscoveryError(
        `Failed to register agent: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Discover agents by capability, status, tag, or provider
   */
  async discoverAgents(query?: AgentCardQuery): Promise<AgentCard[]> {
    const cacheKey = JSON.stringify(query || {})

    // Check cache
    const cached = this.cache.get(cacheKey)
    if (cached && Date.now() - cached.timestamp < this.cacheTtlMs) {
      return cached.agents
    }

    try {
      const params = new URLSearchParams()
      if (query?.capability) params.set('capability', query.capability)
      if (query?.status) params.set('status', query.status)
      if (query?.tag) params.set('tag', query.tag)
      if (query?.provider) params.set('provider', query.provider)
      if (query?.limit) params.set('limit', String(query.limit))
      if (query?.offset) params.set('offset', String(query.offset))

      const qs = params.toString()
      const url = `${this.options.baseUrl}/agents${qs ? `?${qs}` : ''}`
      const response = await fetch(url)

      if (!response.ok) {
        const text = await response.text()
        throw new DiscoveryError(`Failed to discover agents: ${response.status} ${text}`)
      }

      const agents: AgentCard[] = await response.json()

      // Cache result
      this.cache.set(cacheKey, { agents, timestamp: Date.now() })

      return agents
    } catch (error) {
      if (error instanceof DiscoveryError) throw error
      throw new DiscoveryError(
        `Failed to discover agents: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Get a specific agent by DID
   */
  async getAgent(did: string): Promise<AgentCard | null> {
    try {
      const response = await fetch(
        `${this.options.baseUrl}/agents/${encodeURIComponent(did)}`
      )

      if (response.status === 404) return null

      if (!response.ok) {
        const text = await response.text()
        throw new DiscoveryError(`Failed to get agent: ${response.status} ${text}`)
      }

      return await response.json()
    } catch (error) {
      if (error instanceof DiscoveryError) throw error
      throw new DiscoveryError(
        `Failed to get agent: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Update agent registration
   */
  async updateAgent(did: string, updates: Partial<RegisterAgentParams>): Promise<AgentCard> {
    try {
      const response = await fetch(
        `${this.options.baseUrl}/agents/${encodeURIComponent(did)}`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(updates),
        }
      )

      if (!response.ok) {
        const text = await response.text()
        throw new DiscoveryError(`Failed to update agent: ${response.status} ${text}`)
      }

      this.clearCache()
      return await response.json()
    } catch (error) {
      if (error instanceof DiscoveryError) throw error
      throw new DiscoveryError(
        `Failed to update agent: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Send heartbeat to keep agent online
   */
  async heartbeat(did: string): Promise<void> {
    try {
      const response = await fetch(
        `${this.options.baseUrl}/agents/${encodeURIComponent(did)}/heartbeat`,
        { method: 'PUT' }
      )

      if (!response.ok) {
        const text = await response.text()
        throw new DiscoveryError(`Heartbeat failed: ${response.status} ${text}`)
      }
    } catch (error) {
      if (error instanceof DiscoveryError) throw error
      throw new DiscoveryError(
        `Heartbeat failed: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Deregister an agent
   */
  async deregisterAgent(did: string): Promise<void> {
    try {
      const response = await fetch(
        `${this.options.baseUrl}/agents/${encodeURIComponent(did)}`,
        { method: 'DELETE' }
      )

      if (!response.ok) {
        const text = await response.text()
        throw new DiscoveryError(`Failed to deregister agent: ${response.status} ${text}`)
      }

      this.clearCache()
    } catch (error) {
      if (error instanceof DiscoveryError) throw error
      throw new DiscoveryError(
        `Failed to deregister agent: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  clearCache(): void {
    this.cache.clear()
  }
}
