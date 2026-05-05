import type { AgentCard, SignedAgentCard } from '@fides/core'
import { DiscoveryProvider } from './provider.js'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'

/**
 * LocalDiscoveryProvider discovers agents via a local file store.
 *
 * Agents can register their AgentCard to a local file, and this
 * provider reads from that file to resolve DIDs.
 *
 * File location: ~/.fides/local-agents.json
 */
export class LocalDiscoveryProvider implements DiscoveryProvider {
  readonly name = 'local'
  private storePath: string

  constructor(options?: { storePath?: string }) {
    this.storePath = options?.storePath || join(homedir(), '.fides', 'local-agents.json')
  }

  async resolve(did: string): Promise<AgentCard | null> {
    const store = this.loadStore()
    return store.get(did) || null
  }

  async register(card: SignedAgentCard): Promise<void> {
    const store = this.loadStore()
    const did = card.payload.id
    store.set(did, card.payload as AgentCard)
    this.saveStore(store)
  }

  async deregister(did: string): Promise<void> {
    const store = this.loadStore()
    store.delete(did)
    this.saveStore(store)
  }

  /**
   * Register an AgentCard directly (without SignedAgentCard wrapper).
   */
  registerCard(card: AgentCard): void {
    const store = this.loadStore()
    store.set(card.id, card)
    this.saveStore(store)
  }

  /**
   * List all locally registered agents.
   */
  list(): AgentCard[] {
    const store = this.loadStore()
    return Array.from(store.values())
  }

  private loadStore(): Map<string, AgentCard> {
    if (!existsSync(this.storePath)) {
      return new Map()
    }
    const data = JSON.parse(readFileSync(this.storePath, 'utf-8'))
    return new Map(Object.entries(data)) as Map<string, AgentCard>
  }

  private saveStore(store: Map<string, AgentCard>): void {
    const dir = join(homedir(), '.fides')
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true })
    }
    const obj: Record<string, AgentCard> = {}
    for (const [did, card] of store) {
      obj[did] = card
    }
    writeFileSync(this.storePath, JSON.stringify(obj, null, 2))
  }
}
