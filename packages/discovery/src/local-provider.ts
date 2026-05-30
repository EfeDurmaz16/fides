import {
  cardSupportsCapability,
  createDiscoveryCandidate,
  verifySignedAgentCardIdentity,
  type AgentCard,
  type DiscoveryCandidate,
  type DiscoveryQuery,
  type SignedAgentCard,
} from '@fides/core'
import { DiscoveryProvider } from './provider.js'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'

interface LocalAgentRecord {
  card: AgentCard
  signedCard?: SignedAgentCard
}

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
    const record = store.get(did)
    if (!record) return null
    return (await this.resolveRecord(record)).card
  }

  async discover(query: DiscoveryQuery): Promise<DiscoveryCandidate[]> {
    const records = await this.listResolvedRecords()
    return records
      .filter(record => cardSupportsCapability(record.card, query.capability))
      .map((record, index) => createDiscoveryCandidate({
        provider: this.name,
        card: record.card,
        capability: query.capability,
        verified: record.verified,
        rank: 100 - index,
        explanations: [
          query.capability
            ? `Local AgentCard advertises ${query.capability}`
            : 'Local AgentCard matched discovery query',
        ],
      }))
      .slice(0, query.limit ?? Number.POSITIVE_INFINITY)
  }

  async register(card: SignedAgentCard): Promise<void> {
    if (!await verifySignedAgentCardIdentity(card)) {
      throw new Error('Local registration requires an identity-bound signed AgentCard')
    }
    const store = this.loadStore()
    const did = card.payload.id
    store.set(did, { card: card.payload as AgentCard, signedCard: card })
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
    store.set(card.id, { card })
    this.saveStore(store)
  }

  /**
   * List all locally registered agents.
   */
  list(): AgentCard[] {
    const store = this.loadStore()
    return Array.from(store.values()).map(record => record.card)
  }

  private async listResolvedRecords(): Promise<Array<LocalAgentRecord & { verified: boolean }>> {
    const records: Array<LocalAgentRecord & { verified: boolean }> = []
    for (const record of this.loadStore().values()) {
      records.push(await this.resolveRecord(record))
    }
    return records
  }

  private async resolveRecord(record: LocalAgentRecord): Promise<LocalAgentRecord & { verified: boolean }> {
    if (record.signedCard && await verifySignedAgentCardIdentity(record.signedCard)) {
      return {
        card: record.signedCard.payload as AgentCard,
        signedCard: record.signedCard,
        verified: true,
      }
    }
    return { card: record.card, verified: false }
  }

  private loadStore(): Map<string, LocalAgentRecord> {
    if (!existsSync(this.storePath)) {
      return new Map()
    }
    try {
      const raw = readFileSync(this.storePath, 'utf-8')
      const data = JSON.parse(raw, (key, value) => {
        // Reconstruct Uint8Array from base64
        if (value && value.type === 'Buffer' && Array.isArray(value.data)) {
          return new Uint8Array(value.data)
        }
        return value
      })
      const map = new Map<string, LocalAgentRecord>()
      for (const [did, value] of Object.entries(data)) {
        map.set(did, normalizeLocalAgentRecord(value))
      }
      return map
    } catch {
      return new Map()
    }
  }

  private saveStore(store: Map<string, LocalAgentRecord>): void {
    const dir = join(homedir(), '.fides')
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true })
    }
    const obj: Record<string, unknown> = {}
    for (const [did, record] of store) {
      // Convert Uint8Array to JSON-safe format
      const serialized = JSON.parse(JSON.stringify(record, (key, value) => {
        if (value instanceof Uint8Array) {
          return { type: 'Buffer', data: Array.from(value) }
        }
        return value
      }))
      obj[did] = serialized
    }
    writeFileSync(this.storePath, JSON.stringify(obj, null, 2))
  }
}

function normalizeLocalAgentRecord(value: unknown): LocalAgentRecord {
  if (value && typeof value === 'object' && 'card' in value) {
    const record = value as Partial<LocalAgentRecord>
    return {
      card: record.card as AgentCard,
      ...(record.signedCard !== undefined && { signedCard: record.signedCard as SignedAgentCard }),
    }
  }
  return { card: value as AgentCard }
}
