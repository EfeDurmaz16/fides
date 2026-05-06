import { mkdir, rename, writeFile } from 'node:fs/promises'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'

export const RELAY_STORE_SCHEMA_VERSION = 1

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

export interface RelayStats {
  total: number
  pending: number
  delivered: number
  expired: number
  queues: number
}

export interface RelayStore {
  readonly kind: 'memory' | 'file'
  put(message: RelayMessage): Promise<void>
  get(id: string): Promise<RelayMessage | undefined>
  delete(id: string): Promise<boolean>
  pollPending(did: string, deliveredAt: string): Promise<RelayMessage[]>
  expirePending(nowMs: number): Promise<void>
  stats(): Promise<RelayStats>
}

interface RelayStoreSnapshot {
  schemaVersion: typeof RELAY_STORE_SCHEMA_VERSION
  messages: RelayMessage[]
}

export class InMemoryRelayStore implements RelayStore {
  readonly kind = 'memory' as const
  private messages = new Map<string, RelayMessage>()

  async put(message: RelayMessage): Promise<void> {
    this.messages.set(message.id, message)
  }

  async get(id: string): Promise<RelayMessage | undefined> {
    return this.messages.get(id)
  }

  async delete(id: string): Promise<boolean> {
    return this.messages.delete(id)
  }

  async pollPending(did: string, deliveredAt: string): Promise<RelayMessage[]> {
    const pending = [...this.messages.values()]
      .filter(message => message.to === did && message.status === 'pending')
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))

    for (const message of pending) {
      message.status = 'delivered'
      message.deliveredAt = deliveredAt
      this.messages.set(message.id, message)
    }

    return pending
  }

  async expirePending(nowMs: number): Promise<void> {
    for (const message of this.messages.values()) {
      if (message.status === 'pending' && new Date(message.expiresAt).getTime() < nowMs) {
        message.status = 'expired'
        this.messages.set(message.id, message)
      }
    }
  }

  async stats(): Promise<RelayStats> {
    return relayStats([...this.messages.values()])
  }
}

export class FileRelayStore implements RelayStore {
  readonly kind = 'file' as const
  private messages = new Map<string, RelayMessage>()
  private writeQueue: Promise<void> = Promise.resolve()

  constructor(private readonly filePath: string = defaultRelayStorePath()) {
    this.messages = loadRelaySnapshot(filePath)
  }

  async put(message: RelayMessage): Promise<void> {
    this.messages.set(message.id, message)
    await this.persist()
  }

  async get(id: string): Promise<RelayMessage | undefined> {
    return this.messages.get(id)
  }

  async delete(id: string): Promise<boolean> {
    const deleted = this.messages.delete(id)
    if (deleted) {
      await this.persist()
    }
    return deleted
  }

  async pollPending(did: string, deliveredAt: string): Promise<RelayMessage[]> {
    const pending = [...this.messages.values()]
      .filter(message => message.to === did && message.status === 'pending')
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))

    for (const message of pending) {
      message.status = 'delivered'
      message.deliveredAt = deliveredAt
      this.messages.set(message.id, message)
    }

    if (pending.length > 0) {
      await this.persist()
    }

    return pending
  }

  async expirePending(nowMs: number): Promise<void> {
    let changed = false
    for (const message of this.messages.values()) {
      if (message.status === 'pending' && new Date(message.expiresAt).getTime() < nowMs) {
        message.status = 'expired'
        this.messages.set(message.id, message)
        changed = true
      }
    }
    if (changed) {
      await this.persist()
    }
  }

  async stats(): Promise<RelayStats> {
    return relayStats([...this.messages.values()])
  }

  private async persist(): Promise<void> {
    const snapshot: RelayStoreSnapshot = {
      schemaVersion: RELAY_STORE_SCHEMA_VERSION,
      messages: [...this.messages.values()],
    }
    const body = `${JSON.stringify(snapshot, null, 2)}\n`
    const tempPath = `${this.filePath}.tmp`

    const write = this.writeQueue.catch(() => undefined).then(async () => {
      await mkdir(dirname(this.filePath), { recursive: true })
      await writeFile(tempPath, body)
      await rename(tempPath, this.filePath)
    })
    this.writeQueue = write.catch(() => undefined)
    await write
  }
}

export function createRelayStore(): RelayStore {
  if (process.env.RELAY_STORE === 'memory') {
    return new InMemoryRelayStore()
  }
  if (process.env.RELAY_STORE === 'file' || process.env.RELAY_STORE_PATH || process.env.NODE_ENV === 'production') {
    return new FileRelayStore(process.env.RELAY_STORE_PATH || defaultRelayStorePath())
  }
  return new InMemoryRelayStore()
}

export function defaultRelayStorePath(): string {
  return join(homedir(), '.fides', 'relay', 'relay-store.json')
}

function relayStats(messages: RelayMessage[]): RelayStats {
  let pending = 0
  let delivered = 0
  let expired = 0
  const activeQueues = new Set<string>()

  for (const message of messages) {
    if (message.status === 'pending') {
      pending++
      activeQueues.add(message.to)
    } else if (message.status === 'delivered') {
      delivered++
    } else if (message.status === 'expired') {
      expired++
    }
  }

  return { total: messages.length, pending, delivered, expired, queues: activeQueues.size }
}

function loadRelaySnapshot(filePath: string): Map<string, RelayMessage> {
  if (!existsSync(filePath)) {
    return new Map()
  }

  const raw = readFileSyncUtf8(filePath)
  const parsed = JSON.parse(raw) as Partial<RelayStoreSnapshot>
  if (parsed.schemaVersion !== RELAY_STORE_SCHEMA_VERSION) {
    throw new Error(`unsupported relay store schema version: ${parsed.schemaVersion ?? 'missing'}`)
  }
  if (!Array.isArray(parsed.messages)) {
    throw new Error('relay store snapshot is missing messages')
  }

  return new Map(parsed.messages.map(message => [message.id, message]))
}

function readFileSyncUtf8(filePath: string): string {
  return existsSync(filePath)
    ? readFileSync(filePath, 'utf8')
    : ''
}
