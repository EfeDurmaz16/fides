import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it } from 'vitest'
import {
  FileRelayStore,
  InMemoryRelayStore,
  RELAY_STORE_SCHEMA_VERSION,
  type RelayMessage,
} from '../src/storage.js'

const tempDirs: string[] = []

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map(dir => rm(dir, { recursive: true, force: true })))
})

async function tempStorePath(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fides-relay-store-'))
  tempDirs.push(dir)
  return join(dir, 'relay-store.json')
}

function message(overrides: Partial<RelayMessage> = {}): RelayMessage {
  const now = new Date()
  return {
    id: crypto.randomUUID(),
    to: 'did:fides:receiver',
    from: 'did:fides:sender',
    payload: { content: 'hello' },
    status: 'pending',
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60_000).toISOString(),
    ...overrides,
  }
}

describe('relay stores', () => {
  it('tracks relay messages in memory', async () => {
    const store = new InMemoryRelayStore()
    const relayMessage = message()

    await store.put(relayMessage)

    expect(await store.get(relayMessage.id)).toEqual(relayMessage)
    expect(await store.stats()).toMatchObject({ total: 1, pending: 1, queues: 1 })
  })

  it('persists relay messages through the file store', async () => {
    const filePath = await tempStorePath()
    const store = new FileRelayStore(filePath)
    const relayMessage = message({ to: 'did:fides:file-receiver' })

    await store.put(relayMessage)
    const restored = new FileRelayStore(filePath)

    expect(await restored.get(relayMessage.id)).toEqual(relayMessage)
    expect(await restored.stats()).toMatchObject({ total: 1, pending: 1, queues: 1 })
  })

  it('marks pending messages delivered only once and persists the update', async () => {
    const filePath = await tempStorePath()
    const store = new FileRelayStore(filePath)
    const relayMessage = message({ to: 'did:fides:poller' })
    const deliveredAt = new Date().toISOString()

    await store.put(relayMessage)
    const firstPoll = await store.pollPending(relayMessage.to, deliveredAt)
    const secondPoll = await store.pollPending(relayMessage.to, deliveredAt)
    const restored = new FileRelayStore(filePath)

    expect(firstPoll).toHaveLength(1)
    expect(firstPoll[0]).toMatchObject({ id: relayMessage.id, status: 'delivered', deliveredAt })
    expect(secondPoll).toHaveLength(0)
    expect(await restored.get(relayMessage.id)).toMatchObject({ status: 'delivered', deliveredAt })
  })

  it('expires pending messages and persists the status', async () => {
    const filePath = await tempStorePath()
    const store = new FileRelayStore(filePath)
    const relayMessage = message({ expiresAt: new Date(Date.now() - 1_000).toISOString() })

    await store.put(relayMessage)
    await store.expirePending(Date.now())
    const restored = new FileRelayStore(filePath)

    expect(await restored.get(relayMessage.id)).toMatchObject({ status: 'expired' })
    expect(await restored.stats()).toMatchObject({ total: 1, expired: 1, queues: 0 })
  })

  it('rejects unsupported file snapshot schema versions', async () => {
    const filePath = await tempStorePath()
    await writeFile(filePath, JSON.stringify({ schemaVersion: RELAY_STORE_SCHEMA_VERSION + 1, messages: [] }))

    expect(() => new FileRelayStore(filePath)).toThrow('unsupported relay store schema version')
  })

  it('writes the current relay store schema version', async () => {
    const filePath = await tempStorePath()
    const store = new FileRelayStore(filePath)

    await store.put(message())
    const snapshot = JSON.parse(await readFile(filePath, 'utf8'))

    expect(snapshot.schemaVersion).toBe(RELAY_STORE_SCHEMA_VERSION)
    expect(snapshot.messages).toHaveLength(1)
  })
})
