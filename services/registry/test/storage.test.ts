import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it } from 'vitest'
import { FileRegistryStore, InMemoryRegistryStore, type RegistryEntry } from '../src/storage.js'

const tempDirs: string[] = []

afterEach(async () => {
  await Promise.all(tempDirs.map(path => rm(path, { recursive: true, force: true })))
  tempDirs.length = 0
})

function entry(overrides: Partial<RegistryEntry> = {}): RegistryEntry {
  return {
    card: { id: 'did:fides:test', name: 'Test Agent' },
    mode: 'public',
    registeredAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    metadata: {},
    ...overrides,
  }
}

describe('Registry stores', () => {
  it('tracks entries and stats in memory', async () => {
    const store = new InMemoryRegistryStore()

    await store.put('did:fides:public', entry())
    await store.put('did:fides:private', entry({ mode: 'private' }))

    expect(await store.get('did:fides:public')).toMatchObject({ mode: 'public' })
    expect(await store.stats()).toEqual({ total: 2, public: 1, private: 1 })
    expect(await store.delete('did:fides:private')).toBe(true)
    expect(await store.delete('did:fides:missing')).toBe(false)
  })

  it('persists entries through the file store', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fides-registry-'))
    tempDirs.push(dir)
    const path = join(dir, 'registry.json')

    const writer = new FileRegistryStore(path)
    await writer.put('did:fides:persisted', entry({ metadata: { owner: 'test' } }))

    const reader = new FileRegistryStore(path)
    expect(await reader.get('did:fides:persisted')).toMatchObject({
      mode: 'public',
      metadata: { owner: 'test' },
    })
    expect(await reader.healthCheck()).toMatchObject({ ok: true, kind: 'file' })
  })
})
