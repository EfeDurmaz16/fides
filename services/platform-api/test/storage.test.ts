import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it } from 'vitest'
import { FilePlatformStore, InMemoryPlatformStore } from '../src/storage.js'
import type { PasskeyCredentialBinding } from '@fides/core'

const tempDirs: string[] = []

afterEach(async () => {
  await Promise.all(tempDirs.map(path => rm(path, { recursive: true, force: true })))
  tempDirs.length = 0
})

function binding(overrides: Partial<PasskeyCredentialBinding> = {}): PasskeyCredentialBinding {
  return {
    principalDid: 'did:fides:principal-store-01',
    credentialId: 'credential-store-01',
    publicKey: 'public-key-material',
    relyingPartyId: 'example.com',
    signCount: 1,
    createdAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  }
}

describe('platform stores', () => {
  it('tracks passkey bindings in memory', async () => {
    const store = new InMemoryPlatformStore()

    await store.putPasskeyBinding(binding())
    await store.putPasskeyBinding(binding({
      principalDid: 'did:fides:other-principal',
      credentialId: 'credential-store-02',
    }))

    expect(await store.getPasskeyBinding('credential-store-01')).toMatchObject({
      principalDid: 'did:fides:principal-store-01',
    })
    expect(await store.listPasskeyBindings('did:fides:principal-store-01')).toHaveLength(1)
    expect(await store.deletePasskeyBinding('credential-store-01')).toBe(true)
    expect(await store.deletePasskeyBinding('missing')).toBe(false)
  })

  it('persists passkey bindings through the file store', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fides-platform-'))
    tempDirs.push(dir)
    const path = join(dir, 'platform-store.json')

    const writer = new FilePlatformStore(path)
    await writer.putPasskeyBinding(binding({ backedUp: true }))

    const reader = new FilePlatformStore(path)
    expect(await reader.getPasskeyBinding('credential-store-01')).toMatchObject({
      relyingPartyId: 'example.com',
      backedUp: true,
    })
    expect(await reader.healthCheck()).toMatchObject({ ok: true, kind: 'file' })
  })
})
