import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it } from 'vitest'
import { FilePlatformStore, InMemoryPlatformStore, PLATFORM_STORE_SCHEMA_VERSION } from '../src/storage.js'
import type { PasskeyCredentialBinding } from '@fides/core'
import type { PlatformTrustAnchorRecord } from '../src/storage.js'

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

function trustAnchor(overrides: Partial<PlatformTrustAnchorRecord> = {}): PlatformTrustAnchorRecord {
  return {
    did: 'did:fides:anchor-store-01',
    name: 'Store Anchor',
    publicKey: '00'.repeat(32),
    attestation: {
      payload: { did: 'did:fides:anchor-store-01' },
      proof: {
        type: 'Ed25519Signature2024',
        created: '2026-01-01T00:00:00.000Z',
        verificationMethod: 'did:fides:issuer-store-01#key-1',
        proofPurpose: 'assertionMethod',
        canonicalizationAlgorithm: 'https://fides.dev/canonical-json/v1',
        proofValue: 'sig',
      },
    },
    status: 'active',
    scopes: ['identity.organization'],
    issuerDid: 'did:fides:issuer-store-01',
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

  it('tracks governed trust anchors in memory', async () => {
    const store = new InMemoryPlatformStore()

    await store.putTrustAnchor(trustAnchor())
    await store.putTrustAnchor(trustAnchor({
      did: 'did:fides:anchor-store-02',
      status: 'suspended',
    }))

    expect(await store.getTrustAnchor('did:fides:anchor-store-01')).toMatchObject({
      name: 'Store Anchor',
      status: 'active',
    })
    expect(await store.listTrustAnchors()).toHaveLength(2)
    expect(await store.deleteTrustAnchor('did:fides:anchor-store-01')).toBe(true)
    expect(await store.deleteTrustAnchor('missing')).toBe(false)
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
    expect(JSON.parse(await readFile(path, 'utf8'))).toMatchObject({
      schemaVersion: PLATFORM_STORE_SCHEMA_VERSION,
    })
  })

  it('persists governed trust anchors through the file store', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fides-platform-'))
    tempDirs.push(dir)
    const path = join(dir, 'platform-store.json')

    const writer = new FilePlatformStore(path)
    await writer.putTrustAnchor(trustAnchor({ metadata: { tier: 'root' } }))

    const reader = new FilePlatformStore(path)
    expect(await reader.getTrustAnchor('did:fides:anchor-store-01')).toMatchObject({
      scopes: ['identity.organization'],
      metadata: { tier: 'root' },
    })
    expect(await reader.listTrustAnchors()).toHaveLength(1)
  })

  it('migrates legacy unversioned file snapshots on read and writes current schema version', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fides-platform-'))
    tempDirs.push(dir)
    const path = join(dir, 'platform-store.json')

    await writeFile(path, JSON.stringify({
      passkeyBindings: {
        'credential-store-01': binding(),
      },
    }), 'utf8')

    const store = new FilePlatformStore(path)
    expect(await store.getPasskeyBinding('credential-store-01')).toMatchObject({
      principalDid: 'did:fides:principal-store-01',
    })

    await store.putTrustAnchor(trustAnchor())

    const snapshot = JSON.parse(await readFile(path, 'utf8'))
    expect(snapshot).toMatchObject({
      schemaVersion: PLATFORM_STORE_SCHEMA_VERSION,
      passkeyBindings: {
        'credential-store-01': {
          principalDid: 'did:fides:principal-store-01',
        },
      },
      trustAnchors: {
        'did:fides:anchor-store-01': {
          status: 'active',
        },
      },
    })
  })

  it('rejects unsupported file snapshot schema versions', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fides-platform-'))
    tempDirs.push(dir)
    const path = join(dir, 'platform-store.json')

    await writeFile(path, JSON.stringify({
      schemaVersion: 999,
      passkeyBindings: {},
      trustAnchors: {},
    }), 'utf8')

    const store = new FilePlatformStore(path)
    await expect(store.healthCheck()).resolves.toMatchObject({
      ok: false,
      kind: 'file',
      detail: 'Unsupported platform store schemaVersion 999',
    })
  })
})
