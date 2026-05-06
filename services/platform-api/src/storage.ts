import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'
import type { PasskeyCredentialBinding } from '@fides/core'
import type { SignedObject, TrustAnchorStatus } from '@fides/core'

export const PLATFORM_STORE_SCHEMA_VERSION = 1

export interface PlatformStoreHealth {
  ok: boolean
  kind: PlatformStore['kind']
  detail?: string
  schemaVersion?: number
}

export interface PlatformStore {
  readonly kind: 'memory' | 'file'
  putPasskeyBinding(binding: PasskeyCredentialBinding): Promise<PasskeyCredentialBinding>
  getPasskeyBinding(credentialId: string): Promise<PasskeyCredentialBinding | null>
  listPasskeyBindings(principalDid: string): Promise<PasskeyCredentialBinding[]>
  deletePasskeyBinding(credentialId: string): Promise<boolean>
  putTrustAnchor(anchor: PlatformTrustAnchorRecord): Promise<PlatformTrustAnchorRecord>
  getTrustAnchor(did: string): Promise<PlatformTrustAnchorRecord | null>
  listTrustAnchors(): Promise<PlatformTrustAnchorRecord[]>
  deleteTrustAnchor(did: string): Promise<boolean>
  healthCheck(): Promise<PlatformStoreHealth>
}

export interface PlatformTrustAnchorRecord {
  did: string
  name: string
  publicKey: string
  attestation: SignedObject<unknown>
  status: TrustAnchorStatus
  scopes: string[]
  issuerDid?: string
  createdAt: string
  updatedAt?: string
  expiresAt?: string
  revokedAt?: string
  reason?: string
  metadata?: Record<string, unknown>
}

interface PlatformSnapshot {
  schemaVersion: typeof PLATFORM_STORE_SCHEMA_VERSION
  passkeyBindings: Record<string, PasskeyCredentialBinding>
  trustAnchors: Record<string, PlatformTrustAnchorRecord>
}

function emptySnapshot(): PlatformSnapshot {
  return {
    schemaVersion: PLATFORM_STORE_SCHEMA_VERSION,
    passkeyBindings: {},
    trustAnchors: {},
  }
}

export class InMemoryPlatformStore implements PlatformStore {
  readonly kind = 'memory' as const
  private passkeyBindings = new Map<string, PasskeyCredentialBinding>()

  async putPasskeyBinding(binding: PasskeyCredentialBinding): Promise<PasskeyCredentialBinding> {
    this.passkeyBindings.set(binding.credentialId, binding)
    return binding
  }

  async getPasskeyBinding(credentialId: string): Promise<PasskeyCredentialBinding | null> {
    return this.passkeyBindings.get(credentialId) ?? null
  }

  async listPasskeyBindings(principalDid: string): Promise<PasskeyCredentialBinding[]> {
    return [...this.passkeyBindings.values()]
      .filter(binding => binding.principalDid === principalDid)
      .sort((a, b) => a.credentialId.localeCompare(b.credentialId))
  }

  async deletePasskeyBinding(credentialId: string): Promise<boolean> {
    return this.passkeyBindings.delete(credentialId)
  }

  private trustAnchors = new Map<string, PlatformTrustAnchorRecord>()

  async putTrustAnchor(anchor: PlatformTrustAnchorRecord): Promise<PlatformTrustAnchorRecord> {
    this.trustAnchors.set(anchor.did, anchor)
    return anchor
  }

  async getTrustAnchor(did: string): Promise<PlatformTrustAnchorRecord | null> {
    return this.trustAnchors.get(did) ?? null
  }

  async listTrustAnchors(): Promise<PlatformTrustAnchorRecord[]> {
    return [...this.trustAnchors.values()].sort((a, b) => a.did.localeCompare(b.did))
  }

  async deleteTrustAnchor(did: string): Promise<boolean> {
    return this.trustAnchors.delete(did)
  }

  async healthCheck(): Promise<PlatformStoreHealth> {
    return { ok: true, kind: this.kind, schemaVersion: PLATFORM_STORE_SCHEMA_VERSION }
  }
}

export class FilePlatformStore implements PlatformStore {
  readonly kind = 'file' as const

  constructor(private readonly path = join(homedir(), '.fides', 'platform-api', 'platform-store.json')) {}

  async putPasskeyBinding(binding: PasskeyCredentialBinding): Promise<PasskeyCredentialBinding> {
    const snapshot = await this.read()
    await this.write({
      ...snapshot,
      passkeyBindings: {
        ...snapshot.passkeyBindings,
        [binding.credentialId]: binding,
      },
    })
    return binding
  }

  async getPasskeyBinding(credentialId: string): Promise<PasskeyCredentialBinding | null> {
    return (await this.read()).passkeyBindings[credentialId] ?? null
  }

  async listPasskeyBindings(principalDid: string): Promise<PasskeyCredentialBinding[]> {
    return Object.values((await this.read()).passkeyBindings)
      .filter(binding => binding.principalDid === principalDid)
      .sort((a, b) => a.credentialId.localeCompare(b.credentialId))
  }

  async deletePasskeyBinding(credentialId: string): Promise<boolean> {
    const snapshot = await this.read()
    if (!snapshot.passkeyBindings[credentialId]) return false
    const { [credentialId]: _removed, ...remaining } = snapshot.passkeyBindings
    await this.write({ ...snapshot, passkeyBindings: remaining })
    return true
  }

  async putTrustAnchor(anchor: PlatformTrustAnchorRecord): Promise<PlatformTrustAnchorRecord> {
    const snapshot = await this.read()
    await this.write({
      ...snapshot,
      trustAnchors: {
        ...snapshot.trustAnchors,
        [anchor.did]: anchor,
      },
    })
    return anchor
  }

  async getTrustAnchor(did: string): Promise<PlatformTrustAnchorRecord | null> {
    return (await this.read()).trustAnchors[did] ?? null
  }

  async listTrustAnchors(): Promise<PlatformTrustAnchorRecord[]> {
    return Object.values((await this.read()).trustAnchors)
      .sort((a, b) => a.did.localeCompare(b.did))
  }

  async deleteTrustAnchor(did: string): Promise<boolean> {
    const snapshot = await this.read()
    if (!snapshot.trustAnchors[did]) return false
    const { [did]: _removed, ...remaining } = snapshot.trustAnchors
    await this.write({ ...snapshot, trustAnchors: remaining })
    return true
  }

  async healthCheck(): Promise<PlatformStoreHealth> {
    try {
      await mkdir(dirname(this.path), { recursive: true })
      const snapshot = await this.read()
      return { ok: true, kind: this.kind, detail: this.path, schemaVersion: snapshot.schemaVersion }
    } catch (error) {
      return { ok: false, kind: this.kind, detail: error instanceof Error ? error.message : String(error) }
    }
  }

  private async read(): Promise<PlatformSnapshot> {
    try {
      const raw = await readFile(this.path, 'utf8')
      return migrateSnapshot(JSON.parse(raw))
    } catch (error) {
      if (error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'ENOENT') {
        return emptySnapshot()
      }
      throw error
    }
  }

  private async write(snapshot: PlatformSnapshot): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true })
    const tempPath = `${this.path}.${process.pid}.${Date.now()}.tmp`
    await writeFile(tempPath, `${JSON.stringify(snapshot, null, 2)}\n`, 'utf8')
    await rename(tempPath, this.path)
  }
}

function migrateSnapshot(raw: unknown): PlatformSnapshot {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Invalid platform store snapshot')
  }

  const snapshot = raw as Partial<PlatformSnapshot>
  if (snapshot.schemaVersion !== undefined && snapshot.schemaVersion !== PLATFORM_STORE_SCHEMA_VERSION) {
    throw new Error(`Unsupported platform store schemaVersion ${snapshot.schemaVersion}`)
  }

  return {
    ...emptySnapshot(),
    passkeyBindings: isRecord(snapshot.passkeyBindings) ? snapshot.passkeyBindings as Record<string, PasskeyCredentialBinding> : {},
    trustAnchors: isRecord(snapshot.trustAnchors) ? snapshot.trustAnchors as Record<string, PlatformTrustAnchorRecord> : {},
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

export function createPlatformStore(): PlatformStore {
  if (process.env.NODE_ENV === 'test') return new InMemoryPlatformStore()
  return new FilePlatformStore(process.env.PLATFORM_STORE_PATH)
}
