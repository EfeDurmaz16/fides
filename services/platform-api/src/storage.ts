import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'
import type { PasskeyCredentialBinding } from '@fides/core'

export interface PlatformStoreHealth {
  ok: boolean
  kind: PlatformStore['kind']
  detail?: string
}

export interface PlatformStore {
  readonly kind: 'memory' | 'file'
  putPasskeyBinding(binding: PasskeyCredentialBinding): Promise<PasskeyCredentialBinding>
  getPasskeyBinding(credentialId: string): Promise<PasskeyCredentialBinding | null>
  listPasskeyBindings(principalDid: string): Promise<PasskeyCredentialBinding[]>
  deletePasskeyBinding(credentialId: string): Promise<boolean>
  healthCheck(): Promise<PlatformStoreHealth>
}

interface PlatformSnapshot {
  passkeyBindings: Record<string, PasskeyCredentialBinding>
}

function emptySnapshot(): PlatformSnapshot {
  return { passkeyBindings: {} }
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

  async healthCheck(): Promise<PlatformStoreHealth> {
    return { ok: true, kind: this.kind }
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

  async healthCheck(): Promise<PlatformStoreHealth> {
    try {
      await mkdir(dirname(this.path), { recursive: true })
      await this.read()
      return { ok: true, kind: this.kind, detail: this.path }
    } catch (error) {
      return { ok: false, kind: this.kind, detail: error instanceof Error ? error.message : String(error) }
    }
  }

  private async read(): Promise<PlatformSnapshot> {
    try {
      const raw = await readFile(this.path, 'utf8')
      return { ...emptySnapshot(), ...JSON.parse(raw) as Partial<PlatformSnapshot> }
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

export function createPlatformStore(): PlatformStore {
  if (process.env.NODE_ENV === 'test') return new InMemoryPlatformStore()
  return new FilePlatformStore(process.env.PLATFORM_STORE_PATH)
}
