import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'crypto'
import { writeFileSync, readFileSync, mkdirSync, chmodSync, existsSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'
import type { KeyPair } from '@fides/shared'
import { KeyError } from '@fides/shared'

export interface KeyStore {
  save(did: string, keyPair: KeyPair): Promise<void>
  load(did: string): Promise<KeyPair>
}

/**
 * In-memory keystore for testing
 */
export class MemoryKeyStore implements KeyStore {
  private keys: Map<string, KeyPair> = new Map()

  async save(did: string, keyPair: KeyPair): Promise<void> {
    this.keys.set(did, {
      publicKey: new Uint8Array(keyPair.publicKey),
      privateKey: new Uint8Array(keyPair.privateKey),
    })
  }

  async load(did: string): Promise<KeyPair> {
    const keyPair = this.keys.get(did)
    if (!keyPair) {
      throw new KeyError(`Key not found for DID: ${did}`)
    }
    return {
      publicKey: new Uint8Array(keyPair.publicKey),
      privateKey: new Uint8Array(keyPair.privateKey),
    }
  }
}

interface EncryptedKeyData {
  iv: string
  salt: string
  authTag: string
  ciphertext: string
}

interface KeyFileData {
  did: string
  publicKey: string
  encrypted: boolean
  data: EncryptedKeyData | { privateKey: string }
  createdAt: string
}

/**
 * File-based keystore with optional encryption
 * Keys are stored in ~/.fides/keys/
 * Files have 0600 permissions (owner read/write only)
 */
export class FileKeyStore implements KeyStore {
  private readonly keysDir: string
  private readonly passphrase?: string
  private readonly encrypt: boolean

  constructor(options?: { passphrase?: string; encrypt?: boolean }) {
    this.keysDir = join(homedir(), '.fides', 'keys')
    this.passphrase = options?.passphrase
    this.encrypt = options?.encrypt !== false // default to true if passphrase provided

    // Ensure keys directory exists
    if (!existsSync(this.keysDir)) {
      mkdirSync(this.keysDir, { recursive: true, mode: 0o700 })
    }
  }

  private getKeyPath(did: string): string {
    // Sanitize DID for use as filename (replace : with -)
    const safeDid = did.replace(/:/g, '-')
    return join(this.keysDir, `${safeDid}.json`)
  }

  private encryptPrivateKey(privateKey: Uint8Array): EncryptedKeyData {
    if (!this.passphrase) {
      throw new KeyError('Passphrase required for encryption')
    }

    // Generate random salt and IV
    const salt = randomBytes(32)
    const iv = randomBytes(16)

    // Derive key using PBKDF2 with 600k iterations
    const key = pbkdf2Sync(this.passphrase, salt, 600000, 32, 'sha256')

    // Encrypt using AES-256-GCM
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    const ciphertext = Buffer.concat([
      cipher.update(privateKey),
      cipher.final(),
    ])
    const authTag = cipher.getAuthTag()

    return {
      iv: iv.toString('base64'),
      salt: salt.toString('base64'),
      authTag: authTag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    }
  }

  private decryptPrivateKey(data: EncryptedKeyData): Uint8Array {
    if (!this.passphrase) {
      throw new KeyError('Passphrase required for decryption')
    }

    const salt = Buffer.from(data.salt, 'base64')
    const iv = Buffer.from(data.iv, 'base64')
    const authTag = Buffer.from(data.authTag, 'base64')
    const ciphertext = Buffer.from(data.ciphertext, 'base64')

    // Derive the same key
    const key = pbkdf2Sync(this.passphrase, salt, 600000, 32, 'sha256')

    // Decrypt using AES-256-GCM
    const decipher = createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(authTag)

    try {
      const privateKey = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ])
      return new Uint8Array(privateKey)
    } catch (error) {
      throw new KeyError(
        `Decryption failed: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  async save(did: string, keyPair: KeyPair): Promise<void> {
    const keyPath = this.getKeyPath(did)

    const fileData: KeyFileData = {
      did,
      publicKey: Buffer.from(keyPair.publicKey).toString('base64'),
      encrypted: this.encrypt && !!this.passphrase,
      data:
        this.encrypt && this.passphrase
          ? this.encryptPrivateKey(keyPair.privateKey)
          : { privateKey: Buffer.from(keyPair.privateKey).toString('base64') },
      createdAt: new Date().toISOString(),
    }

    try {
      writeFileSync(keyPath, JSON.stringify(fileData, null, 2), {
        mode: 0o600,
      })
      // Ensure file permissions are set correctly
      chmodSync(keyPath, 0o600)
    } catch (error) {
      throw new KeyError(
        `Failed to save key: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  async load(did: string): Promise<KeyPair> {
    const keyPath = this.getKeyPath(did)

    if (!existsSync(keyPath)) {
      throw new KeyError(`Key not found for DID: ${did}`)
    }

    try {
      const fileContent = readFileSync(keyPath, 'utf-8')
      const fileData: KeyFileData = JSON.parse(fileContent)

      if (fileData.did !== did) {
        throw new KeyError('DID mismatch in key file')
      }

      const publicKey = new Uint8Array(
        Buffer.from(fileData.publicKey, 'base64')
      )

      let privateKey: Uint8Array

      if (fileData.encrypted) {
        privateKey = this.decryptPrivateKey(fileData.data as EncryptedKeyData)
      } else {
        const data = fileData.data as { privateKey: string }
        privateKey = new Uint8Array(Buffer.from(data.privateKey, 'base64'))
      }

      return { publicKey, privateKey }
    } catch (error) {
      if (error instanceof KeyError) {
        throw error
      }
      throw new KeyError(
        `Failed to load key: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }
}
