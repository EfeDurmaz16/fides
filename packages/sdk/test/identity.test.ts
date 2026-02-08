import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { unlinkSync, existsSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'
import {
  generateKeyPair,
  sign,
  verify,
  generateDID,
  parseDID,
  MemoryKeyStore,
  FileKeyStore,
  KeyError,
} from '../src/index.js'

describe('Keypair Generation', () => {
  it('should generate valid 32-byte keys', async () => {
    const keyPair = await generateKeyPair()

    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array)
    expect(keyPair.privateKey).toBeInstanceOf(Uint8Array)
    expect(keyPair.publicKey.length).toBe(32)
    expect(keyPair.privateKey.length).toBe(32)
  })

  it('should generate unique keypairs', async () => {
    const keyPair1 = await generateKeyPair()
    const keyPair2 = await generateKeyPair()

    expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey)
    expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey)
  })

  it('should sign and verify messages', async () => {
    const keyPair = await generateKeyPair()
    const message = new TextEncoder().encode('Hello, FIDES!')

    const signature = await sign(message, keyPair.privateKey)

    expect(signature).toBeInstanceOf(Uint8Array)
    expect(signature.length).toBe(64) // Ed25519 signatures are 64 bytes

    const valid = await verify(message, signature, keyPair.publicKey)
    expect(valid).toBe(true)
  })

  it('should reject invalid signatures', async () => {
    const keyPair = await generateKeyPair()
    const message = new TextEncoder().encode('Hello, FIDES!')

    const signature = await sign(message, keyPair.privateKey)

    // Modify the message
    const wrongMessage = new TextEncoder().encode('Wrong message')
    const valid = await verify(wrongMessage, signature, keyPair.publicKey)

    expect(valid).toBe(false)
  })

  it('should reject signature with wrong public key', async () => {
    const keyPair1 = await generateKeyPair()
    const keyPair2 = await generateKeyPair()
    const message = new TextEncoder().encode('Hello, FIDES!')

    const signature = await sign(message, keyPair1.privateKey)

    // Verify with different public key
    const valid = await verify(message, signature, keyPair2.publicKey)
    expect(valid).toBe(false)
  })
})

describe('DID Generation', () => {
  it('should generate valid DID from public key', async () => {
    const keyPair = await generateKeyPair()
    const did = generateDID(keyPair.publicKey)

    expect(did).toMatch(/^did:fides:[1-9A-HJ-NP-Za-km-z]+$/)
    expect(did.startsWith('did:fides:')).toBe(true)
  })

  it('should round-trip DID generation and parsing', async () => {
    const keyPair = await generateKeyPair()
    const did = generateDID(keyPair.publicKey)

    const recoveredPublicKey = parseDID(did)

    expect(recoveredPublicKey).toEqual(keyPair.publicKey)
  })

  it('should throw error for invalid DID prefix', () => {
    expect(() => parseDID('did:invalid:abc123')).toThrow(KeyError)
    expect(() => parseDID('not-a-did')).toThrow(KeyError)
  })

  it('should throw error for invalid base58 encoding', () => {
    expect(() => parseDID('did:fides:!!!invalid!!!')).toThrow(KeyError)
  })

  it('should generate consistent DIDs for same public key', async () => {
    const keyPair = await generateKeyPair()
    const did1 = generateDID(keyPair.publicKey)
    const did2 = generateDID(keyPair.publicKey)

    expect(did1).toBe(did2)
  })
})

describe('MemoryKeyStore', () => {
  let store: MemoryKeyStore

  beforeEach(() => {
    store = new MemoryKeyStore()
  })

  it('should save and load keypair', async () => {
    const keyPair = await generateKeyPair()
    const did = generateDID(keyPair.publicKey)

    await store.save(did, keyPair)
    const loaded = await store.load(did)

    expect(loaded.publicKey).toEqual(keyPair.publicKey)
    expect(loaded.privateKey).toEqual(keyPair.privateKey)
  })

  it('should throw error for non-existent key', async () => {
    await expect(store.load('did:fides:nonexistent')).rejects.toThrow(KeyError)
  })

  it('should handle multiple keys', async () => {
    const keyPair1 = await generateKeyPair()
    const keyPair2 = await generateKeyPair()
    const did1 = generateDID(keyPair1.publicKey)
    const did2 = generateDID(keyPair2.publicKey)

    await store.save(did1, keyPair1)
    await store.save(did2, keyPair2)

    const loaded1 = await store.load(did1)
    const loaded2 = await store.load(did2)

    expect(loaded1.publicKey).toEqual(keyPair1.publicKey)
    expect(loaded2.publicKey).toEqual(keyPair2.publicKey)
  })
})

describe('FileKeyStore', () => {
  let testDids: string[] = []

  afterEach(() => {
    // Clean up test files
    const keysDir = join(homedir(), '.fides', 'keys')
    testDids.forEach((did) => {
      const safeDid = did.replace(/:/g, '-')
      const keyPath = join(keysDir, `${safeDid}.json`)
      if (existsSync(keyPath)) {
        unlinkSync(keyPath)
      }
    })
    testDids = []
  })

  it('should save and load keypair without encryption', async () => {
    const store = new FileKeyStore({ encrypt: false })
    const keyPair = await generateKeyPair()
    const did = generateDID(keyPair.publicKey)
    testDids.push(did)

    await store.save(did, keyPair)
    const loaded = await store.load(did)

    expect(loaded.publicKey).toEqual(keyPair.publicKey)
    expect(loaded.privateKey).toEqual(keyPair.privateKey)
  })

  it('should save and load keypair with encryption', async () => {
    const passphrase = 'test-passphrase-12345'
    const store = new FileKeyStore({ passphrase, encrypt: true })
    const keyPair = await generateKeyPair()
    const did = generateDID(keyPair.publicKey)
    testDids.push(did)

    await store.save(did, keyPair)
    const loaded = await store.load(did)

    expect(loaded.publicKey).toEqual(keyPair.publicKey)
    expect(loaded.privateKey).toEqual(keyPair.privateKey)
  })

  it('should fail to decrypt with wrong passphrase', async () => {
    const keyPair = await generateKeyPair()
    const did = generateDID(keyPair.publicKey)
    testDids.push(did)

    const store1 = new FileKeyStore({
      passphrase: 'correct-passphrase',
      encrypt: true,
    })
    await store1.save(did, keyPair)

    const store2 = new FileKeyStore({
      passphrase: 'wrong-passphrase',
      encrypt: true,
    })

    await expect(store2.load(did)).rejects.toThrow(KeyError)
  })

  it('should throw error for non-existent key', async () => {
    const store = new FileKeyStore({ encrypt: false })

    await expect(store.load('did:fides:nonexistent')).rejects.toThrow(KeyError)
  })

  it('should handle multiple keys', async () => {
    const store = new FileKeyStore({ encrypt: false })
    const keyPair1 = await generateKeyPair()
    const keyPair2 = await generateKeyPair()
    const did1 = generateDID(keyPair1.publicKey)
    const did2 = generateDID(keyPair2.publicKey)
    testDids.push(did1, did2)

    await store.save(did1, keyPair1)
    await store.save(did2, keyPair2)

    const loaded1 = await store.load(did1)
    const loaded2 = await store.load(did2)

    expect(loaded1.publicKey).toEqual(keyPair1.publicKey)
    expect(loaded2.publicKey).toEqual(keyPair2.publicKey)
  })

  it('should create keys directory if not exists', async () => {
    const store = new FileKeyStore({ encrypt: false })
    const keyPair = await generateKeyPair()
    const did = generateDID(keyPair.publicKey)
    testDids.push(did)

    // Should not throw
    await store.save(did, keyPair)

    const keysDir = join(homedir(), '.fides', 'keys')
    expect(existsSync(keysDir)).toBe(true)
  })
})

describe('Encrypted Keystore Round-trip', () => {
  let testDids: string[] = []

  afterEach(() => {
    const keysDir = join(homedir(), '.fides', 'keys')
    testDids.forEach((did) => {
      const safeDid = did.replace(/:/g, '-')
      const keyPath = join(keysDir, `${safeDid}.json`)
      if (existsSync(keyPath)) {
        unlinkSync(keyPath)
      }
    })
    testDids = []
  })

  it('should perform full encrypted round-trip', async () => {
    const passphrase = 'secure-test-passphrase-xyz'
    const store = new FileKeyStore({ passphrase, encrypt: true })

    // Generate keypair
    const keyPair = await generateKeyPair()
    const did = generateDID(keyPair.publicKey)
    testDids.push(did)

    // Save encrypted
    await store.save(did, keyPair)

    // Load and verify
    const loaded = await store.load(did)
    expect(loaded.publicKey).toEqual(keyPair.publicKey)
    expect(loaded.privateKey).toEqual(keyPair.privateKey)

    // Verify signature still works
    const message = new TextEncoder().encode('Test message')
    const signature = await sign(message, loaded.privateKey)
    const valid = await verify(message, signature, loaded.publicKey)

    expect(valid).toBe(true)
  })

  it('should verify DID round-trip with stored keys', async () => {
    const store = new FileKeyStore({ encrypt: false })

    // Generate and store
    const keyPair = await generateKeyPair()
    const did = generateDID(keyPair.publicKey)
    testDids.push(did)

    await store.save(did, keyPair)

    // Load and verify DID
    const loaded = await store.load(did)
    const regeneratedDid = generateDID(loaded.publicKey)

    expect(regeneratedDid).toBe(did)
  })
})
