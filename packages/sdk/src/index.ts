// Re-export shared types and errors
export * from '@fides/shared'

// Identity module exports
export { generateKeyPair, sign, verify } from './identity/keypair.js'
export { generateDID, parseDID } from './identity/did.js'
export {
  type KeyStore,
  MemoryKeyStore,
  FileKeyStore,
} from './identity/keystore.js'
