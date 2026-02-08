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

// Signing module exports
export {
  type RequestLike,
  type SignatureParams,
  createSignatureBase,
  parseSignatureInput,
} from './signing/canonicalize.js'
export { type SignOptions, signRequest } from './signing/http-signature.js'
export { type VerifyResult, verifyRequest } from './signing/verify.js'
