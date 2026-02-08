// Re-export shared types and errors
export * from '@fides/shared'

// Identity module exports
export { generateKeyPair, sign, verify } from './identity/keypair.js'
export { generateDID, parseDID, isValidDID } from './identity/did.js'
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

// Discovery module exports
export { DiscoveryClient } from './discovery/client.js'
export { IdentityResolver } from './discovery/resolver.js'

// Trust module exports
export { TrustLevel } from './trust/types.js'
export { createAttestation, verifyAttestation } from './trust/attestation.js'
export { TrustClient } from './trust/client.js'

// High-level API
export { Fides } from './fides.js'
