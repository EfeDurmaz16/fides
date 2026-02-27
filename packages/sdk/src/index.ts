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
export { type VerifyResult, type VerifyOptions, verifyRequest } from './signing/verify.js'
export { NonceStore } from './signing/nonce-store.js'

// Discovery module exports
export { DiscoveryClient } from './discovery/client.js'
export { IdentityResolver } from './discovery/resolver.js'

// Trust module exports
export { TrustLevel } from './trust/types.js'
export { createAttestation, verifyAttestation } from './trust/attestation.js'
export { TrustClient } from './trust/client.js'

// Security module exports
export { RateLimiter, type RateLimiterOptions } from './security/rate-limiter.js'
export {
  validateContent,
  validateRequestContent,
  type ContentValidationResult,
  type ContentThreat,
} from './security/content-validator.js'
export { rateLimitMiddleware, type RateLimitMiddlewareOptions } from './security/rate-limit-middleware.js'
export { contentValidationMiddleware } from './security/content-validation-middleware.js'

// Key rotation exports
export { rotateKey, createRevocation, type KeyRotationResult, type RotationRecord, type RevocationRecord } from './identity/rotation.js'

// Observability module exports
export { MetricsCollector } from './observability/metrics.js'
export { metricsMiddleware } from './observability/metrics-middleware.js'

// High-level API
export { Fides } from './fides.js'

// Integration exports
export {
  AgitCommitSigner,
  TrustGatedAccess,
  type CommitSignature,
  type CommitVerification,
  type TrustGateResult,
} from './integrations/agit.js'
