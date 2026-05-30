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
export {
  DiscoveryClient,
  type DiscoveryClientOptions,
  type RegisterIdentityParams,
  type VerifyIdentityDomainResponse,
  type VerifyOrganizationDomainResponse,
} from './discovery/client.js'
export { IdentityResolver } from './discovery/resolver.js'
export { AgentDiscoveryClient, type AgentDiscoveryClientOptions, type RegisterAgentParams } from './discovery/agent-client.js'
export { toA2AAgentCard, fromA2AAgentCard } from './discovery/a2a.js'
export {
  RegistryClient,
  RegistryError,
  type AgentCard,
  type RegistryClientOptions,
  type RegistryMode,
  type RegistryModeResponse,
  type RegistryMutationResponse,
  type RegistryRegisterResponse,
  type RegistrySearchResponse,
  type RegistrySearchResult,
  type RegistryStatsResponse,
} from './registry/client.js'
export {
  RelayClient,
  RelayError,
  type RelayAcceptResponse,
  type RelayClientOptions,
  type RelayDeleteResponse,
  type RelayMessage,
  type RelayMessageRequest,
  type RelayPollResponse,
  type RelayStatsResponse,
} from './relay/client.js'
export {
  PlatformClient,
  PlatformError,
  type PlatformClientOptions,
  type PlatformMutationResponse,
  type PlatformPasskeyBindingResponse,
  type PlatformPasskeyCredentialBinding,
  type PlatformPasskeyCredentialDescriptor,
  type PlatformPasskeyCredentialsResponse,
  type PlatformTopologyResponse,
  type PlatformTrustAnchorDistribution,
  type PlatformTrustAnchorDistributionEntry,
  type PlatformTrustAnchorDistributionOptions,
  type PlatformTrustAnchorDistributionResponse,
  type PlatformTrustAnchorRecord,
  type PlatformTrustAnchorResponse,
  type PlatformTrustAnchorStatus,
  type PlatformTrustAnchorsResponse,
} from './platform/client.js'

// Trust module exports
export { TrustLevel } from './trust/types.js'
export { createAttestation, verifyAttestation } from './trust/attestation.js'
export { TrustClient, type TrustGraphRevocationState } from './trust/client.js'

// Agent daemon exports
export {
  AgentdClient,
  AgentdError,
  type AgentdCardResponse,
  type AgentdClientOptions,
  type AgentdHealthResponse,
  type AgentdStoreHealth,
  type AuthorizationDecision,
  type AuthorizationRequest,
  type AuthorityPropagationResponse,
  type AuthorityPropagationListResponse,
  type AuthorityPropagationRecord,
  type AuthorityPropagationRetryResponse,
  type AuthorityPropagationRetryResult,
  type CreateSignedSessionOptions,
  type DelegationToken,
  type DomainVerificationResponse,
  type IncidentListResponse,
  type IncidentRecord,
  type RecordSignedIncidentOptions,
  type RecordSignedRevocationOptions,
  type IncidentSubmitRequest,
  type IncidentSubmitResponse,
  type RevocationRecord as AgentdRevocationRecord,
  type RevocationStatusResponse,
  type RevocationSubmitRequest,
  type RevocationSubmitResponse,
  type SessionCreateRequest,
  type SessionCreateResponse,
  type SessionGrant,
  type SessionLookupResponse,
  type SessionRevokeResponse,
} from './agentd/client.js'

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
export {
  FidesClient,
  FidesClientError,
  type FidesClientOptions,
  type FidesDiscoveryQuery,
  type FidesDiscoveryResponse,
  type FidesProviderRecord,
  type FidesRegistryPublishRequest,
  type FidesRelayRegisterRequest,
  type FidesDhtPublishRequest,
  type FidesInvocationRequest,
  type FidesInvocationResponse,
} from './fides-client.js'

// Integration exports
export {
  AgitPrimitiveBridge,
  AgitCommitSigner,
  TrustGatedAccess,
  type AgitEvidenceHashChainInput,
  type AgitEvidenceHashChainResult,
  type AgitMerkleProofInput,
  type AgitMerkleProofResult,
  type AgitPrimitiveBridgeOptions,
  type AgitRustPrimitiveAdapter,
  type CommitSignature,
  type CommitVerification,
  type TrustGateResult,
} from './integrations/agit.js'
