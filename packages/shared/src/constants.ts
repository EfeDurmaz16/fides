export const ALGORITHM = 'ed25519' as const
export const SIGNATURE_HEADER = 'signature' as const
export const SIGNATURE_INPUT_HEADER = 'signature-input' as const
export const WELL_KNOWN_PATH = '/.well-known/fides.json' as const
export const DEFAULT_TRUST_DECAY = 0.85
export const MAX_TRUST_DEPTH = 6
export const DEFAULT_SIGNATURE_EXPIRY_SECONDS = 300
export const DID_METHOD = 'fides' as const
export const DID_PREFIX = `did:${DID_METHOD}:` as const

// Security constants
export const MAX_REQUEST_BODY_SIZE = 1024 * 1024 // 1 MB
export const ED25519_PUBLIC_KEY_LENGTH = 32
export const ED25519_PRIVATE_KEY_LENGTH = 32
export const ED25519_PRIVATE_KEY_LENGTH_EXTENDED = 64
export const MIN_TRUST_LEVEL = 0
export const MAX_TRUST_LEVEL = 100

// Content-Digest constants (RFC 9530)
export const CONTENT_DIGEST_ALGORITHM = 'sha-256' as const

// Clock drift tolerance for signature verification
export const DEFAULT_CLOCK_DRIFT_SECONDS = 30
