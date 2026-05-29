export type FidesErrorCategory =
  | 'identity'
  | 'agent_card'
  | 'capability'
  | 'trust'
  | 'policy'
  | 'approval'
  | 'session'
  | 'attestation'
  | 'discovery'
  | 'dht'
  | 'evidence'
  | 'revocation'
  | 'kill_switch'
  | 'version'
  | 'internal'

export type FidesErrorSeverity = 'info' | 'warning' | 'error' | 'critical'

export const FIDES_ERROR_CODES = {
  IDENTITY_INVALID_SIGNATURE: {
    category: 'identity',
    severity: 'error',
    retryable: false,
    message: 'Identity signature is invalid',
  },
  AGENT_CARD_EXPIRED: {
    category: 'agent_card',
    severity: 'error',
    retryable: false,
    message: 'AgentCard is expired',
  },
  AGENT_CARD_REVOKED: {
    category: 'agent_card',
    severity: 'critical',
    retryable: false,
    message: 'AgentCard is revoked',
  },
  CAPABILITY_NOT_FOUND: {
    category: 'capability',
    severity: 'error',
    retryable: false,
    message: 'Capability was not found',
  },
  CAPABILITY_SCHEMA_INVALID: {
    category: 'capability',
    severity: 'error',
    retryable: false,
    message: 'Capability schema is invalid',
  },
  TRUST_BELOW_THRESHOLD: {
    category: 'trust',
    severity: 'warning',
    retryable: false,
    message: 'Trust score is below policy threshold',
  },
  POLICY_DENIED: {
    category: 'policy',
    severity: 'error',
    retryable: false,
    message: 'Policy denied the request',
  },
  APPROVAL_REQUIRED: {
    category: 'approval',
    severity: 'warning',
    retryable: true,
    message: 'Approval is required before execution',
  },
  SESSION_EXPIRED: {
    category: 'session',
    severity: 'error',
    retryable: true,
    message: 'Session is expired',
  },
  SESSION_SCOPE_INVALID: {
    category: 'session',
    severity: 'error',
    retryable: false,
    message: 'Session scope does not allow this action',
  },
  ATTESTATION_INVALID: {
    category: 'attestation',
    severity: 'error',
    retryable: false,
    message: 'Runtime attestation is invalid',
  },
  ATTESTATION_EXPIRED: {
    category: 'attestation',
    severity: 'error',
    retryable: true,
    message: 'Runtime attestation is expired',
  },
  DHT_POINTER_TAMPERED: {
    category: 'dht',
    severity: 'critical',
    retryable: false,
    message: 'DHT pointer record was tampered with',
  },
  DHT_POINTER_EXPIRED: {
    category: 'dht',
    severity: 'error',
    retryable: true,
    message: 'DHT pointer record is expired',
  },
  EVIDENCE_CHAIN_BROKEN: {
    category: 'evidence',
    severity: 'critical',
    retryable: false,
    message: 'Evidence hash chain is broken',
  },
  REVOCATION_ACTIVE: {
    category: 'revocation',
    severity: 'critical',
    retryable: false,
    message: 'An active revocation blocks this action',
  },
  KILL_SWITCH_ACTIVE: {
    category: 'kill_switch',
    severity: 'critical',
    retryable: false,
    message: 'Kill switch is active',
  },
  VERSION_INCOMPATIBLE: {
    category: 'version',
    severity: 'error',
    retryable: false,
    message: 'Protocol versions are incompatible',
  },
} as const satisfies Record<string, {
  category: FidesErrorCategory
  severity: FidesErrorSeverity
  retryable: boolean
  message: string
}>

export type FidesErrorCode = keyof typeof FIDES_ERROR_CODES

export interface ErrorEnvelope {
  code: FidesErrorCode
  category: FidesErrorCategory
  severity: FidesErrorSeverity
  retryable: boolean
  message: string
  details?: Record<string, unknown>
}

export function createErrorEnvelope(
  code: FidesErrorCode,
  options: {
    message?: string
    details?: Record<string, unknown>
  } = {}
): ErrorEnvelope {
  const definition = FIDES_ERROR_CODES[code]
  const envelope: ErrorEnvelope = {
    code,
    category: definition.category,
    severity: definition.severity,
    retryable: definition.retryable,
    message: options.message ?? definition.message,
  }
  if (options.details !== undefined) envelope.details = options.details
  return envelope
}

export function isErrorEnvelope(value: unknown): value is ErrorEnvelope {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<ErrorEnvelope>
  return typeof candidate.code === 'string' &&
    candidate.code in FIDES_ERROR_CODES &&
    typeof candidate.category === 'string' &&
    typeof candidate.severity === 'string' &&
    typeof candidate.retryable === 'boolean' &&
    typeof candidate.message === 'string'
}
