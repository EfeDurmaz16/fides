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
  | 'incident'
  | 'kill_switch'
  | 'version'
  | 'request'
  | 'internal'

export type FidesErrorSeverity = 'info' | 'warning' | 'error' | 'critical'

export const FIDES_ERROR_CODES = {
  IDENTITY_INVALID_SIGNATURE: {
    category: 'identity',
    severity: 'error',
    retryable: false,
    message: 'Identity signature is invalid',
  },
  IDENTITY_KEY_UNBOUND: {
    category: 'identity',
    severity: 'critical',
    retryable: false,
    message: 'Identity DID is not bound to the advertised public key',
  },
  IDENTITY_NOT_FOUND: {
    category: 'identity',
    severity: 'error',
    retryable: false,
    message: 'Identity was not found',
  },
  AGENT_CARD_INVALID_SIGNATURE: {
    category: 'agent_card',
    severity: 'error',
    retryable: false,
    message: 'AgentCard signature is invalid',
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
  AGENT_CARD_NOT_FOUND: {
    category: 'agent_card',
    severity: 'error',
    retryable: false,
    message: 'AgentCard was not found',
  },
  AGENT_NOT_REGISTERED: {
    category: 'discovery',
    severity: 'error',
    retryable: false,
    message: 'Agent is not registered',
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
  APPROVAL_NOT_FOUND: {
    category: 'approval',
    severity: 'error',
    retryable: false,
    message: 'Approval request was not found',
  },
  SESSION_EXPIRED: {
    category: 'session',
    severity: 'error',
    retryable: true,
    message: 'Session is expired',
  },
  SESSION_NOT_FOUND: {
    category: 'session',
    severity: 'error',
    retryable: false,
    message: 'Session was not found',
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
  ATTESTATION_NOT_FOUND: {
    category: 'attestation',
    severity: 'error',
    retryable: false,
    message: 'Attestation was not found',
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
  EVIDENCE_EVENT_NOT_FOUND: {
    category: 'evidence',
    severity: 'error',
    retryable: false,
    message: 'Evidence event was not found',
  },
  EVIDENCE_PRIVACY_MODE_INVALID: {
    category: 'evidence',
    severity: 'error',
    retryable: false,
    message: 'Evidence privacy mode is invalid',
  },
  REVOCATION_ACTIVE: {
    category: 'revocation',
    severity: 'critical',
    retryable: false,
    message: 'An active revocation blocks this action',
  },
  REVOCATION_NOT_FOUND: {
    category: 'revocation',
    severity: 'error',
    retryable: false,
    message: 'Revocation record was not found',
  },
  INCIDENT_ACTIVE: {
    category: 'incident',
    severity: 'critical',
    retryable: false,
    message: 'An active incident requires review before execution',
  },
  INCIDENT_INVALID: {
    category: 'incident',
    severity: 'error',
    retryable: false,
    message: 'Incident record is invalid',
  },
  INCIDENT_NOT_FOUND: {
    category: 'incident',
    severity: 'error',
    retryable: false,
    message: 'Incident record was not found',
  },
  KILL_SWITCH_ACTIVE: {
    category: 'kill_switch',
    severity: 'critical',
    retryable: false,
    message: 'Kill switch is active',
  },
  KILL_SWITCH_RULE_NOT_FOUND: {
    category: 'kill_switch',
    severity: 'error',
    retryable: false,
    message: 'Kill switch rule was not found',
  },
  VERSION_INCOMPATIBLE: {
    category: 'version',
    severity: 'error',
    retryable: false,
    message: 'Protocol versions are incompatible',
  },
  REQUEST_INVALID: {
    category: 'request',
    severity: 'error',
    retryable: false,
    message: 'Request payload is invalid',
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
