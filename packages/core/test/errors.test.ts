import { describe, expect, it } from 'vitest'
import {
  createErrorEnvelope,
  FIDES_ERROR_CODES,
  isErrorEnvelope,
} from '../src/errors.js'

describe('error envelopes', () => {
  it('creates stable typed error envelopes', () => {
    const envelope = createErrorEnvelope('POLICY_DENIED', {
      details: { rule: 'revoked-agent-deny' },
    })

    expect(envelope).toEqual({
      code: 'POLICY_DENIED',
      category: 'policy',
      severity: 'error',
      retryable: false,
      message: 'Policy denied the request',
      details: { rule: 'revoked-agent-deny' },
    })
  })

  it('allows caller messages without changing machine fields', () => {
    const envelope = createErrorEnvelope('APPROVAL_REQUIRED', {
      message: 'Human approval is required for payments.prepare',
    })

    expect(envelope.code).toBe('APPROVAL_REQUIRED')
    expect(envelope.category).toBe(FIDES_ERROR_CODES.APPROVAL_REQUIRED.category)
    expect(envelope.retryable).toBe(true)
    expect(envelope.message).toBe('Human approval is required for payments.prepare')
  })

  it('detects error envelopes', () => {
    expect(isErrorEnvelope(createErrorEnvelope('DHT_POINTER_TAMPERED'))).toBe(true)
    expect(isErrorEnvelope({ code: 'NOPE' })).toBe(false)
    expect(isErrorEnvelope(null)).toBe(false)
  })

  it('covers incident and key-binding failures as stable protocol errors', () => {
    expect(createErrorEnvelope('IDENTITY_KEY_UNBOUND')).toMatchObject({
      code: 'IDENTITY_KEY_UNBOUND',
      category: 'identity',
      severity: 'critical',
      retryable: false,
    })
    expect(createErrorEnvelope('AGENT_CARD_INVALID_SIGNATURE')).toMatchObject({
      code: 'AGENT_CARD_INVALID_SIGNATURE',
      category: 'agent_card',
    })
    expect(createErrorEnvelope('INCIDENT_ACTIVE')).toMatchObject({
      code: 'INCIDENT_ACTIVE',
      category: 'incident',
      severity: 'critical',
    })
  })

  it('covers root local API validation and lookup failures', () => {
    expect(createErrorEnvelope('REQUEST_INVALID')).toMatchObject({
      code: 'REQUEST_INVALID',
      category: 'request',
      retryable: false,
    })
    expect(createErrorEnvelope('IDENTITY_NOT_FOUND')).toMatchObject({
      code: 'IDENTITY_NOT_FOUND',
      category: 'identity',
    })
    expect(createErrorEnvelope('AGENT_CARD_NOT_FOUND')).toMatchObject({
      code: 'AGENT_CARD_NOT_FOUND',
      category: 'agent_card',
    })
    expect(createErrorEnvelope('AGENT_NOT_REGISTERED')).toMatchObject({
      code: 'AGENT_NOT_REGISTERED',
      category: 'discovery',
    })
    expect(createErrorEnvelope('ATTESTATION_NOT_FOUND')).toMatchObject({
      code: 'ATTESTATION_NOT_FOUND',
      category: 'attestation',
    })
    expect(createErrorEnvelope('APPROVAL_NOT_FOUND')).toMatchObject({
      code: 'APPROVAL_NOT_FOUND',
      category: 'approval',
    })
    expect(createErrorEnvelope('KILL_SWITCH_RULE_NOT_FOUND')).toMatchObject({
      code: 'KILL_SWITCH_RULE_NOT_FOUND',
      category: 'kill_switch',
    })
    expect(createErrorEnvelope('REVOCATION_NOT_FOUND')).toMatchObject({
      code: 'REVOCATION_NOT_FOUND',
      category: 'revocation',
    })
    expect(createErrorEnvelope('INCIDENT_NOT_FOUND')).toMatchObject({
      code: 'INCIDENT_NOT_FOUND',
      category: 'incident',
    })
    expect(createErrorEnvelope('EVIDENCE_EVENT_NOT_FOUND')).toMatchObject({
      code: 'EVIDENCE_EVENT_NOT_FOUND',
      category: 'evidence',
    })
    expect(createErrorEnvelope('EVIDENCE_PRIVACY_MODE_INVALID')).toMatchObject({
      code: 'EVIDENCE_PRIVACY_MODE_INVALID',
      category: 'evidence',
    })
  })
})
