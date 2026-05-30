import { describe, expect, it } from 'vitest'
import {
  computeCapabilityReputation,
  createReputationRecord,
} from '../src/reputation.js'

describe('capability-specific reputation v2', () => {
  it('does not let one capability reputation imply another capability', () => {
    const paymentRecord = createReputationRecord({
      agentId: 'did:fides:agent',
      issuer: 'did:fides:reputation-engine',
      recordId: 'rep_payments_execute',
      publisherId: 'did:fides:publisher',
      capability: 'payments.execute',
      successfulInvocations: 20,
      failedInvocations: 1,
      incidentCount: 0,
      publisherWeight: 0.8,
    })

    const calendarRecord = createReputationRecord({
      agentId: 'did:fides:agent',
      publisherId: 'did:fides:publisher',
      capability: 'calendar.schedule',
      successfulInvocations: 1,
      failedInvocations: 0,
      incidentCount: 0,
      publisherWeight: 0.8,
    })

    expect(paymentRecord.capability).toBe('payments.execute')
    expect(paymentRecord).toMatchObject({
      id: 'rep_payments_execute',
      issuer: 'did:fides:reputation-engine',
      subject: 'did:fides:agent',
      schema_version: 'fides.reputation.record.v1',
    })
    expect(paymentRecord.payload_hash).toMatch(/^sha256:/)
    expect(calendarRecord.capability).toBe('calendar.schedule')
    expect(paymentRecord.score).toBeGreaterThan(calendarRecord.score)
  })

  it('penalizes incidents and context laundering attempts', () => {
    const result = computeCapabilityReputation({
      agentId: 'did:fides:agent',
      publisherId: 'did:fides:publisher',
      capability: 'payments.execute',
      successfulInvocations: 20,
      failedInvocations: 0,
      incidentCount: 2,
      publisherWeight: 0.9,
      contextBoundaryMismatch: true,
    })

    expect(result.score).toBeLessThan(0.75)
    expect(result.payload_hash).toMatch(/^sha256:/)
    expect(result.reasons.map(reason => reason.factor)).toEqual(expect.arrayContaining([
      'incident_penalty',
      'context_boundary_penalty',
    ]))
  })

  it('changes payload_hash when reputation context changes', () => {
    const base = {
      agentId: 'did:fides:agent',
      recordId: 'rep_stable',
      issuer: 'did:fides:reputation-engine',
      capability: 'invoice.reconcile',
      successfulInvocations: 10,
      failedInvocations: 0,
      incidentCount: 0,
      publisherWeight: 0.7,
      computedAt: '2026-05-30T00:00:00.000Z',
    }

    const scoped = computeCapabilityReputation({
      ...base,
      principalId: 'did:fides:principal-a',
    })
    const otherPrincipal = computeCapabilityReputation({
      ...base,
      principalId: 'did:fides:principal-b',
    })

    expect(scoped.payload_hash).not.toBe(otherPrincipal.payload_hash)
  })
})
