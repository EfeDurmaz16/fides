import { describe, expect, it } from 'vitest'
import * as ed from '@noble/ed25519'
import {
  InMemorySessionStore,
  authorizeDelegation,
  authorizeSessionInvocation,
  createIncidentRecord,
  createRevocationRecord,
  signDelegationToken,
  signIncidentRecord,
  signRevocationRecord,
  validateDelegationToken,
  verifyDelegationTokenSignature,
  verifyIncidentRecord,
  verifyRevocationRecord,
  type DelegationToken,
  type IncidentRecord,
  type RevocationRecord,
} from '@fides/core'

const DELEGATOR_PRIVATE_KEY = Uint8Array.from(Buffer.from('01'.repeat(32), 'hex'))
const REPORTER_PRIVATE_KEY = Uint8Array.from(Buffer.from('02'.repeat(32), 'hex'))

const DELEGATOR_DID = 'did:fides:conformance-delegator'
const DELEGATEE_DID = 'did:fides:conformance-delegatee'
const REPORTER_DID = 'did:fides:conformance-reporter'
const AUDIENCE = 'agentd'
const PAYMENT_CAPABILITY = 'payments.authorize'

describe('FIDES authority conformance fixtures', () => {
  it('validates signed delegation tokens and rejects replay or tampering', async () => {
    const delegatorPublicKey = await ed.getPublicKeyAsync(DELEGATOR_PRIVATE_KEY)
    const token = await signDelegationToken(delegationFixture(), DELEGATOR_PRIVATE_KEY)

    expect(Object.keys(token).sort()).toEqual([
      'audience',
      'capabilities',
      'constraints',
      'delegatee',
      'delegator',
      'expiresAt',
      'id',
      'issuedAt',
      'nonce',
      'signature',
    ])
    expect(token.signature).toMatch(/^[a-f0-9]{128}$/)
    expect(validateDelegationToken(token)).toEqual({ valid: true, errors: [] })
    await expect(verifyDelegationTokenSignature(token, delegatorPublicKey)).resolves.toBe(true)

    const store = new InMemorySessionStore()
    const authorized = await authorizeDelegation({
      token,
      store,
      capabilityId: PAYMENT_CAPABILITY,
      audience: AUDIENCE,
      boundTo: 'https://merchant.example/checkout/123',
      ttlMs: 60_000,
    })
    expect(authorized.ok).toBe(true)
    expect(authorized.session?.token.id).toBe(token.id)

    const invocation = await authorizeSessionInvocation({
      sessionId: authorized.session?.id ?? '',
      store,
      capabilityId: PAYMENT_CAPABILITY,
      audience: AUDIENCE,
    })
    expect(invocation.ok).toBe(true)

    await expect(authorizeDelegation({ token, store })).resolves.toMatchObject({
      ok: false,
      errors: ['DelegationToken nonce has already been used'],
    })

    const tampered = { ...token, capabilities: ['payments.refund'] }
    await expect(verifyDelegationTokenSignature(tampered, delegatorPublicKey)).resolves.toBe(false)
  })

  it('validates signed revocation records and rejects tampering', async () => {
    const revokerPublicKey = await ed.getPublicKeyAsync(DELEGATOR_PRIVATE_KEY)
    const record = await signRevocationRecord(revocationFixture(), DELEGATOR_PRIVATE_KEY)

    expect(Object.keys(record).sort()).toEqual([
      'did',
      'id',
      'propagatedTo',
      'reason',
      'revokedAt',
      'revokedBy',
      'signature',
    ])
    expect(record.signature).toMatch(/^[a-f0-9]{128}$/)
    await expect(verifyRevocationRecord(record, revokerPublicKey)).resolves.toBe(true)

    const tampered = { ...record, reason: 'operator_error' }
    await expect(verifyRevocationRecord(tampered, revokerPublicKey)).resolves.toBe(false)
  })

  it('validates signed incident records and rejects tampering', async () => {
    const reporterPublicKey = await ed.getPublicKeyAsync(REPORTER_PRIVATE_KEY)
    const record = await signIncidentRecord(incidentFixture(), REPORTER_PRIVATE_KEY)

    expect(Object.keys(record).sort()).toEqual([
      'actor',
      'description',
      'evidenceRefs',
      'id',
      'impact',
      'reportedAt',
      'reportedBy',
      'severity',
      'signature',
      'type',
    ])
    expect(record.signature).toMatch(/^[a-f0-9]{128}$/)
    await expect(verifyIncidentRecord(record, reporterPublicKey)).resolves.toBe(true)

    const tampered = {
      ...record,
      impact: { ...record.impact, trustPenalty: 0 },
    }
    await expect(verifyIncidentRecord(tampered, reporterPublicKey)).resolves.toBe(false)
  })
})

function delegationFixture(): DelegationToken {
  return {
    id: 'fides-conformance-delegation-001',
    delegator: DELEGATOR_DID,
    delegatee: DELEGATEE_DID,
    capabilities: [PAYMENT_CAPABILITY, 'registry.write'],
    constraints: {
      maxActions: 3,
      maxSpend: '500.00',
      allowedContexts: ['checkout'],
      forbiddenContexts: ['wire-transfer'],
    },
    issuedAt: '2026-05-06T00:00:00.000Z',
    expiresAt: '2099-01-01T00:00:00.000Z',
    nonce: 'fides-conformance-nonce-001',
    audience: [AUDIENCE, 'registry'],
    signature: '',
  }
}

function revocationFixture(): RevocationRecord {
  return {
    ...createRevocationRecord({
      did: DELEGATEE_DID,
      reason: 'key_compromise',
      revokedBy: DELEGATOR_DID,
    }),
    id: 'fides-conformance-revocation-001',
    revokedAt: '2026-05-06T00:01:00.000Z',
  }
}

function incidentFixture(): IncidentRecord {
  return {
    ...createIncidentRecord({
      type: 'policy_violation',
      severity: 'high',
      actor: DELEGATEE_DID,
      reportedBy: REPORTER_DID,
      description: 'Delegatee attempted a payment outside the granted policy.',
      evidenceRefs: ['sha256:fides-conformance-evidence-001'],
      capabilitiesRevoked: [PAYMENT_CAPABILITY],
    }),
    id: 'fides-conformance-incident-001',
    reportedAt: '2026-05-06T00:02:00.000Z',
  }
}
