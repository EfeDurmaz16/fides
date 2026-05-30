import { describe, expect, it } from 'vitest'
import { createIdentityKeyPair } from '../src/identity.js'
import { createSessionGrantV2, signSessionGrantV2 } from '../src/delegation.js'
import {
  createInvocationRequest,
  createInvocationResult,
  evaluateInvocationPreflight,
  signInvocationRequest,
  signInvocationResult,
  validateJsonSchemaValue,
  verifySignedInvocationRequest,
  verifySignedInvocationResult,
} from '../src/invocation.js'

async function signedGrant() {
  const issuer = await createIdentityKeyPair()
  const grant = createSessionGrantV2({
    requesterAgentId: 'did:fides:requester',
    targetAgentId: 'did:fides:target',
    principalId: 'did:fides:principal',
    capability: 'invoice.reconcile',
    scopes: ['invoice:read'],
    constraints: {},
    policyHash: 'sha256:policy',
    trustResultHash: 'sha256:trust',
    issuer: issuer.did,
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
  })
  return signSessionGrantV2(grant, issuer.privateKey, issuer.did)
}

describe('invocation protocol objects', () => {
  it('creates and verifies signed invocation requests', async () => {
    const requester = await createIdentityKeyPair()
    const grant = await signedGrant()
    const request = createInvocationRequest({
      issuer: requester.did,
      sessionGrant: grant.payload,
      input: { invoiceId: 'inv_123' },
      dryRun: true,
    })

    expect(request.input_hash).toMatch(/^sha256:/)
    expect(request.output_schema_hash).toBeUndefined()
    expect(request.issuer).toBe(requester.did)
    expect(request.subject).toBe('did:fides:target')
    expect(request.payload_hash).toMatch(/^sha256:/)

    const signed = await signInvocationRequest(request, requester.privateKey, requester.did)
    expect(await verifySignedInvocationRequest(signed)).toBe(true)
  })

  it('preflights denied and approval-required policy decisions without execution', async () => {
    const grant = await signedGrant()
    const request = createInvocationRequest({
      issuer: 'did:fides:requester',
      sessionGrant: grant.payload,
      input: { invoiceId: 'inv_123' },
    })

    const denied = evaluateInvocationPreflight({
      request,
      policyDecision: { decision: 'deny', reason_codes: ['POLICY_DENIED'] },
    })
    expect(denied.status).toBe('denied')

    const pending = evaluateInvocationPreflight({
      request,
      policyDecision: { decision: 'require_approval', reason_codes: ['APPROVAL_REQUIRED'] },
    })
    expect(pending.status).toBe('approval_required')
  })

  it('creates and verifies signed invocation results', async () => {
    const target = await createIdentityKeyPair()
    const result = createInvocationResult({
      issuer: target.did,
      invocationRequestId: 'inv_req_1',
      status: 'completed',
      output: { ok: true },
      evidenceRefs: ['evt_1'],
    })

    expect(result.output_hash).toMatch(/^sha256:/)
    expect(result.issuer).toBe(target.did)
    expect(result.subject).toBe('inv_req_1')
    expect(result.payload_hash).toMatch(/^sha256:/)
    const signed = await signInvocationResult(result, target.privateKey, target.did)
    expect(await verifySignedInvocationResult(signed)).toBe(true)
  })

  it('validates invocation inputs and outputs against a JSON Schema subset', () => {
    const schema = {
      type: 'object',
      required: ['invoiceId', 'amount'],
      additionalProperties: false,
      properties: {
        invoiceId: { type: 'string' },
        amount: { type: 'number' },
        dryRun: { type: 'boolean' },
      },
    }

    expect(validateJsonSchemaValue(schema, {
      invoiceId: 'inv_123',
      amount: 42,
      dryRun: true,
    })).toEqual({ valid: true, errors: [] })

    const invalid = validateJsonSchemaValue(schema, {
      invoiceId: 123,
      unexpected: true,
    })
    expect(invalid.valid).toBe(false)
    expect(invalid.errors).toEqual(expect.arrayContaining([
      '$.amount is required',
      '$.invoiceId must be string',
      '$.unexpected is not allowed',
    ]))
  })
})
