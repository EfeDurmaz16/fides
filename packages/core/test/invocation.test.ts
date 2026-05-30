import { describe, expect, it } from 'vitest'
import { createIdentityKeyPair } from '../src/identity.js'
import { createSessionGrantV2, signSessionGrantV2 } from '../src/delegation.js'
import {
  createInvocationRequest,
  createInvocationResult,
  evaluateInvocationPreflight,
  signInvocationRequest,
  signInvocationResult,
  validateInvocationRequestAgainstSessionGrant,
  validateJsonSchemaValue,
  verifySignedInvocationRequestIssuer,
  verifySignedInvocationRequest,
  verifySignedInvocationResultIssuer,
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
    expect(await verifySignedInvocationRequestIssuer(signed)).toBe(true)
  })

  it('rejects invocation request proofs whose verification method is not the issuer', async () => {
    const requester = await createIdentityKeyPair()
    const attacker = await createIdentityKeyPair()
    const grant = await signedGrant()
    const request = createInvocationRequest({
      issuer: requester.did,
      sessionGrant: grant.payload,
      input: { invoiceId: 'inv_123' },
    })

    const signed = await signInvocationRequest(request, attacker.privateKey, attacker.did)

    expect(await verifySignedInvocationRequest(signed)).toBe(true)
    expect(await verifySignedInvocationRequestIssuer(signed)).toBe(false)
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

  it('validates invocation requests against scoped SessionGrants', async () => {
    const grant = await signedGrant()
    const request = createInvocationRequest({
      issuer: 'did:fides:requester',
      sessionGrant: grant.payload,
      input: { invoiceId: 'inv_123' },
    })

    expect(validateInvocationRequestAgainstSessionGrant({
      request,
      sessionGrant: grant.payload,
    })).toEqual({ valid: true, errors: [] })
  })

  it('rejects invocation requests that exceed or mutate the SessionGrant', async () => {
    const grant = await signedGrant()
    const request = createInvocationRequest({
      issuer: 'did:fides:requester',
      sessionGrant: grant.payload,
      input: { invoiceId: 'inv_123' },
    })

    const result = validateInvocationRequestAgainstSessionGrant({
      request: {
        ...request,
        capability: 'payments.execute',
        scopes: ['invoice:read', 'payments:execute'],
      },
      sessionGrant: grant.payload,
    })

    expect(result.valid).toBe(false)
    expect(result.errors).toEqual(expect.arrayContaining([
      'InvocationRequest.payload_hash mismatch',
      'InvocationRequest.capability does not match SessionGrant',
      'InvocationRequest.scope payments:execute is not granted by SessionGrant',
    ]))
  })

  it('enforces dry-run-only SessionGrant constraints', async () => {
    const issuer = await createIdentityKeyPair()
    const grant = createSessionGrantV2({
      requesterAgentId: 'did:fides:requester',
      targetAgentId: 'did:fides:target',
      principalId: 'did:fides:principal',
      capability: 'payments.prepare',
      scopes: ['payments:prepare'],
      constraints: { dryRunOnly: true },
      policyHash: 'sha256:policy',
      trustResultHash: 'sha256:trust',
      issuer: issuer.did,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    })

    const executeRequest = createInvocationRequest({
      issuer: 'did:fides:requester',
      sessionGrant: grant,
      input: { amount: 100 },
      dryRun: false,
    })
    expect(validateInvocationRequestAgainstSessionGrant({
      request: executeRequest,
      sessionGrant: grant,
    })).toEqual({
      valid: false,
      errors: ['InvocationRequest.dry_run must be true for dry-run-only SessionGrant'],
    })

    const dryRunRequest = createInvocationRequest({
      issuer: 'did:fides:requester',
      sessionGrant: grant,
      input: { amount: 100 },
      dryRun: true,
    })
    expect(validateInvocationRequestAgainstSessionGrant({
      request: dryRunRequest,
      sessionGrant: grant,
    })).toEqual({ valid: true, errors: [] })
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
    expect(await verifySignedInvocationResultIssuer(signed)).toBe(true)
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
