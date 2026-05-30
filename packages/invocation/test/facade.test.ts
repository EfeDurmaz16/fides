import { describe, expect, it } from 'vitest'
import { createInvocationRequest, createInvocationResult } from '../src/index.js'

describe('@fides/invocation facade', () => {
  it('exports invocation request and result primitives', () => {
    const request = createInvocationRequest({
      issuer: 'did:fides:requester',
      sessionGrant: {
        schema_version: 'fides.session_grant.v1',
        id: 'sess_1',
        session_id: 'sess_1',
        issuer: 'did:fides:issuer',
        subject: 'did:fides:target',
        requester_agent_id: 'did:fides:requester',
        target_agent_id: 'did:fides:target',
        principal_id: 'did:fides:principal',
        capability: 'invoice.reconcile',
        scopes: ['invoice:read'],
        constraints: {},
        policy_hash: 'sha256:policy',
        trust_result_hash: 'sha256:trust',
        issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        nonce: 'nonce',
        audience: ['did:fides:target'],
        supported_versions: ['fides.v2.0'],
        negotiated_version: 'fides.v2.0',
        payload_hash: 'sha256:payload',
        signature: 'sig',
      },
      input: { invoiceId: 'inv_123' },
      dryRun: true,
    })
    const result = createInvocationResult({
      issuer: 'did:fides:target',
      invocationRequestId: request.id,
      status: 'dry_run',
      output: { ok: true },
    })

    expect(request.session_id).toBe('sess_1')
    expect(result.invocation_request_id).toBe(request.id)
  })
})
