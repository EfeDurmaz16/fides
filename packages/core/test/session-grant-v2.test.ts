import { describe, expect, it } from 'vitest'
import { createIdentityKeyPair } from '../src/identity.js'
import {
  createSessionGrantV2,
  isSessionGrantV2Expired,
  signSessionGrantV2,
  validateSessionGrantV2,
  verifySignedSessionGrantV2,
} from '../src/delegation.js'

describe('SessionGrant v2', () => {
  it('creates a scoped session grant with audience, nonce, and hashes', async () => {
    const issuer = await createIdentityKeyPair()
    const grant = createSessionGrantV2({
      requesterAgentId: 'did:fides:requester',
      targetAgentId: 'did:fides:target',
      principalId: 'did:fides:principal',
      capability: 'invoice.reconcile',
      scopes: ['invoice:read'],
      constraints: { maxActions: 3 },
      policyHash: 'sha256:policy',
      trustResultHash: 'sha256:trust',
      audience: ['did:fides:target'],
      issuer: issuer.did,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    })

    expect(grant).toMatchObject({
      schema_version: 'fides.session_grant.v1',
      id: grant.session_id,
      subject: 'did:fides:target',
      requester_agent_id: 'did:fides:requester',
      target_agent_id: 'did:fides:target',
      principal_id: 'did:fides:principal',
      capability: 'invoice.reconcile',
      scopes: ['invoice:read'],
      policy_hash: 'sha256:policy',
      trust_result_hash: 'sha256:trust',
      audience: ['did:fides:target'],
      issuer: issuer.did,
    })
    expect(grant.id).toBe(grant.session_id)
    expect(grant.nonce).toBeTruthy()
    expect(validateSessionGrantV2(grant)).toEqual({ valid: true, errors: [] })
    expect(isSessionGrantV2Expired(grant)).toBe(false)
  })

  it('signs and verifies a session grant using the canonical signing model', async () => {
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

    const signed = await signSessionGrantV2(grant, issuer.privateKey, issuer.did)
    expect(await verifySignedSessionGrantV2(signed)).toBe(true)
  })

  it('rejects grants whose shared object ids or subjects drift from session binding', async () => {
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

    expect(validateSessionGrantV2({
      ...grant,
      id: 'different-id',
      subject: 'did:fides:other-target',
    })).toEqual({
      valid: false,
      errors: [
        'SessionGrant.id must match SessionGrant.session_id',
        'SessionGrant.subject must match SessionGrant.target_agent_id',
      ],
    })
  })
})
