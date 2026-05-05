import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it } from 'vitest'
import { appendEvidenceEvent, createEvidenceChain } from '@fides/evidence'
import { createDelegationToken, toStoredSession, createSessionGrant } from '@fides/core'
import { FileAuthorityStore, InMemoryAuthorityStore, PostgresAuthorityStore } from '../src/storage.js'

const tempDirs: string[] = []
const postgresUrl = process.env.AGENTD_DATABASE_URL || process.env.DATABASE_URL

afterEach(async () => {
  await Promise.all(tempDirs.map(dir => rm(dir, { recursive: true, force: true })))
  tempDirs.length = 0
})

async function tempStore() {
  const dir = await mkdtemp(join(tmpdir(), 'fides-agentd-store-'))
  tempDirs.push(dir)
  return new FileAuthorityStore(join(dir, 'authority.json'))
}

function session() {
  const token = {
    ...createDelegationToken({
      delegator: 'did:fides:principal',
      delegatee: 'did:fides:agent',
      capabilities: ['payments.execute'],
      constraints: {},
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      audience: ['agentd'],
    }),
    signature: '00'.repeat(64),
  }
  return toStoredSession(createSessionGrant({ token }))
}

describe('agentd authority stores', () => {
  it('persists sessions, evidence, revocations, and incidents to a file', async () => {
    const store = await tempStore()
    const grant = session()
    let chain = createEvidenceChain()
    chain = appendEvidenceEvent(chain, {
      id: 'event-1',
      type: 'authorization',
      timestamp: new Date().toISOString(),
      actor: grant.token.delegatee,
      action: 'authorization.allow',
      payload: {},
      privacy: { level: 'private' },
    }, 'test')

    await store.markNonceUsed({ nonce: grant.token.nonce, tokenId: grant.token.id, usedAt: new Date().toISOString() })
    await store.createSession(grant)
    await store.setEvidenceChain(grant.token.delegatee, chain)
    await store.putRevocation({
      id: 'rev-1',
      did: grant.token.delegatee,
      reason: 'test',
      revokedAt: new Date().toISOString(),
      revokedBy: grant.token.delegator,
      signature: 'test',
      propagatedTo: [],
    })
    await store.putIncident({
      id: 'inc-1',
      actor: grant.token.delegatee,
      type: 'policy_violation',
      severity: 'high',
      description: 'test',
      evidenceRefs: ['event-1'],
      reportedAt: new Date().toISOString(),
      impact: { trustPenalty: 0.35, reputationPenalty: 0.7, capabilitiesRevoked: ['payments.execute'] },
      signature: 'test',
    })
    await store.enqueuePropagation({
      id: 'prop-1',
      actor: grant.token.delegatee,
      recordType: 'revocation',
      recordId: 'rev-1',
      target: 'trust-graph',
      path: '/v1/revocations',
      body: { did: grant.token.delegatee },
      status: 'pending',
      attempts: 1,
      maxAttempts: 3,
      nextAttemptAt: new Date().toISOString(),
      lastAttemptAt: new Date().toISOString(),
      lastStatus: 0,
      lastError: 'unavailable',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    })

    const reopened = new FileAuthorityStore(join(tempDirs[0]!, 'authority.json'))
    expect(await reopened.hasNonce(grant.token.nonce)).toBe(true)
    expect((await reopened.getSession(grant.id))?.id).toBe(grant.id)
    expect((await reopened.getEvidenceChain(grant.token.delegatee))?.events).toHaveLength(1)
    expect((await reopened.getRevocation(grant.token.delegatee))?.reason).toBe('test')
    expect(await reopened.listIncidents(grant.token.delegatee)).toHaveLength(1)
    expect(await reopened.listPendingPropagations()).toHaveLength(1)
    const updated = await reopened.updatePropagationAttempt('prop-1', {
      ok: true,
      status: 201,
      attemptedAt: new Date().toISOString(),
    })
    expect(updated?.status).toBe('confirmed')
    expect(await reopened.listPendingPropagations()).toHaveLength(0)
  })

  it('revokes sessions consistently in memory', async () => {
    const store = new InMemoryAuthorityStore()
    const grant = session()
    await store.createSession(grant)

    const revoked = await store.revokeSession(grant.id, 'manual')

    expect(revoked?.revoked).toBe(true)
    expect((await store.getSession(grant.id))?.revocationReason).toBe('manual')
  })

  describe.skipIf(!postgresUrl)('postgres authority store', () => {
    it('round-trips authority state through Postgres', async () => {
      const store = new PostgresAuthorityStore(postgresUrl!)
      const did = `did:fides:pg-agent-${crypto.randomUUID()}`
      const baseSession = session()
      const grant = {
        ...baseSession,
        token: {
          ...baseSession.token,
          delegatee: did,
          nonce: crypto.randomUUID(),
        },
      }

      try {
        await store.markNonceUsed({ nonce: grant.token.nonce, tokenId: grant.token.id, usedAt: new Date().toISOString() })
        await store.createSession(grant)
        await store.putRevocation({
          id: crypto.randomUUID(),
          did,
          reason: 'postgres test',
          revokedAt: new Date().toISOString(),
          revokedBy: grant.token.delegator,
          signature: 'test',
          propagatedTo: [],
        })
        await store.putIncident({
          id: crypto.randomUUID(),
          actor: did,
          type: 'policy_violation',
          severity: 'medium',
          description: 'postgres test',
          evidenceRefs: [],
          reportedAt: new Date().toISOString(),
          impact: { trustPenalty: 0.15, reputationPenalty: 0.3, capabilitiesRevoked: [] },
          signature: 'test',
        })

        expect(await store.hasNonce(grant.token.nonce)).toBe(true)
        expect((await store.getSession(grant.id))?.token.delegatee).toBe(did)
        expect((await store.getRevocation(did))?.reason).toBe('postgres test')
        expect(await store.listIncidents(did)).toHaveLength(1)
        expect((await store.healthCheck()).ok).toBe(true)
      } finally {
        await store.close()
      }
    }, 30_000)
  })
})
