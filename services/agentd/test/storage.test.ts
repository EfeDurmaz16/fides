import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import postgres from 'postgres'
import { afterEach, describe, expect, it } from 'vitest'
import { appendEvidenceEvent, createEvidenceChain } from '@fides/evidence'
import { createDelegationToken, toStoredSession, createSessionGrant } from '@fides/core'
import {
  AUTHORITY_MIGRATIONS,
  FileAuthorityStore,
  InMemoryAuthorityStore,
  PostgresAuthorityStore,
  runAuthorityMigrations,
} from '../src/storage.js'

const tempDirs: string[] = []
const postgresUrl = process.env.AGENTD_DATABASE_URL || process.env.DATABASE_URL
const postgresTestRequired = process.env.AGENTD_POSTGRES_TEST_REQUIRED === 'true'

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

function postgresUrlWithSearchPath(connectionString: string, schema: string): string {
  const url = new URL(connectionString)
  url.searchParams.set('options', `-c search_path=${schema}`)
  return url.toString()
}

function quoteIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`
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
      reportedBy: grant.token.delegator,
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

  describe.skipIf(!postgresUrl && !postgresTestRequired)('postgres authority store', () => {
    if (!postgresUrl) {
      it('requires AGENTD_DATABASE_URL or DATABASE_URL when Postgres tests are mandatory', () => {
        expect(postgresUrl, 'AGENTD_DATABASE_URL or DATABASE_URL must be set when AGENTD_POSTGRES_TEST_REQUIRED=true').toBeTruthy()
      })

      return
    }

    it('records applied authority migrations once', async () => {
      const sql = postgres(postgresUrl, { max: 1 })

      try {
        await runAuthorityMigrations(sql)
        await runAuthorityMigrations(sql)

        const rows = await sql`
          SELECT id, checksum, count(*)::int AS count
          FROM agentd_schema_migrations
          WHERE id IN ${sql(AUTHORITY_MIGRATIONS.map(migration => migration.id))}
          GROUP BY id, checksum
        `

        expect(rows).toHaveLength(AUTHORITY_MIGRATIONS.length)
        expect(rows.every(row => row.count === 1)).toBe(true)
        expect(rows.every(row => typeof row.checksum === 'string' && row.checksum.length === 64)).toBe(true)
      } finally {
        await sql.end()
      }
    }, 30_000)

    it('fails closed when an applied migration checksum drifts', async () => {
      const schema = `agentd_migration_checksum_${crypto.randomUUID().replaceAll('-', '')}`
      const schemaIdentifier = quoteIdentifier(schema)
      const adminSql = postgres(postgresUrl, { max: 1 })
      const scopedUrl = postgresUrlWithSearchPath(postgresUrl, schema)
      const scopedSql = postgres(scopedUrl, { max: 1 })

      try {
        await adminSql.unsafe(`CREATE SCHEMA ${schemaIdentifier}`)
        await runAuthorityMigrations(scopedSql)
        await scopedSql`
          UPDATE agentd_schema_migrations
          SET checksum = ${'0'.repeat(64)}
          WHERE id = ${AUTHORITY_MIGRATIONS[0].id}
        `

        await expect(runAuthorityMigrations(scopedSql)).rejects.toThrow('checksum mismatch')
        const store = new PostgresAuthorityStore(scopedUrl)
        try {
          const health = await store.healthCheck()
          expect(health.ok).toBe(false)
          expect(health.detail).toContain('checksum mismatch')
        } finally {
          await store.close()
        }
      } finally {
        await scopedSql.end()
        await adminSql.unsafe(`DROP SCHEMA IF EXISTS ${schemaIdentifier} CASCADE`)
        await adminSql.end()
      }
    }, 30_000)

    it('round-trips authority state through Postgres', async () => {
      const store = new PostgresAuthorityStore(postgresUrl)
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

    it('fails closed without manual migrations when auto-migrate is disabled', async () => {
      const schema = `agentd_manual_migration_${crypto.randomUUID().replaceAll('-', '')}`
      const schemaIdentifier = quoteIdentifier(schema)
      const adminSql = postgres(postgresUrl, { max: 1 })
      const scopedUrl = postgresUrlWithSearchPath(postgresUrl, schema)
      const scopedSql = postgres(scopedUrl, { max: 1 })
      const previousAutoMigrate = process.env.AGENTD_DB_AUTO_MIGRATE

      try {
        await adminSql.unsafe(`CREATE SCHEMA ${schemaIdentifier}`)
        process.env.AGENTD_DB_AUTO_MIGRATE = 'false'

        const unmigratedStore = new PostgresAuthorityStore(scopedUrl)
        try {
          const health = await unmigratedStore.healthCheck()
          expect(health.ok).toBe(false)
          expect(health.detail).toContain('agentd authority store schema is not migrated')
        } finally {
          await unmigratedStore.close()
        }

        await runAuthorityMigrations(scopedSql)

        const migratedStore = new PostgresAuthorityStore(scopedUrl)
        try {
          await migratedStore.markNonceUsed({
            nonce: crypto.randomUUID(),
            tokenId: crypto.randomUUID(),
            usedAt: new Date().toISOString(),
          })
          expect((await migratedStore.healthCheck()).ok).toBe(true)
        } finally {
          await migratedStore.close()
        }
      } finally {
        if (previousAutoMigrate === undefined) {
          delete process.env.AGENTD_DB_AUTO_MIGRATE
        } else {
          process.env.AGENTD_DB_AUTO_MIGRATE = previousAutoMigrate
        }
        await scopedSql.end()
        await adminSql.unsafe(`DROP SCHEMA IF EXISTS ${schemaIdentifier} CASCADE`)
        await adminSql.end()
      }
    }, 30_000)
  })
})
