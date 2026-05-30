import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it } from 'vitest'
import {
  authorizeDelegation,
  authorizeDelegationV2,
  authorizeSessionInvocation,
  createDelegationToken,
  createDelegationTokenV2,
  createIdentityKeyPair,
  FileSessionStore,
  InMemorySessionStore,
  signDelegationTokenV2,
} from '../src/index.js'

const tempDirs: string[] = []

afterEach(async () => {
  await Promise.all(tempDirs.map(dir => rm(dir, { recursive: true, force: true })))
  tempDirs.length = 0
})

function makeSignedToken(overrides: Record<string, unknown> = {}) {
  return {
    ...createDelegationToken({
      delegator: 'did:fides:delegator',
      delegatee: 'did:fides:delegatee',
      capabilities: ['payments.execute', 'files.read'],
      constraints: {},
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      audience: ['agentd'],
    }),
    signature: '00'.repeat(64),
    ...overrides,
  }
}

async function makeTempStore() {
  const dir = await mkdtemp(join(tmpdir(), 'fides-session-store-'))
  tempDirs.push(dir)
  return new FileSessionStore(join(dir, 'store.json'))
}

describe('SessionStore authorization', () => {
  it('creates a session and records the token nonce', async () => {
    const store = new InMemorySessionStore()
    const token = makeSignedToken()

    const result = await authorizeDelegation({
      token,
      store,
      capabilityId: 'payments.execute',
      audience: 'agentd',
    })

    expect(result.ok).toBe(true)
    expect(result.session?.token.id).toBe(token.id)
    expect(await store.hasNonce(token.nonce)).toBe(true)
  })

  it('rejects replayed delegation nonces', async () => {
    const store = new InMemorySessionStore()
    const token = makeSignedToken()

    await authorizeDelegation({ token, store, capabilityId: 'payments.execute', audience: 'agentd' })
    const replay = await authorizeDelegation({ token, store, capabilityId: 'payments.execute', audience: 'agentd' })

    expect(replay.ok).toBe(false)
    expect(replay.errors).toContain('DelegationToken nonce has already been used')
  })

  it('creates sessions from issuer-bound canonical delegation tokens', async () => {
    const store = new InMemorySessionStore()
    const { privateKey, did: delegator } = await createIdentityKeyPair()
    const token = createDelegationTokenV2({
      delegator,
      delegatee: 'did:fides:delegatee',
      capabilities: ['payments.execute'],
      constraints: { maxActions: 1 },
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      audience: ['agentd'],
      nonce: 'nonce_v2_authorized',
    })
    const signedToken = await signDelegationTokenV2(token, privateKey, delegator)

    const result = await authorizeDelegationV2({
      signedToken,
      store,
      capabilityId: 'payments.execute',
      audience: 'agentd',
    })

    expect(result.ok).toBe(true)
    expect(result.session?.token).toMatchObject({
      id: token.id,
      delegator,
      delegatee: 'did:fides:delegatee',
      capabilities: ['payments.execute'],
      issuedAt: token.issued_at,
      expiresAt: token.expires_at,
      nonce: 'nonce_v2_authorized',
      signature: signedToken.proof.proofValue,
    })
    expect(await store.hasNonce(token.nonce)).toBe(true)
  })

  it('rejects canonical delegation tokens signed by a different issuer', async () => {
    const store = new InMemorySessionStore()
    const { did: delegator } = await createIdentityKeyPair()
    const wrongIssuer = await createIdentityKeyPair()
    const token = createDelegationTokenV2({
      delegator,
      delegatee: 'did:fides:delegatee',
      capabilities: ['payments.execute'],
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      audience: ['agentd'],
    })
    const signedToken = await signDelegationTokenV2(token, wrongIssuer.privateKey, wrongIssuer.did)

    const result = await authorizeDelegationV2({
      signedToken,
      store,
      capabilityId: 'payments.execute',
      audience: 'agentd',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toContain('DelegationToken canonical signature verification failed')
    expect(await store.listSessions()).toHaveLength(0)
  })

  it('rejects missing capabilities before creating a session', async () => {
    const store = new InMemorySessionStore()

    const result = await authorizeDelegation({
      token: makeSignedToken(),
      store,
      capabilityId: 'wallets.sign',
      audience: 'agentd',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toContain('DelegationToken does not grant capability wallets.sign')
    expect(await store.listSessions()).toHaveLength(0)
  })

  it('rejects audience mismatches', async () => {
    const store = new InMemorySessionStore()

    const result = await authorizeDelegation({
      token: makeSignedToken(),
      store,
      capabilityId: 'payments.execute',
      audience: 'registry',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toContain('DelegationToken audience does not include registry')
  })

  it('rejects expired delegation tokens', async () => {
    const store = new InMemorySessionStore()

    const result = await authorizeDelegation({
      token: makeSignedToken({ expiresAt: new Date(Date.now() - 1000).toISOString() }),
      store,
      capabilityId: 'payments.execute',
      audience: 'agentd',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toContain('DelegationToken is expired')
  })

  it('rejects revoked sessions during invocation authorization', async () => {
    const store = new InMemorySessionStore()
    const created = await authorizeDelegation({
      token: makeSignedToken(),
      store,
      capabilityId: 'payments.execute',
      audience: 'agentd',
    })

    await store.revokeSession(created.session!.id, 'principal revoked')
    const result = await authorizeSessionInvocation({
      sessionId: created.session!.id,
      store,
      capabilityId: 'payments.execute',
      audience: 'agentd',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toContain('SessionGrant is revoked')
  })

  it('persists sessions and nonces through the file-backed store', async () => {
    const store = await makeTempStore()
    const token = makeSignedToken()
    const created = await authorizeDelegation({
      token,
      store,
      capabilityId: 'payments.execute',
      audience: 'agentd',
    })
    const reopened = new FileSessionStore(join(tempDirs[0]!, 'store.json'))

    expect(await reopened.hasNonce(token.nonce)).toBe(true)
    expect((await reopened.getSession(created.session!.id))?.id).toBe(created.session!.id)
  })
})
