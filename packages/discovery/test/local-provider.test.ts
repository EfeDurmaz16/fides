import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { createAgentIdentity, signAgentCard, type AgentCard } from '@fides/core'
import { LocalDiscoveryProvider } from '../src/local-provider.js'

describe('LocalDiscoveryProvider', () => {
  const tempDirs: string[] = []

  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  async function signedCard() {
    const agent = await createAgentIdentity()
    const card: AgentCard = {
      id: agent.identity.did,
      agent_id: agent.identity.did,
      identity: agent.identity,
      capabilities: [],
      endpoints: [],
      policies: [{ requiresRuntimeAttestation: false, requiresApproval: false }],
      createdAt: '2026-05-30T00:00:00.000Z',
      updatedAt: '2026-05-30T00:00:00.000Z',
    }
    return {
      agent,
      card,
      signed: await signAgentCard(card, agent.privateKey, agent.identity.did),
    }
  }

  function provider() {
    const dir = mkdtempSync(join(tmpdir(), 'fides-local-provider-'))
    tempDirs.push(dir)
    return new LocalDiscoveryProvider({ storePath: join(dir, 'local-agents.json') })
  }

  it('registers identity-bound signed AgentCards in the local store', async () => {
    const { card, signed } = await signedCard()
    const local = provider()

    await expect(local.register(signed)).resolves.toBeUndefined()

    await expect(local.resolve(card.id)).resolves.toMatchObject({ id: card.id })
  })

  it('rejects AgentCards not signed by the advertised agent identity', async () => {
    const { card } = await signedCard()
    const attacker = await createAgentIdentity()
    const signed = await signAgentCard(card, attacker.privateKey, attacker.identity.did)
    const local = provider()

    await expect(local.register(signed)).rejects.toThrow(
      'Local registration requires an identity-bound signed AgentCard',
    )
    await expect(local.resolve(card.id)).resolves.toBeNull()
  })
})
