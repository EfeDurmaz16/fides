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

  it('returns verified discovery candidates for persisted signed AgentCards', async () => {
    const { agent, card } = await signedCard()
    card.capabilities = [{
      id: 'invoice.reconcile',
      namespace: 'invoice',
      action: 'reconcile',
      resource: 'invoice',
      inputSchema: { type: 'object' },
      outputSchema: { type: 'object' },
      riskClass: 'medium',
      requiredScopes: ['read:invoices'],
      supportedControls: ['dry_run', 'human_approval'],
      dryRunSupported: true,
      humanApprovalSupported: true,
      policyProofSupported: false,
    }]
    const signed = await signAgentCard(card, agent.privateKey, agent.identity.did)
    const dir = mkdtempSync(join(tmpdir(), 'fides-local-provider-'))
    tempDirs.push(dir)
    const storePath = join(dir, 'local-agents.json')
    const local = new LocalDiscoveryProvider({ storePath })

    await local.register(signed)

    const reloaded = new LocalDiscoveryProvider({ storePath })
    const candidates = await reloaded.discover({
      schema_version: 'fides.discovery_query.v1',
      id: 'query_1',
      capability: 'invoice.reconcile',
    })

    expect(candidates).toHaveLength(1)
    expect(candidates[0]).toMatchObject({
      agentId: card.id,
      capability: 'invoice.reconcile',
      verified: true,
      authority: 'candidate_only',
    })
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
