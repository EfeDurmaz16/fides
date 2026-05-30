import { describe, expect, it } from 'vitest'
import {
  createAgentIdentity,
  createCapabilityDescriptor,
  createDHTPointerRecord,
  hashAgentCard,
  hashCapability,
  signDHTPointerRecord,
  verifyDHTPointerRecord,
  type AgentCard,
} from '../src/index.js'

describe('DHT pointer records', () => {
  async function fixture() {
    const publisher = await createAgentIdentity()
    const agent = await createAgentIdentity()
    const card: AgentCard = {
      id: agent.identity.did,
      agent_id: agent.identity.did,
      identity: agent.identity,
      capabilities: [createCapabilityDescriptor({ id: 'invoice.reconcile' })],
      endpoints: [{ url: 'https://agent.example/card.json', protocol: 'https' }],
      policies: [{ requiresRuntimeAttestation: false, requiresApproval: false }],
      createdAt: '2026-05-29T00:00:00.000Z',
      updatedAt: '2026-05-29T00:00:00.000Z',
    }
    const record = createDHTPointerRecord({
      capability: 'invoice.reconcile',
      agentId: agent.identity.did,
      agentCardUrl: 'https://agent.example/card.json',
      agentCardHash: hashAgentCard(card),
      publisherId: publisher.identity.did,
      expiresAt: '2999-01-01T00:00:00.000Z',
    })
    return {
      card,
      publisher,
      record: await signDHTPointerRecord(record, publisher.privateKey),
    }
  }

  it('accepts a valid signed pointer', async () => {
    const { card, record } = await fixture()

    await expect(verifyDHTPointerRecord(record, { card })).resolves.toEqual({ valid: true, errors: [] })
    expect(record.capability_hash).toBe(hashCapability('invoice.reconcile'))
  })

  it('rejects tampered pointers', async () => {
    const { card, record } = await fixture()
    const result = await verifyDHTPointerRecord({ ...record, capability: 'payments.execute' }, { card })

    expect(result.valid).toBe(false)
    expect(result.errors).toEqual(expect.arrayContaining([
      'DHT pointer capability_hash mismatch',
      'DHT pointer signature is invalid',
    ]))
  })

  it('rejects pointer signatures whose verification method does not match publisher_id', async () => {
    const { card, record } = await fixture()
    const attacker = await createAgentIdentity()
    const signed = await signDHTPointerRecord(record, attacker.privateKey, attacker.identity.did)

    const result = await verifyDHTPointerRecord(signed, {
      card,
      verificationMethod: attacker.identity.did,
    })

    expect(result.valid).toBe(false)
    expect(result.errors).toContain('DHT pointer verificationMethod must match publisher_id')
  })

  it('rejects expired pointers', async () => {
    const { card, record } = await fixture()
    const result = await verifyDHTPointerRecord({
      ...record,
      expires_at: '2026-05-28T00:00:00.000Z',
    }, {
      card,
      now: new Date('2026-05-29T00:00:00.000Z'),
    })

    expect(result.valid).toBe(false)
    expect(result.errors).toEqual(expect.arrayContaining([
      'DHT pointer is expired',
      'DHT pointer signature is invalid',
    ]))
  })

  it('rejects card hash mismatches', async () => {
    const { card, record } = await fixture()
    const result = await verifyDHTPointerRecord(record, {
      card: { ...card, updatedAt: '2026-05-30T00:00:00.000Z' },
    })

    expect(result.valid).toBe(false)
    expect(result.errors).toContain('DHT pointer agent_card_hash mismatch')
  })

  it('rejects pointers for capabilities not advertised by the AgentCard', async () => {
    const { card, publisher } = await fixture()
    const record = createDHTPointerRecord({
      capability: 'payments.execute',
      agentId: card.identity.did,
      agentCardUrl: 'https://agent.example/card.json',
      agentCardHash: hashAgentCard(card),
      publisherId: publisher.identity.did,
      expiresAt: '2999-01-01T00:00:00.000Z',
    })
    const signed = await signDHTPointerRecord(record, publisher.privateKey)

    const result = await verifyDHTPointerRecord(signed, { card })

    expect(result.valid).toBe(false)
    expect(result.errors).toContain('DHT pointer capability is not advertised by AgentCard')
  })
})
