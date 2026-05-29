import { describe, it, expect } from 'vitest'
import { normalizeAgentCard, signAgentCard, validateAgentCard, verifySignedAgentCard } from '../src/agent-card.js'
import type { AgentCard } from '../src/agent-card.js'
import { createAgentIdentity } from '../src/identity.js'

describe('AgentCard', () => {
  const validCard: AgentCard = {
    id: 'did:fides:test',
    identity: {
      did: 'did:fides:test',
      publicKey: new Uint8Array(32),
      keyType: 'Ed25519',
      createdAt: new Date().toISOString(),
    },
    capabilities: [],
    endpoints: [],
    policies: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  describe('validateAgentCard', () => {
    it('should validate a correct card', () => {
      const result = validateAgentCard(validCard)
      expect(result.valid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should reject missing id', () => {
      const card = { ...validCard, id: '' }
      const result = validateAgentCard(card)
      expect(result.valid).toBe(false)
      expect(result.errors).toContain('AgentCard.id is required')
    })

    it('should reject missing identity.did', () => {
      const card = { ...validCard, identity: { ...validCard.identity, did: '' } }
      const result = validateAgentCard(card)
      expect(result.valid).toBe(false)
      expect(result.errors).toContain('AgentCard.identity.did is required')
    })

    it('should reject invalid public key length', () => {
      const card = { ...validCard, identity: { ...validCard.identity, publicKey: new Uint8Array(16) } }
      const result = validateAgentCard(card)
      expect(result.valid).toBe(false)
      expect(result.errors).toContain('AgentCard.identity.publicKey must be 32 bytes')
    })

    it('should reject missing capabilities array', () => {
      const card = { ...validCard, capabilities: undefined as any }
      const result = validateAgentCard(card)
      expect(result.valid).toBe(false)
      expect(result.errors).toContain('AgentCard.capabilities must be an array')
    })

    it('should reject mismatched agent_id', () => {
      const result = validateAgentCard({
        ...validCard,
        agent_id: 'did:fides:other',
      })

      expect(result.valid).toBe(false)
      expect(result.errors).toContain('AgentCard.agent_id must match AgentCard.identity.did')
    })

    it('should normalize v2 schema and agent id fields', () => {
      expect(normalizeAgentCard(validCard)).toMatchObject({
        schema_version: 'fides.agent_card.v1',
        agent_id: validCard.identity.did,
      })
    })

    it('should sign and verify AgentCards with the canonical signing model', async () => {
      const issued = await createAgentIdentity()
      const card: AgentCard = {
        ...validCard,
        id: issued.identity.did,
        identity: issued.identity,
        capabilities: [
          {
            id: 'calendar.schedule',
            namespace: 'calendar',
            action: 'schedule',
            resource: 'event',
            name: 'Schedule calendar event',
            description: 'Schedule a calendar event',
            inputSchema: { type: 'object' },
            outputSchema: { type: 'object' },
            riskLevel: 'low',
            requiresApproval: false,
            requiresRuntimeAttestation: false,
            requiredScopes: ['calendar:write'],
            supportedControls: ['dry_run'],
            supportsDryRun: true,
          },
        ],
        protocolVersions: ['fides.v2.0'],
        expiresAt: '2999-01-01T00:00:00.000Z',
      }

      const signed = await signAgentCard(card, issued.privateKey, issued.identity.did)

      expect(signed.payload.schema_version).toBe('fides.agent_card.v1')
      expect(signed.payload.agent_id).toBe(issued.identity.did)
      expect(await verifySignedAgentCard(signed)).toBe(true)

      signed.payload.capabilities[0].name = 'Tampered'
      expect(await verifySignedAgentCard(signed)).toBe(false)
    })
  })
})
