import { describe, it, expect } from 'vitest'
import {
  normalizeAgentCard,
  signAgentCard,
  validateAgentCard,
  verifySignedAgentCard,
  verifySignedAgentCardIdentity,
} from '../src/agent-card.js'
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

    it('should reject invalid transports metadata', () => {
      const card = { ...validCard, transports: 'stdio' as any }
      const result = validateAgentCard(card)
      expect(result.valid).toBe(false)
      expect(result.errors).toContain('AgentCard.transports must be an array')
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
      const normalized = normalizeAgentCard(validCard)

      expect(normalized).toMatchObject({
        schema_version: 'fides.agent_card.v1',
        agent_id: validCard.identity.did,
        protocolVersions: ['fides.v2.0'],
      })
      expect(normalized.publicKeys?.[0]).toMatchObject({
        id: `${validCard.identity.did}#ed25519`,
        type: 'Ed25519',
      })
      expect(normalized.transports).toEqual([])
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
        endpoints: [
          {
            url: 'https://calendar.example.test/invoke',
            protocol: 'https',
            capabilities: ['calendar.schedule'],
            auth: 'delegation',
          },
        ],
        protocolVersions: ['fides.v2.0'],
        expiresAt: '2999-01-01T00:00:00.000Z',
      }

      const signed = await signAgentCard(card, issued.privateKey, issued.identity.did)

      expect(signed.payload.schema_version).toBe('fides.agent_card.v1')
      expect(signed.payload.agent_id).toBe(issued.identity.did)
      expect(signed.payload.publicKeys?.[0].publicKey).toBeTruthy()
      expect(signed.payload.transports?.[0]).toMatchObject({
        protocol: 'https',
        url: 'https://calendar.example.test/invoke',
        auth: 'delegation',
      })
      expect(await verifySignedAgentCard(signed)).toBe(true)
      expect(await verifySignedAgentCardIdentity(signed)).toBe(true)

      signed.payload.capabilities[0].name = 'Tampered'
      expect(await verifySignedAgentCard(signed)).toBe(false)
    })

    it('should reject AgentCard proofs whose verification method is not the agent identity', async () => {
      const issued = await createAgentIdentity()
      const attacker = await createAgentIdentity()
      const card: AgentCard = {
        ...validCard,
        id: issued.identity.did,
        identity: issued.identity,
        expiresAt: '2999-01-01T00:00:00.000Z',
      }

      const signed = await signAgentCard(card, attacker.privateKey, attacker.identity.did)

      expect(await verifySignedAgentCard(signed)).toBe(true)
      expect(await verifySignedAgentCardIdentity(signed)).toBe(false)
    })
  })
})
