import { describe, it, expect } from 'vitest'
import { validateAgentCard } from '../src/agent-card.js'
import type { AgentCard } from '../src/agent-card.js'

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
  })
})
