import { describe, it, expect, vi, beforeEach } from 'vitest'
import { computeCapabilityScore, recordCapabilityInvocation, recordIncident, getIncidents } from '../src/services/capability-scoring.js'

function createMockDb() {
  return {
    select: vi.fn(() => ({
      from: vi.fn(() => ({
        where: vi.fn(() => Promise.resolve([])),
      })),
    })),
    insert: vi.fn(() => ({
      values: vi.fn(() => ({
        returning: vi.fn(() => Promise.resolve([{ id: 'test-incident-id' }])),
        onConflictDoUpdate: vi.fn(() => Promise.resolve()),
      })),
    })),
  }
}

describe('Capability Scoring', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
  })

  it('computes default score for unknown DID', async () => {
    const result = await computeCapabilityScore(mockDb, 'did:test:unknown', 'email:send')
    expect(result.score).toBe(0.5) // Default neutral trust
    expect(result.invocationCount).toBe(0)
    expect(result.incidentCount).toBe(0)
  })

  it('records capability invocations', async () => {
    await recordCapabilityInvocation(mockDb, 'did:test:agent', 'email:send')
    expect(mockDb.insert).toHaveBeenCalled()
  })

  it('records incidents with severity penalty', async () => {
    const id = await recordIncident(mockDb, {
      actorDid: 'did:test:agent',
      type: 'policy_violation',
      severity: 'high',
      description: 'Exceeded rate limit',
      capabilitiesRevoked: ['email:send'],
    })
    expect(id).toBe('test-incident-id')
  })

  it('returns incidents for a DID', async () => {
    mockDb.select = vi.fn(() => ({
      from: vi.fn(() => ({
        where: vi.fn(() => Promise.resolve([
          {
            id: 'inc-1',
            type: 'auth_failure',
            severity: 'medium',
            description: 'Multiple auth failures',
            reportedAt: new Date('2024-01-01'),
            resolvedAt: null,
            trustPenalty: 0.15,
          },
        ])),
      })),
    }))

    const incidents = await getIncidents(mockDb, 'did:test:agent')
    expect(incidents).toHaveLength(1)
    expect(incidents[0].type).toBe('auth_failure')
    expect(incidents[0].severity).toBe('medium')
  })
})
