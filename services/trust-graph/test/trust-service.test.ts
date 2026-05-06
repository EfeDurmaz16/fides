import { describe, it, expect, beforeEach, vi } from 'vitest'
import { TrustService } from '../src/services/trust-service.js'
import type { CreateTrustRequest } from '../src/types.js'
import {
  createIncidentRecord,
  createRevocationRecord,
  signIncidentRecord,
  signRevocationRecord,
} from '@fides/core'
import * as ed from '@noble/ed25519'

describe('TrustService', () => {
  let service: TrustService
  let mockDb: any

  beforeEach(() => {
    service = new TrustService()

    // Create mock database
    mockDb = {
      insert: vi.fn(() => ({
        values: vi.fn(() => ({
          returning: vi.fn(() => Promise.resolve([{ id: 'test-uuid-123' }])),
          onConflictDoUpdate: vi.fn(() => Promise.resolve()),
        })),
      })),
      select: vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            limit: vi.fn(() => Promise.resolve([])),
          })),
        })),
      })),
      update: vi.fn(() => ({
        set: vi.fn(() => ({
          where: vi.fn(() => Promise.resolve()),
        })),
      })),
    }
  })

  function mockIdentity(publicKey: Uint8Array) {
    mockDb.select = vi.fn(() => ({
      from: vi.fn(() => ({
        where: vi.fn(() => ({
          limit: vi.fn(() => Promise.resolve([{ publicKey: Buffer.from(publicKey) }])),
        })),
      })),
    }))
  }

  async function signedRevocationRecord() {
    const privateKey = ed.utils.randomPrivateKey()
    const publicKey = await ed.getPublicKeyAsync(privateKey)
    mockIdentity(publicKey)
    const record = createRevocationRecord({
      did: 'did:fides:agent',
      reason: 'principal revoked authority',
      revokedBy: 'did:fides:principal',
    })
    return signRevocationRecord(record, privateKey)
  }

  async function signedIncidentRecord() {
    const privateKey = ed.utils.randomPrivateKey()
    const publicKey = await ed.getPublicKeyAsync(privateKey)
    mockIdentity(publicKey)
    const record = createIncidentRecord({
      actor: 'did:fides:agent',
      reportedBy: 'did:fides:principal',
      type: 'policy_violation',
      severity: 'high',
      description: 'Unauthorized payment attempt',
      capabilitiesRevoked: ['payments.execute'],
    })
    return signIncidentRecord(record, privateKey)
  }

  async function signedTrustRequest(overrides: Partial<CreateTrustRequest> = {}) {
    const privateKey = ed.utils.randomPrivateKey()
    const publicKey = await ed.getPublicKeyAsync(privateKey)
    mockIdentity(publicKey)

    const payloadObject = {
      issuerDid: 'did:fides:alice',
      subjectDid: 'did:fides:bob',
      trustLevel: 85,
      capabilityId: 'payments.execute',
      context: 'production-delegation',
      ...overrides,
    }
    const payload = JSON.stringify(payloadObject)
    const signature = Buffer.from(
      await ed.signAsync(new TextEncoder().encode(payload), privateKey)
    ).toString('hex')

    return {
      issuerDid: payloadObject.issuerDid,
      subjectDid: payloadObject.subjectDid,
      trustLevel: payloadObject.trustLevel,
      capabilityId: payloadObject.capabilityId,
      context: payloadObject.context,
      signature,
      payload,
    }
  }

  describe('createTrust', () => {
    it('should reject invalid trust levels', async () => {
      const request: CreateTrustRequest = {
        issuerDid: 'did:fides:alice',
        subjectDid: 'did:fides:bob',
        trustLevel: 150,
        signature: 'deadbeef',
        payload: '{}',
      }

      await expect(service.createTrust(mockDb, request)).rejects.toThrow(
        'Trust level must be an integer between'
      )
    })

    it('should reject negative trust levels', async () => {
      const request: CreateTrustRequest = {
        issuerDid: 'did:fides:alice',
        subjectDid: 'did:fides:bob',
        trustLevel: -10,
        signature: 'deadbeef',
        payload: '{}',
      }

      await expect(service.createTrust(mockDb, request)).rejects.toThrow(
        'Trust level must be an integer between'
      )
    })

    it('should reject missing payload', async () => {
      const request = {
        issuerDid: 'did:fides:alice',
        subjectDid: 'did:fides:bob',
        trustLevel: 80,
        signature: 'deadbeef',
      } as CreateTrustRequest

      await expect(service.createTrust(mockDb, request)).rejects.toThrow(
        'Payload is required'
      )
    })

    it('persists capability-scoped trust edges', async () => {
      let insertedValues: Record<string, unknown> | undefined
      mockDb.insert = vi.fn(() => ({
        values: vi.fn((values) => {
          insertedValues = values
          return {
            returning: vi.fn(() => Promise.resolve([{ id: 'trust-edge-id' }])),
          }
        }),
      }))

      const request = await signedTrustRequest()

      const id = await service.createTrust(mockDb, request)

      expect(id).toBe('trust-edge-id')
      expect(insertedValues).toMatchObject({
        sourceDid: request.issuerDid,
        targetDid: request.subjectDid,
        trustLevel: request.trustLevel,
        capabilityId: 'payments.execute',
        context: 'production-delegation',
      })
      expect(insertedValues?.attestation).toMatchObject({
        capabilityId: 'payments.execute',
        context: 'production-delegation',
      })
    })

    it('rejects capability scope mismatches in signed trust payloads', async () => {
      const request = await signedTrustRequest()

      await expect(service.createTrust(mockDb, {
        ...request,
        capabilityId: 'payments.refund',
      })).rejects.toThrow('capabilityId mismatch')
    })
  })

  describe('getTrustPath', () => {
    it('should return path result', async () => {
      // Mock edges query
      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => Promise.resolve([
            {
              sourceDid: 'did:fides:alice',
              targetDid: 'did:fides:bob',
              trustLevel: 80,
              revokedAt: null,
              expiresAt: null,
            },
          ])),
        })),
      }))

      const result = await service.getTrustPath(mockDb, 'did:fides:alice', 'did:fides:bob')

      expect(result.found).toBe(true)
      expect(result.from).toBe('did:fides:alice')
      expect(result.to).toBe('did:fides:bob')
    })
  })

  describe('getScore', () => {
    it('should return cached score if valid', async () => {
      const now = new Date()
      const recentCompute = new Date(now.getTime() - 1800000) // 30 min ago

      // Mock cached score
      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            limit: vi.fn(() => Promise.resolve([
              {
                did: 'did:fides:alice',
                score: 0.75,
                directTrusters: 5,
                transitiveTrusters: 10,
                lastComputed: recentCompute,
              },
            ])),
          })),
        })),
      }))

      const result = await service.getScore(mockDb, 'did:fides:alice')

      expect(result.score).toBe(0.75)
      expect(result.directTrusters).toBe(5)
      expect(result.transitiveTrusters).toBe(10)
    })

    it('should compute fresh score if cache expired', async () => {
      const oldCompute = new Date(Date.now() - 7200000) // 2 hours ago

      // Mock expired cache
      let selectCallCount = 0
      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => {
            selectCallCount++
            if (selectCallCount === 1) {
              // First call: identity lookup
              return {
                limit: vi.fn(() => Promise.resolve([
                  { did: 'did:fides:alice', publicKey: Buffer.from('01'.repeat(32), 'hex') },
                ])),
              }
            }
            if (selectCallCount === 2) {
              // Second call: cached score (expired)
              return {
                limit: vi.fn(() => Promise.resolve([
                  {
                    did: 'did:fides:alice',
                    score: 0.5,
                    directTrusters: 3,
                    transitiveTrusters: 5,
                    lastComputed: oldCompute,
                  },
                ])),
              }
            }
            // Third call: edges for recomputation
            return Promise.resolve([])
          }),
        })),
      }))

      const result = await service.getScore(mockDb, 'did:fides:alice')

      expect(mockDb.insert).toHaveBeenCalled()
    })
  })

  describe('recordRevocation', () => {
    it('records a revocation and invalidates reputation cache', async () => {
      const record = await signedRevocationRecord()
      const result = await service.recordRevocation(mockDb, {
        record,
      })

      expect(result.id).toBe('test-uuid-123')
      expect(mockDb.insert).toHaveBeenCalled()
      expect(mockDb.update).toHaveBeenCalled()
    })

    it('rejects missing revocation fields', async () => {
      await expect(service.recordRevocation(mockDb, {
        did: 'did:fides:agent',
        reason: '',
        revokedBy: '',
      })).rejects.toThrow('signed revocation record')
    })

    it('rejects tampered revocation records', async () => {
      const record = await signedRevocationRecord()
      await expect(service.recordRevocation(mockDb, {
        record: { ...record, reason: 'tampered reason' },
      })).rejects.toThrow('invalid revocation record signature')
    })

    it('returns the latest stored revocation for a DID', async () => {
      const record = await signedRevocationRecord()
      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            orderBy: vi.fn(() => ({
              limit: vi.fn(() => Promise.resolve([{ record }])),
            })),
          })),
        })),
      }))

      await expect(service.getRevocation(mockDb, 'did:fides:agent')).resolves.toMatchObject({
        did: 'did:fides:agent',
      })
    })

    it('returns null when a DID has no revocation', async () => {
      mockDb.select = vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            orderBy: vi.fn(() => ({
              limit: vi.fn(() => Promise.resolve([])),
            })),
          })),
        })),
      }))

      await expect(service.getRevocation(mockDb, 'did:fides:agent')).resolves.toBeNull()
    })
  })

  describe('recordIncident', () => {
    it('records signed incidents', async () => {
      const record = await signedIncidentRecord()
      const id = await service.recordIncident(mockDb, { actorDid: record.actor, record })

      expect(id).toBe('test-uuid-123')
      expect(mockDb.insert).toHaveBeenCalled()
    })

    it('rejects tampered incident records', async () => {
      const record = await signedIncidentRecord()
      await expect(service.recordIncident(mockDb, {
        actorDid: record.actor,
        record: { ...record, description: 'tampered description' },
      })).rejects.toThrow('invalid incident record signature')
    })
  })
})
