import { describe, it, expect } from 'vitest'
import { findTrustPath } from '../src/services/graph.js'
import type { GraphEdge } from '../src/services/graph.js'

describe('Trust Graph BFS Traversal', () => {
  const now = new Date()
  const future = new Date(Date.now() + 86400000) // +1 day

  it('should find direct path (1 hop)', () => {
    const edges: GraphEdge[] = [
      {
        sourceDid: 'did:fides:alice',
        targetDid: 'did:fides:bob',
        trustLevel: 80,
        revokedAt: null,
        expiresAt: null,
      },
    ]

    const result = findTrustPath(edges, 'did:fides:alice', 'did:fides:bob')

    expect(result.found).toBe(true)
    expect(result.hops).toBe(1)
    expect(result.path).toHaveLength(2)
    expect(result.path[0].did).toBe('did:fides:alice')
    expect(result.path[1].did).toBe('did:fides:bob')
    expect(result.cumulativeTrust).toBe(0.8) // 80/100 * 0.85^0
  })

  it('should find transitive path (2 hops)', () => {
    const edges: GraphEdge[] = [
      {
        sourceDid: 'did:fides:alice',
        targetDid: 'did:fides:bob',
        trustLevel: 80,
        revokedAt: null,
        expiresAt: null,
      },
      {
        sourceDid: 'did:fides:bob',
        targetDid: 'did:fides:charlie',
        trustLevel: 90,
        revokedAt: null,
        expiresAt: null,
      },
    ]

    const result = findTrustPath(edges, 'did:fides:alice', 'did:fides:charlie')

    expect(result.found).toBe(true)
    expect(result.hops).toBe(2)
    expect(result.path).toHaveLength(3)
    expect(result.path[0].did).toBe('did:fides:alice')
    expect(result.path[1].did).toBe('did:fides:bob')
    expect(result.path[2].did).toBe('did:fides:charlie')
    // Trust: 1.0 * (0.8 * 0.85^0) * (0.9 * 0.85^1) = 1.0 * 0.8 * 0.765 = 0.612
    expect(result.cumulativeTrust).toBeCloseTo(0.612, 3)
  })

  it('should find transitive path (3 hops)', () => {
    const edges: GraphEdge[] = [
      {
        sourceDid: 'did:fides:alice',
        targetDid: 'did:fides:bob',
        trustLevel: 100,
        revokedAt: null,
        expiresAt: null,
      },
      {
        sourceDid: 'did:fides:bob',
        targetDid: 'did:fides:charlie',
        trustLevel: 100,
        revokedAt: null,
        expiresAt: null,
      },
      {
        sourceDid: 'did:fides:charlie',
        targetDid: 'did:fides:dave',
        trustLevel: 100,
        revokedAt: null,
        expiresAt: null,
      },
    ]

    const result = findTrustPath(edges, 'did:fides:alice', 'did:fides:dave')

    expect(result.found).toBe(true)
    expect(result.hops).toBe(3)
    // Trust: 1.0 * (1.0 * 0.85^0) * (1.0 * 0.85^1) * (1.0 * 0.85^2)
    // = 1.0 * 1.0 * 0.85 * 0.7225 = 0.614125
    expect(result.cumulativeTrust).toBeCloseTo(0.614125, 5)
  })

  it('should return no path when disconnected', () => {
    const edges: GraphEdge[] = [
      {
        sourceDid: 'did:fides:alice',
        targetDid: 'did:fides:bob',
        trustLevel: 80,
        revokedAt: null,
        expiresAt: null,
      },
      {
        sourceDid: 'did:fides:charlie',
        targetDid: 'did:fides:dave',
        trustLevel: 90,
        revokedAt: null,
        expiresAt: null,
      },
    ]

    const result = findTrustPath(edges, 'did:fides:alice', 'did:fides:dave')

    expect(result.found).toBe(false)
    expect(result.hops).toBe(0)
    expect(result.path).toHaveLength(0)
    expect(result.cumulativeTrust).toBe(0)
  })

  it('should handle cycles without infinite loop', () => {
    const edges: GraphEdge[] = [
      {
        sourceDid: 'did:fides:alice',
        targetDid: 'did:fides:bob',
        trustLevel: 80,
        revokedAt: null,
        expiresAt: null,
      },
      {
        sourceDid: 'did:fides:bob',
        targetDid: 'did:fides:charlie',
        trustLevel: 90,
        revokedAt: null,
        expiresAt: null,
      },
      {
        sourceDid: 'did:fides:charlie',
        targetDid: 'did:fides:alice',
        trustLevel: 70,
        revokedAt: null,
        expiresAt: null,
      },
    ]

    const result = findTrustPath(edges, 'did:fides:alice', 'did:fides:charlie')

    expect(result.found).toBe(true)
    expect(result.hops).toBe(2)
  })

  it('should respect max depth', () => {
    const edges: GraphEdge[] = [
      { sourceDid: 'did:fides:a', targetDid: 'did:fides:b', trustLevel: 100, revokedAt: null, expiresAt: null },
      { sourceDid: 'did:fides:b', targetDid: 'did:fides:c', trustLevel: 100, revokedAt: null, expiresAt: null },
      { sourceDid: 'did:fides:c', targetDid: 'did:fides:d', trustLevel: 100, revokedAt: null, expiresAt: null },
      { sourceDid: 'did:fides:d', targetDid: 'did:fides:e', trustLevel: 100, revokedAt: null, expiresAt: null },
    ]

    const result = findTrustPath(edges, 'did:fides:a', 'did:fides:e', 2)

    expect(result.found).toBe(false)
  })

  it('should ignore revoked edges', () => {
    const edges: GraphEdge[] = [
      {
        sourceDid: 'did:fides:alice',
        targetDid: 'did:fides:bob',
        trustLevel: 80,
        revokedAt: now,
        expiresAt: null,
      },
    ]

    const result = findTrustPath(edges, 'did:fides:alice', 'did:fides:bob')

    expect(result.found).toBe(false)
  })

  it('should ignore expired edges', () => {
    const past = new Date(Date.now() - 86400000) // -1 day
    const edges: GraphEdge[] = [
      {
        sourceDid: 'did:fides:alice',
        targetDid: 'did:fides:bob',
        trustLevel: 80,
        revokedAt: null,
        expiresAt: past,
      },
    ]

    const result = findTrustPath(edges, 'did:fides:alice', 'did:fides:bob')

    expect(result.found).toBe(false)
  })

  it('should calculate trust decay correctly', () => {
    const edges: GraphEdge[] = [
      {
        sourceDid: 'did:fides:alice',
        targetDid: 'did:fides:bob',
        trustLevel: 100,
        revokedAt: null,
        expiresAt: null,
      },
    ]

    const result = findTrustPath(edges, 'did:fides:alice', 'did:fides:bob')

    // Hop 1: trust = 1.0 (100/100 * 0.85^0)
    expect(result.cumulativeTrust).toBe(1.0)
  })

  it('should calculate 2-hop trust decay correctly', () => {
    const edges: GraphEdge[] = [
      {
        sourceDid: 'did:fides:alice',
        targetDid: 'did:fides:bob',
        trustLevel: 100,
        revokedAt: null,
        expiresAt: null,
      },
      {
        sourceDid: 'did:fides:bob',
        targetDid: 'did:fides:charlie',
        trustLevel: 100,
        revokedAt: null,
        expiresAt: null,
      },
    ]

    const result = findTrustPath(edges, 'did:fides:alice', 'did:fides:charlie')

    // Hop 2: trust = 0.85 (100/100 * 0.85^1)
    expect(result.cumulativeTrust).toBe(0.85)
  })

  it('should calculate 3-hop trust decay correctly', () => {
    const edges: GraphEdge[] = [
      {
        sourceDid: 'did:fides:alice',
        targetDid: 'did:fides:bob',
        trustLevel: 100,
        revokedAt: null,
        expiresAt: null,
      },
      {
        sourceDid: 'did:fides:bob',
        targetDid: 'did:fides:charlie',
        trustLevel: 100,
        revokedAt: null,
        expiresAt: null,
      },
      {
        sourceDid: 'did:fides:charlie',
        targetDid: 'did:fides:dave',
        trustLevel: 100,
        revokedAt: null,
        expiresAt: null,
      },
    ]

    const result = findTrustPath(edges, 'did:fides:alice', 'did:fides:dave')

    // 3 hops with 100% trust: 1.0 * (1.0 * 0.85^0) * (1.0 * 0.85^1) * (1.0 * 0.85^2) = 1.0 * 0.85 * 0.7225 = 0.6141
    expect(result.cumulativeTrust).toBeCloseTo(0.6141, 3)
  })
})
