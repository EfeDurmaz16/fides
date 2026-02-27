import { describe, it, expect } from 'vitest'
import { filterValidEdges, buildForwardIndex, buildReverseIndex } from '../src/services/edge-utils.js'
import type { GraphEdge } from '../src/services/graph.js'

describe('Edge Utilities', () => {
  const now = new Date()
  const past = new Date(Date.now() - 86400000) // -1 day
  const future = new Date(Date.now() + 86400000) // +1 day

  const edges: GraphEdge[] = [
    { sourceDid: 'did:fides:alice', targetDid: 'did:fides:bob', trustLevel: 80, revokedAt: null, expiresAt: null },
    { sourceDid: 'did:fides:bob', targetDid: 'did:fides:carol', trustLevel: 70, revokedAt: null, expiresAt: future },
    { sourceDid: 'did:fides:carol', targetDid: 'did:fides:dave', trustLevel: 60, revokedAt: past, expiresAt: null }, // revoked
    { sourceDid: 'did:fides:dave', targetDid: 'did:fides:eve', trustLevel: 50, revokedAt: null, expiresAt: past },   // expired
    { sourceDid: 'did:fides:alice', targetDid: 'did:fides:carol', trustLevel: 90, revokedAt: null, expiresAt: null },
  ]

  describe('filterValidEdges', () => {
    it('should filter out revoked edges', () => {
      const valid = filterValidEdges(edges)
      const hasDaveEdge = valid.some(e => e.sourceDid === 'did:fides:carol' && e.targetDid === 'did:fides:dave')
      expect(hasDaveEdge).toBe(false)
    })

    it('should filter out expired edges', () => {
      const valid = filterValidEdges(edges)
      const hasEveEdge = valid.some(e => e.sourceDid === 'did:fides:dave' && e.targetDid === 'did:fides:eve')
      expect(hasEveEdge).toBe(false)
    })

    it('should keep valid edges', () => {
      const valid = filterValidEdges(edges)
      expect(valid).toHaveLength(3)
    })

    it('should accept custom timestamp', () => {
      // Use a timestamp far in the future — bob→carol (expires +1 day) is also expired relative to farFuture
      const farFuture = new Date(Date.now() + 365 * 86400000)
      const valid = filterValidEdges(edges, farFuture)
      // Filters: carol→dave (revoked), dave→eve (expired), bob→carol (expired relative to farFuture)
      expect(valid).toHaveLength(2)
    })

    it('should return empty array for empty input', () => {
      expect(filterValidEdges([])).toEqual([])
    })
  })

  describe('buildForwardIndex', () => {
    it('should build sourceDid → targets map', () => {
      const valid = filterValidEdges(edges)
      const index = buildForwardIndex(valid)

      expect(index.get('did:fides:alice')).toHaveLength(2)
      expect(index.get('did:fides:bob')).toHaveLength(1)
      expect(index.has('did:fides:carol')).toBe(false) // carol's edge was revoked
    })

    it('should contain correct trust levels', () => {
      const valid = filterValidEdges(edges)
      const index = buildForwardIndex(valid)

      const aliceTargets = index.get('did:fides:alice')!
      const bobTarget = aliceTargets.find(t => t.target === 'did:fides:bob')
      expect(bobTarget?.trust).toBe(80)
    })

    it('should handle empty input', () => {
      const index = buildForwardIndex([])
      expect(index.size).toBe(0)
    })
  })

  describe('buildReverseIndex', () => {
    it('should build targetDid → sources map', () => {
      const valid = filterValidEdges(edges)
      const index = buildReverseIndex(valid)

      expect(index.get('did:fides:bob')).toHaveLength(1)
      expect(index.get('did:fides:carol')).toHaveLength(2) // alice→carol and bob→carol
    })

    it('should contain correct source DIDs', () => {
      const valid = filterValidEdges(edges)
      const index = buildReverseIndex(valid)

      const carolSources = index.get('did:fides:carol')!
      const sourceDids = carolSources.map(s => s.sourceDid)
      expect(sourceDids).toContain('did:fides:alice')
      expect(sourceDids).toContain('did:fides:bob')
    })

    it('should handle empty input', () => {
      const index = buildReverseIndex([])
      expect(index.size).toBe(0)
    })
  })

  describe('performance', () => {
    it('should handle 1000 edges efficiently', () => {
      // Generate a large graph
      const largeEdges: GraphEdge[] = []
      for (let i = 0; i < 1000; i++) {
        largeEdges.push({
          sourceDid: `did:fides:node${i}`,
          targetDid: `did:fides:node${(i + 1) % 1000}`,
          trustLevel: 80,
          revokedAt: null,
          expiresAt: null,
        })
      }

      const start = performance.now()
      const valid = filterValidEdges(largeEdges)
      const forward = buildForwardIndex(valid)
      const reverse = buildReverseIndex(valid)
      const elapsed = performance.now() - start

      expect(valid).toHaveLength(1000)
      expect(forward.size).toBe(1000)
      expect(reverse.size).toBe(1000)
      expect(elapsed).toBeLessThan(50) // Should complete in <50ms
    })
  })
})
