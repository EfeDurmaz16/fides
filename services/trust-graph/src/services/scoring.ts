import { DEFAULT_TRUST_DECAY } from '@fides/shared'
import type { GraphEdge } from './graph.js'
import { filterValidEdges, buildReverseIndex } from './edge-utils.js'

/**
 * Compute reputation score for a DID based on trust edges.
 * Pure function - aggregates direct trust + transitive trust with decay.
 *
 * Optimizations:
 * - Reverse-index map for O(1) incoming-edge lookup (was O(V×N) filter per BFS step)
 * - Index-based dequeue instead of queue.shift()
 *
 * @param edges - Array of all trust edges
 * @param did - DID to compute score for
 * @returns Normalized score 0.0-1.0
 */
export function computeReputationScore(edges: GraphEdge[], did: string): {
  score: number
  directTrusters: number
  transitiveTrusters: number
} {
  // Filter valid edges and build reverse-index using shared utilities
  const validEdges = filterValidEdges(edges)
  const reverseIndex = buildReverseIndex(validEdges)

  // Find all direct trusters using reverse index — O(1) lookup
  const directEdges = reverseIndex.get(did) || []
  const directTrusters = new Set(directEdges.map(e => e.sourceDid))

  // Calculate direct trust score (average of trust levels)
  let directScore = 0
  if (directEdges.length > 0) {
    const avgTrustLevel = directEdges.reduce((sum, e) => sum + e.trustLevel, 0) / directEdges.length
    directScore = avgTrustLevel / 100 // Normalize to 0-1
  }

  // BFS to find transitive trusters (2-hop and 3-hop)
  const transitiveTrusters = new Set<string>()
  let transitiveScore = 0

  interface QueueItem {
    did: string
    depth: number
    pathTrust: number
  }

  const queue: QueueItem[] = []
  const visited = new Set<string>([did])

  // Start from direct trusters
  for (const truster of directTrusters) {
    queue.push({ did: truster, depth: 1, pathTrust: 1.0 })
    visited.add(truster)
  }

  let head = 0 // Index-based dequeue: O(1) instead of queue.shift() O(n)

  while (head < queue.length) {
    const current = queue[head++]

    // Only go up to 3 hops total
    if (current.depth >= 3) continue

    // Explore who trusts the current node — O(1) reverse-index lookup
    const incomingEdges = reverseIndex.get(current.did) || []

    for (const edge of incomingEdges) {
      if (!visited.has(edge.sourceDid)) {
        visited.add(edge.sourceDid)
        transitiveTrusters.add(edge.sourceDid)

        // Calculate path trust with decay
        const edgeTrust = edge.trustLevel / 100
        const pathTrust = current.pathTrust * edgeTrust * Math.pow(DEFAULT_TRUST_DECAY, current.depth)
        transitiveScore += pathTrust

        queue.push({
          did: edge.sourceDid,
          depth: current.depth + 1,
          pathTrust,
        })
      }
    }
  }

  // Combine direct and transitive scores
  // Weight: 70% direct, 30% transitive
  const combinedScore = (directScore * 0.7) + (Math.min(transitiveScore, 1.0) * 0.3)

  return {
    score: Math.min(combinedScore, 1.0), // Cap at 1.0
    directTrusters: directTrusters.size,
    transitiveTrusters: transitiveTrusters.size,
  }
}
