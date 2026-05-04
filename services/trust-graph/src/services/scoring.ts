import { MAX_TRUST_DEPTH } from '@fides/shared'
import type { GraphEdge } from './graph.js'
import { filterValidEdges, buildReverseIndex } from './edge-utils.js'

/**
 * Compute reputation score for a DID based on trust edges.
 * Pure function - aggregates direct trust + transitive trust with weighted decay.
 *
 * Algorithm (spec-compliant):
 * - Direct trust (depth 1): weight 1.0
 * - Transitive depth 2: weight 0.5
 * - Transitive depth 3-MAX_TRUST_DEPTH: weight 0.25
 * - Final score = weighted sum / total paths
 *
 * Optimizations:
 * - Reverse-index map for O(1) incoming-edge lookup
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

  // Calculate direct trust total (sum of normalized trust levels)
  let directTotal = 0
  const directPaths = directEdges.length
  for (const edge of directEdges) {
    directTotal += edge.trustLevel / 100
  }

  // BFS to find transitive trusters up to MAX_TRUST_DEPTH hops
  const transitiveTrusters = new Set<string>()
  let depth2Score = 0
  let depth2Paths = 0
  let depth3PlusScore = 0
  let depth3PlusPaths = 0

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

    // Only go up to MAX_TRUST_DEPTH hops total
    if (current.depth >= MAX_TRUST_DEPTH) continue

    // Explore who trusts the current node — O(1) reverse-index lookup
    const incomingEdges = reverseIndex.get(current.did) || []

    for (const edge of incomingEdges) {
      if (!visited.has(edge.sourceDid)) {
        visited.add(edge.sourceDid)
        transitiveTrusters.add(edge.sourceDid)

        // Calculate path trust
        const edgeTrust = edge.trustLevel / 100
        const pathTrust = current.pathTrust * edgeTrust
        const nextDepth = current.depth + 1

        if (nextDepth === 2) {
          depth2Score += pathTrust
          depth2Paths++
        } else if (nextDepth >= 3) {
          depth3PlusScore += pathTrust
          depth3PlusPaths++
        }

        queue.push({
          did: edge.sourceDid,
          depth: nextDepth,
          pathTrust,
        })
      }
    }
  }

  // Weighted aggregation per spec:
  // direct * 1.0 + depth2 * 0.5 + depth3+ * 0.25, divided by total paths
  const totalPaths = directPaths + depth2Paths + depth3PlusPaths
  let combinedScore = 0
  if (totalPaths > 0) {
    combinedScore = (directTotal * 1.0 + depth2Score * 0.5 + depth3PlusScore * 0.25) / totalPaths
  }

  return {
    score: Math.min(combinedScore, 1.0), // Cap at 1.0
    directTrusters: directTrusters.size,
    transitiveTrusters: transitiveTrusters.size,
  }
}
