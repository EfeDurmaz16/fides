import { DEFAULT_TRUST_DECAY, MAX_TRUST_DEPTH } from '@fides/shared'
import type { TrustPathResult, TrustPathNode } from '../types.js'
import { filterValidEdges, buildForwardIndex } from './edge-utils.js'

export interface GraphEdge {
  sourceDid: string
  targetDid: string
  trustLevel: number
  revokedAt?: Date | null
  expiresAt?: Date | null
}

/**
 * Find trust path between two DIDs using BFS traversal.
 * Pure function - no database dependency, easy to test.
 *
 * Optimizations:
 * - Index-based dequeue instead of queue.shift() (O(1) vs O(n))
 * - Parent pointer chain instead of path array cloning per edge
 * - Pre-computed decay powers array
 *
 * @param edges - Array of trust edges
 * @param fromDid - Source DID
 * @param toDid - Target DID
 * @param maxDepth - Maximum path depth (default: 6)
 * @returns Trust path with cumulative trust score
 */
export function findTrustPath(
  edges: GraphEdge[],
  fromDid: string,
  toDid: string,
  maxDepth: number = MAX_TRUST_DEPTH
): TrustPathResult {
  // Filter valid edges and build adjacency list using shared utilities
  const validEdges = filterValidEdges(edges)
  const adjacency = buildForwardIndex(validEdges)

  // Pre-compute decay powers: decayPowers[i] = DEFAULT_TRUST_DECAY^i
  const decayPowers = new Array(maxDepth + 1)
  decayPowers[0] = 1.0
  for (let i = 1; i <= maxDepth; i++) {
    decayPowers[i] = decayPowers[i - 1] * DEFAULT_TRUST_DECAY
  }

  // BFS with parent pointers (avoids path cloning per edge)
  interface QueueItem {
    did: string
    parentIndex: number // -1 for root
    trustLevel: number  // trust level of the edge leading to this node
    cumulativeTrust: number
    depth: number
  }

  const queue: QueueItem[] = [{
    did: fromDid,
    parentIndex: -1,
    trustLevel: 100,
    cumulativeTrust: 1.0,
    depth: 0,
  }]

  const visited = new Set<string>([fromDid])
  let head = 0 // Index-based dequeue: O(1) instead of queue.shift() O(n)

  while (head < queue.length) {
    const current = queue[head++]

    // Found target — reconstruct path from parent pointers
    if (current.did === toDid) {
      return {
        from: fromDid,
        to: toDid,
        found: true,
        path: reconstructPath(queue, head - 1),
        cumulativeTrust: current.cumulativeTrust,
        hops: current.depth,
      }
    }

    // Max depth reached
    if (current.depth >= maxDepth) {
      continue
    }

    // Explore neighbors
    const neighbors = adjacency.get(current.did) || []
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor.target)) {
        visited.add(neighbor.target)

        // Calculate trust decay using pre-computed powers
        const trustFactor = (neighbor.trust / 100) * decayPowers[current.depth]
        const newCumulativeTrust = current.cumulativeTrust * trustFactor

        queue.push({
          did: neighbor.target,
          parentIndex: head - 1, // points to current item in queue
          trustLevel: neighbor.trust,
          cumulativeTrust: newCumulativeTrust,
          depth: current.depth + 1,
        })
      }
    }
  }

  // No path found
  return {
    from: fromDid,
    to: toDid,
    found: false,
    path: [],
    cumulativeTrust: 0,
    hops: 0,
  }
}

/**
 * Reconstruct path by walking parent pointers from target back to root.
 * Only called when target is found — avoids path cloning during BFS.
 */
function reconstructPath(
  queue: Array<{ did: string; parentIndex: number; trustLevel: number }>,
  targetIndex: number
): TrustPathNode[] {
  const path: TrustPathNode[] = []
  let idx = targetIndex
  while (idx >= 0) {
    const item = queue[idx]
    path.push({ did: item.did, trustLevel: item.trustLevel })
    idx = item.parentIndex
  }
  path.reverse()
  return path
}
