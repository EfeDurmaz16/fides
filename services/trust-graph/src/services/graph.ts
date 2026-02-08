import { DEFAULT_TRUST_DECAY, MAX_TRUST_DEPTH } from '@fides/shared'
import type { TrustPathResult, TrustPathNode } from '../types.js'

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
  // Filter valid edges (not revoked, not expired)
  const now = new Date()
  const validEdges = edges.filter(edge => {
    if (edge.revokedAt) return false
    if (edge.expiresAt && edge.expiresAt < now) return false
    return true
  })

  // Build adjacency list
  const adjacency = new Map<string, Array<{ target: string; trust: number }>>()
  for (const edge of validEdges) {
    if (!adjacency.has(edge.sourceDid)) {
      adjacency.set(edge.sourceDid, [])
    }
    adjacency.get(edge.sourceDid)!.push({
      target: edge.targetDid,
      trust: edge.trustLevel,
    })
  }

  // BFS with path tracking
  interface QueueItem {
    did: string
    path: TrustPathNode[]
    cumulativeTrust: number
    depth: number
  }

  const queue: QueueItem[] = [{
    did: fromDid,
    path: [{ did: fromDid, trustLevel: 100 }],
    cumulativeTrust: 1.0,
    depth: 0,
  }]

  const visited = new Set<string>([fromDid])

  while (queue.length > 0) {
    const current = queue.shift()!

    // Found target
    if (current.did === toDid) {
      return {
        from: fromDid,
        to: toDid,
        found: true,
        path: current.path,
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

        // Calculate trust decay: trust_level/100 * decay^depth
        const trustFactor = (neighbor.trust / 100) * Math.pow(DEFAULT_TRUST_DECAY, current.depth)
        const newCumulativeTrust = current.cumulativeTrust * trustFactor

        queue.push({
          did: neighbor.target,
          path: [...current.path, { did: neighbor.target, trustLevel: neighbor.trust }],
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
