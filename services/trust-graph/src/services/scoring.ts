import { DEFAULT_TRUST_DECAY } from '@fides/shared'
import type { GraphEdge } from './graph.js'

/**
 * Compute reputation score for a DID based on trust edges.
 * Pure function - aggregates direct trust + transitive trust with decay.
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
  // Filter valid edges (not revoked, not expired)
  const now = new Date()
  const validEdges = edges.filter(edge => {
    if (edge.revokedAt) return false
    if (edge.expiresAt && edge.expiresAt < now) return false
    return true
  })

  // Find all direct trusters
  const directEdges = validEdges.filter(edge => edge.targetDid === did)
  const directTrusters = new Set(directEdges.map(e => e.sourceDid))

  // Calculate direct trust score (average of trust levels)
  let directScore = 0
  if (directEdges.length > 0) {
    const avgTrustLevel = directEdges.reduce((sum, e) => sum + e.trustLevel, 0) / directEdges.length
    directScore = avgTrustLevel / 100 // Normalize to 0-1
  }

  // Build adjacency list for transitive trust
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

  while (queue.length > 0) {
    const current = queue.shift()!

    // Only go up to 3 hops total
    if (current.depth >= 3) continue

    // Explore who trusts the current node
    const incomingEdges = validEdges.filter(e => e.targetDid === current.did)

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
