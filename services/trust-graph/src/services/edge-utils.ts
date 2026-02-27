import type { GraphEdge } from './graph.js'

/**
 * Filter edges to only valid ones (not revoked, not expired).
 */
export function filterValidEdges(edges: GraphEdge[], now?: Date): GraphEdge[] {
  const timestamp = now || new Date()
  return edges.filter(edge => {
    if (edge.revokedAt) return false
    if (edge.expiresAt && edge.expiresAt < timestamp) return false
    return true
  })
}

/**
 * Build forward adjacency index: sourceDid → [{target, trust}]
 * Single pass O(N).
 */
export function buildForwardIndex(
  validEdges: GraphEdge[]
): Map<string, Array<{ target: string; trust: number }>> {
  const index = new Map<string, Array<{ target: string; trust: number }>>()
  for (const edge of validEdges) {
    if (!index.has(edge.sourceDid)) {
      index.set(edge.sourceDid, [])
    }
    index.get(edge.sourceDid)!.push({
      target: edge.targetDid,
      trust: edge.trustLevel,
    })
  }
  return index
}

/**
 * Build reverse adjacency index: targetDid → [{sourceDid, trust}]
 * Single pass O(N).
 */
export function buildReverseIndex(
  validEdges: GraphEdge[]
): Map<string, Array<{ sourceDid: string; trustLevel: number }>> {
  const index = new Map<string, Array<{ sourceDid: string; trustLevel: number }>>()
  for (const edge of validEdges) {
    if (!index.has(edge.targetDid)) {
      index.set(edge.targetDid, [])
    }
    index.get(edge.targetDid)!.push({
      sourceDid: edge.sourceDid,
      trustLevel: edge.trustLevel,
    })
  }
  return index
}
