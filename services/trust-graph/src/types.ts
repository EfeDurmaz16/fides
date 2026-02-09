export interface TrustEdgeRow {
  id: string
  sourceDid: string
  targetDid: string
  trustLevel: number
  attestation: Record<string, unknown>
  signature: Buffer
  createdAt: Date
  expiresAt: Date | null
  revokedAt: Date | null
}

export interface IdentityRow {
  did: string
  publicKey: Buffer
  metadata: Record<string, unknown>
  firstSeen: Date
  lastSeen: Date
}

export interface ReputationScoreRow {
  did: string
  score: number
  directTrusters: number
  transitiveTrusters: number
  lastComputed: Date
}

export interface KeyHistoryRow {
  did: string
  publicKey: Buffer
  successorKey: Buffer | null
  successionSignature: Buffer | null
  activeFrom: Date
  activeUntil: Date | null
}

export interface CreateTrustRequest {
  issuerDid: string
  subjectDid: string
  trustLevel: number
  signature: string
  payload: string  // The signed JSON payload (required for signature verification)
  expiresAt?: string
}

export interface TrustPathNode {
  did: string
  trustLevel: number
}

export interface TrustPathResult {
  from: string
  to: string
  found: boolean
  path: TrustPathNode[]
  cumulativeTrust: number
  hops: number
}
