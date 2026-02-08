export interface KeyPair {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

export interface AgentIdentity {
  did: string
  publicKey: string // hex-encoded
  algorithm: string
  metadata?: Record<string, unknown>
  createdAt: string
  endpoints?: {
    discovery?: string
    trust?: string
  }
}

export interface DiscoveryDocument {
  did: string
  publicKey: string
  algorithm: string
  endpoints: {
    discovery?: string
    trust?: string
  }
  createdAt: string
}

export interface TrustAttestation {
  id: string
  issuerDid: string
  subjectDid: string
  trustLevel: number // 0-100
  issuedAt: string
  expiresAt?: string
  signature: string // hex-encoded Ed25519 signature
  payload: string   // the signed payload (JSON string)
}

export interface TrustEdge {
  id: string
  sourceDid: string
  targetDid: string
  trustLevel: number
  attestation: TrustAttestation
  createdAt: string
  expiresAt?: string
  revokedAt?: string
}

export interface TrustScore {
  did: string
  score: number       // 0.0 - 1.0
  directTrusters: number
  transitiveTrusters: number
  lastComputed: string
}

export interface TrustPath {
  from: string
  to: string
  found: boolean
  path: string[]
  cumulativeTrust: number
  hops: number
}

export interface SignedRequest {
  method: string
  url: string
  headers: Record<string, string>
  body?: string
}

export interface SignatureResult {
  valid: boolean
  keyId?: string
  components?: string[]
  error?: string
}
