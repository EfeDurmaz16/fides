export interface Identity {
  did: string
  publicKey: string // hex-encoded
  metadata?: Record<string, unknown>
  domain?: string | null
  createdAt: Date
  updatedAt: Date
}

export interface RegisterIdentityRequest {
  did: string
  publicKey: string // hex-encoded
  metadata?: Record<string, unknown>
  domain?: string
}

export interface IdentityResponse {
  did: string
  publicKey: string
  metadata: Record<string, unknown>
  domain?: string | null
  createdAt: string
  updatedAt: string
}
