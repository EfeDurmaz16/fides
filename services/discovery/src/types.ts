export interface Identity {
  did: string
  publicKey: string // hex-encoded
  metadata?: Record<string, unknown>
  domain?: string | null
  domainVerified: boolean
  domainVerifiedAt?: Date | null
  verificationMethod?: 'dns' | null
  organizationDomain?: string | null
  organizationDomainVerified: boolean
  organizationDomainVerifiedAt?: Date | null
  organizationVerificationMethod?: 'dns' | null
  createdAt: Date
  updatedAt: Date
}

export interface RegisterIdentityRequest {
  did: string
  publicKey: string // hex-encoded
  metadata?: Record<string, unknown>
  domain?: string
  organizationDomain?: string
}

export interface VerifyIdentityDomainRequest {
  domain?: string
}

export interface VerifyOrganizationDomainRequest {
  domain?: string
}

export interface IdentityResponse {
  did: string
  publicKey: string
  metadata: Record<string, unknown>
  domain?: string | null
  domainVerified: boolean
  domainVerifiedAt?: string | null
  verificationMethod?: 'dns' | null
  organizationDomain?: string | null
  organizationDomainVerified: boolean
  organizationDomainVerifiedAt?: string | null
  organizationVerificationMethod?: 'dns' | null
  createdAt: string
  updatedAt: string
}

// --- Agent Registration ---

export interface RegisterAgentRequest {
  did: string
  name: string
  description?: string
  url: string
  version?: string
  provider?: { organization: string; url?: string }
  capabilities?: {
    streaming?: boolean
    pushNotifications?: boolean
    stateTransitionHistory?: boolean
    a2aCompatible?: boolean
  }
  skills?: Array<{
    id: string
    name: string
    description?: string
    tags?: string[]
    examples?: string[]
    inputModes?: string[]
    outputModes?: string[]
  }>
  defaultInputModes?: string[]
  defaultOutputModes?: string[]
}

export interface AgentResponse {
  did: string
  name: string
  description?: string | null
  url: string
  version: string
  publicKey: string
  algorithm: string
  provider?: { organization: string; url?: string } | null
  capabilities: Record<string, unknown>
  skills: Array<Record<string, unknown>>
  defaultInputModes?: string[] | null
  defaultOutputModes?: string[] | null
  status: string
  heartbeatAt: string
  createdAt: string
  updatedAt: string
}
