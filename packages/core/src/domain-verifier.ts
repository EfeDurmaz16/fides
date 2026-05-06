import { isValidFidesDid, type PrincipalIdentity, type PublisherIdentity } from './identity.js'

const FIDES_TXT_PREFIX = 'fides-did='
const FIDES_ORG_TXT_PREFIX = 'fides-org-did='

export interface DomainVerificationChallenge {
  /** Domain that should publish the verification TXT record. */
  domain: string
  /** DID expected in the TXT record. */
  did: string
  /** DNS name where the TXT record must be published. */
  recordName: string
  /** Exact TXT token expected at recordName. */
  recordValue: string
}

export interface DomainVerificationResult {
  domain: string
  did: string
  recordName: string
  verified: boolean
  reason?: 'invalid-domain' | 'invalid-did' | 'record-not-found' | 'resolver-error'
}

export interface OrganizationDomainVerificationChallenge {
  /** Organization domain that should publish the verification TXT record. */
  domain: string
  /** Organization principal DID expected in the TXT record. */
  did: string
  /** DNS name where the organization TXT record must be published. */
  recordName: string
  /** Exact TXT token expected at recordName. */
  recordValue: string
}

export interface OrganizationDomainVerificationResult {
  domain: string
  did: string
  recordName: string
  verified: boolean
  reason?: DomainVerificationResult['reason']
}

export interface DomainTxtResolver {
  resolveTxt(name: string): Promise<string[] | string[][]>
}

export interface DomainVerificationInput {
  domain: string
  did: string
  resolver: DomainTxtResolver | ((name: string) => Promise<string[] | string[][]>)
}

export function createDomainVerificationChallenge(domain: string, did: string): DomainVerificationChallenge {
  const normalizedDomain = normalizeDomain(domain)
  if (!normalizedDomain) {
    throw new Error('Invalid domain')
  }

  if (!isValidFidesDid(did)) {
    throw new Error('Invalid FIDES DID')
  }

  return {
    domain: normalizedDomain,
    did,
    recordName: `_fides.${normalizedDomain}`,
    recordValue: `${FIDES_TXT_PREFIX}${did}`,
  }
}

export function createOrganizationDomainVerificationChallenge(
  domain: string,
  did: string
): OrganizationDomainVerificationChallenge {
  const normalizedDomain = normalizeDomain(domain)
  if (!normalizedDomain) {
    throw new Error('Invalid organization domain')
  }

  if (!isValidFidesDid(did)) {
    throw new Error('Invalid FIDES DID')
  }

  return {
    domain: normalizedDomain,
    did,
    recordName: `_fides-org.${normalizedDomain}`,
    recordValue: `${FIDES_ORG_TXT_PREFIX}${did}`,
  }
}

export async function verifyDomainDid(input: DomainVerificationInput): Promise<DomainVerificationResult> {
  const normalizedDomain = normalizeDomain(input.domain)
  const recordName = normalizedDomain ? `_fides.${normalizedDomain}` : `_fides.${input.domain}`

  if (!normalizedDomain) {
    return {
      domain: input.domain,
      did: input.did,
      recordName,
      verified: false,
      reason: 'invalid-domain',
    }
  }

  if (!isValidFidesDid(input.did)) {
    return {
      domain: normalizedDomain,
      did: input.did,
      recordName,
      verified: false,
      reason: 'invalid-did',
    }
  }

  let records: string[]
  try {
    records = normalizeTxtRecords(await resolveTxt(input.resolver, recordName))
  } catch {
    return {
      domain: normalizedDomain,
      did: input.did,
      recordName,
      verified: false,
      reason: 'resolver-error',
    }
  }

  const recordValue = `${FIDES_TXT_PREFIX}${input.did}`
  const verified = records.includes(recordValue)

  return {
    domain: normalizedDomain,
    did: input.did,
    recordName,
    verified,
    reason: verified ? undefined : 'record-not-found',
  }
}

export async function verifyOrganizationDomainDid(
  input: DomainVerificationInput
): Promise<OrganizationDomainVerificationResult> {
  const normalizedDomain = normalizeDomain(input.domain)
  const recordName = normalizedDomain ? `_fides-org.${normalizedDomain}` : `_fides-org.${input.domain}`

  if (!normalizedDomain) {
    return {
      domain: input.domain,
      did: input.did,
      recordName,
      verified: false,
      reason: 'invalid-domain',
    }
  }

  if (!isValidFidesDid(input.did)) {
    return {
      domain: normalizedDomain,
      did: input.did,
      recordName,
      verified: false,
      reason: 'invalid-did',
    }
  }

  let records: string[]
  try {
    records = normalizeTxtRecords(await resolveTxt(input.resolver, recordName))
  } catch {
    return {
      domain: normalizedDomain,
      did: input.did,
      recordName,
      verified: false,
      reason: 'resolver-error',
    }
  }

  const recordValue = `${FIDES_ORG_TXT_PREFIX}${input.did}`
  const verified = records.includes(recordValue)

  return {
    domain: normalizedDomain,
    did: input.did,
    recordName,
    verified,
    reason: verified ? undefined : 'record-not-found',
  }
}

export function publisherFromDomainVerification(
  result: DomainVerificationResult,
  publisher: Omit<PublisherIdentity, 'domain' | 'verified' | 'verificationMethod'>
): PublisherIdentity {
  if (publisher.did !== result.did) {
    throw new Error('Publisher DID does not match verified DID')
  }

  return {
    ...publisher,
    domain: result.domain,
    verified: result.verified,
    verificationMethod: 'dns',
  }
}

export function organizationPrincipalFromDomainVerification(
  result: OrganizationDomainVerificationResult,
  principal: Omit<PrincipalIdentity, 'type' | 'domain' | 'verified' | 'verificationMethod'>
): PrincipalIdentity {
  if (principal.did !== result.did) {
    throw new Error('Principal DID does not match verified organization DID')
  }

  return {
    ...principal,
    type: 'organization',
    domain: result.domain,
    verified: result.verified,
    verificationMethod: 'dns',
  }
}

export function normalizeTxtRecords(records: string[] | string[][]): string[] {
  return records
    .map((record) => Array.isArray(record) ? record.join('') : record)
    .map((record) => record.trim())
    .filter(Boolean)
}

function normalizeDomain(domain: string): string | null {
  const normalized = domain.trim().toLowerCase().replace(/\.$/, '')
  if (!normalized || normalized.length > 253) return null
  if (normalized.includes('://') || normalized.includes('/') || normalized.includes('_')) return null

  const labels = normalized.split('.')
  if (labels.length < 2) return null

  for (const label of labels) {
    if (!label || label.length > 63) return null
    if (label.startsWith('-') || label.endsWith('-')) return null
    if (!/^[a-z0-9-]+$/.test(label)) return null
  }

  return normalized
}

async function resolveTxt(
  resolver: DomainTxtResolver | ((name: string) => Promise<string[] | string[][]>),
  recordName: string
): Promise<string[] | string[][]> {
  if (typeof resolver === 'function') {
    return resolver(recordName)
  }

  return resolver.resolveTxt(recordName)
}
