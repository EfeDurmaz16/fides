import { bytesToHex } from '@noble/hashes/utils'
import { canonicalDigest } from './canonical-signer.js'

export const FIDES_PROTOCOL_FAMILY = 'fides' as const
export const FIDES_PROTOCOL_VERSION = 'fides.v2.0' as const
export const FIDES_SUPPORTED_PROTOCOL_VERSIONS = [
  FIDES_PROTOCOL_VERSION,
  'fides.v2',
] as const

export type FidesProtocolVersion = typeof FIDES_SUPPORTED_PROTOCOL_VERSIONS[number]

export type ProtocolObjectId = string
export type FidesDid = `did:fides:${string}`
export type HashValue = `sha256:${string}`

export interface ProtocolObjectBase {
  schema_version: string
  id: ProtocolObjectId
  issuer: string
  subject?: string
  created_at?: string
  issued_at?: string
  expires_at?: string
}

export interface SignedProtocolObjectBase extends ProtocolObjectBase {
  payload_hash: HashValue
  signature: string
}

export interface SignedProtocolObject<TPayload extends ProtocolObjectBase = ProtocolObjectBase> {
  payload: TPayload
  payload_hash: HashValue
  signature: string
}

export interface ProtocolSignatureInput {
  schema_version: string
  id: string
  issuer: string
  subject?: string
  created_at?: string
  issued_at?: string
  expires_at?: string
  payload_hash: HashValue
}

export function hashProtocolPayload(payload: unknown): HashValue {
  return `sha256:${bytesToHex(canonicalDigest(payload))}`
}

export function createProtocolSignatureInput(payload: ProtocolObjectBase): ProtocolSignatureInput {
  const input: ProtocolSignatureInput = {
    schema_version: payload.schema_version,
    id: payload.id,
    issuer: payload.issuer,
    payload_hash: hashProtocolPayload(payload),
  }

  if (payload.subject !== undefined) input.subject = payload.subject
  if (payload.created_at !== undefined) input.created_at = payload.created_at
  if (payload.issued_at !== undefined) input.issued_at = payload.issued_at
  if (payload.expires_at !== undefined) input.expires_at = payload.expires_at

  return input
}

export function isProtocolObjectExpired(
  object: Pick<ProtocolObjectBase, 'expires_at'>,
  now: Date = new Date()
): boolean {
  if (!object.expires_at) return false
  const expiresAt = new Date(object.expires_at)
  if (Number.isNaN(expiresAt.getTime())) return true
  return expiresAt.getTime() <= now.getTime()
}

export function assertProtocolObjectBase(value: ProtocolObjectBase): void {
  if (!value.schema_version) throw new Error('Protocol object schema_version is required')
  if (!value.id) throw new Error('Protocol object id is required')
  if (!value.issuer) throw new Error('Protocol object issuer is required')
  if (!value.created_at && !value.issued_at) {
    throw new Error('Protocol object created_at or issued_at is required')
  }
}
