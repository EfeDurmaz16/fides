/**
 * Passkey/WebAuthn identity primitives.
 *
 * These types define the FIDES boundary for binding human or organization
 * principals to WebAuthn credentials. Cryptographic attestation/assertion
 * validation is delegated to a WebAuthn verifier adapter.
 */

import { isValidFidesDid, type PrincipalIdentity } from './identity.js'

export type PasskeyUserVerification = 'required' | 'preferred' | 'discouraged'

export interface PasskeyRelyingParty {
  id: string
  name: string
  origins: string[]
}

export interface PasskeyCredentialDescriptor {
  id: string
  type: 'public-key'
  transports?: Array<'ble' | 'hybrid' | 'internal' | 'nfc' | 'usb'>
}

export interface PasskeyRegistrationChallenge {
  id: string
  type: 'passkey.registration'
  principalDid: string
  principalDisplayName: string
  relyingParty: PasskeyRelyingParty
  challenge: string
  userVerification: PasskeyUserVerification
  expiresAt: string
}

export interface PasskeyAuthenticationChallenge {
  id: string
  type: 'passkey.authentication'
  principalDid: string
  relyingParty: PasskeyRelyingParty
  challenge: string
  allowCredentials: PasskeyCredentialDescriptor[]
  userVerification: PasskeyUserVerification
  expiresAt: string
}

export interface PasskeyCredentialBinding {
  principalDid: string
  credentialId: string
  publicKey: string
  relyingPartyId: string
  signCount: number
  transports?: PasskeyCredentialDescriptor['transports']
  backedUp?: boolean
  createdAt: string
  lastVerifiedAt?: string
}

export interface PasskeyVerificationInput {
  challenge: PasskeyRegistrationChallenge | PasskeyAuthenticationChallenge
  origin: string
  credentialId: string
  adapterPayload: unknown
}

export interface PasskeyVerificationResult {
  verified: boolean
  principalDid: string
  credentialId?: string
  reason?: 'invalid-principal' | 'invalid-rp' | 'invalid-origin' | 'expired-challenge' | 'adapter-rejected'
  binding?: PasskeyCredentialBinding
}

export interface PasskeyVerifierAdapter {
  readonly provider: string
  verifyRegistration(input: PasskeyVerificationInput): Promise<PasskeyVerificationResult>
  verifyAuthentication(input: PasskeyVerificationInput): Promise<PasskeyVerificationResult>
}

export function createPasskeyRegistrationChallenge(input: {
  principal: PrincipalIdentity
  relyingParty: PasskeyRelyingParty
  expiresInMs?: number
  userVerification?: PasskeyUserVerification
}): PasskeyRegistrationChallenge {
  assertPrincipal(input.principal)
  const relyingParty = normalizeRelyingParty(input.relyingParty)
  return {
    id: crypto.randomUUID(),
    type: 'passkey.registration',
    principalDid: input.principal.did,
    principalDisplayName: input.principal.displayName,
    relyingParty,
    challenge: randomChallenge(),
    userVerification: input.userVerification ?? 'preferred',
    expiresAt: new Date(Date.now() + (input.expiresInMs ?? 5 * 60_000)).toISOString(),
  }
}

export function createPasskeyAuthenticationChallenge(input: {
  principalDid: string
  relyingParty: PasskeyRelyingParty
  allowCredentials: PasskeyCredentialDescriptor[]
  expiresInMs?: number
  userVerification?: PasskeyUserVerification
}): PasskeyAuthenticationChallenge {
  if (!isValidFidesDid(input.principalDid)) {
    throw new Error('Invalid principal DID')
  }
  if (input.allowCredentials.length === 0) {
    throw new Error('At least one passkey credential is required')
  }
  return {
    id: crypto.randomUUID(),
    type: 'passkey.authentication',
    principalDid: input.principalDid,
    relyingParty: normalizeRelyingParty(input.relyingParty),
    challenge: randomChallenge(),
    allowCredentials: input.allowCredentials.map(normalizeCredentialDescriptor),
    userVerification: input.userVerification ?? 'preferred',
    expiresAt: new Date(Date.now() + (input.expiresInMs ?? 5 * 60_000)).toISOString(),
  }
}

export async function verifyPasskeyRegistration(
  adapter: PasskeyVerifierAdapter,
  input: PasskeyVerificationInput
): Promise<PasskeyVerificationResult> {
  const policy = validatePasskeyPolicy(input)
  if (!policy.verified) return policy
  return adapter.verifyRegistration(input)
}

export async function verifyPasskeyAuthentication(
  adapter: PasskeyVerifierAdapter,
  input: PasskeyVerificationInput
): Promise<PasskeyVerificationResult> {
  const policy = validatePasskeyPolicy(input)
  if (!policy.verified) return policy
  if (input.challenge.type === 'passkey.authentication' &&
    !input.challenge.allowCredentials.some(credential => credential.id === input.credentialId)) {
    return {
      verified: false,
      principalDid: input.challenge.principalDid,
      credentialId: input.credentialId,
      reason: 'adapter-rejected',
    }
  }
  return adapter.verifyAuthentication(input)
}

function validatePasskeyPolicy(input: PasskeyVerificationInput): PasskeyVerificationResult {
  const { challenge } = input
  if (!isValidFidesDid(challenge.principalDid)) {
    return { verified: false, principalDid: challenge.principalDid, credentialId: input.credentialId, reason: 'invalid-principal' }
  }
  if (!challenge.relyingParty.id || challenge.relyingParty.origins.length === 0) {
    return { verified: false, principalDid: challenge.principalDid, credentialId: input.credentialId, reason: 'invalid-rp' }
  }
  if (!challenge.relyingParty.origins.includes(normalizeOrigin(input.origin))) {
    return { verified: false, principalDid: challenge.principalDid, credentialId: input.credentialId, reason: 'invalid-origin' }
  }
  if (new Date(challenge.expiresAt) < new Date()) {
    return { verified: false, principalDid: challenge.principalDid, credentialId: input.credentialId, reason: 'expired-challenge' }
  }
  return { verified: true, principalDid: challenge.principalDid, credentialId: input.credentialId }
}

function assertPrincipal(principal: PrincipalIdentity): void {
  if (!isValidFidesDid(principal.did)) {
    throw new Error('Invalid principal DID')
  }
  if (!principal.displayName) {
    throw new Error('Principal displayName is required')
  }
}

function normalizeRelyingParty(relyingParty: PasskeyRelyingParty): PasskeyRelyingParty {
  const id = relyingParty.id.trim().toLowerCase()
  const origins = relyingParty.origins.map(normalizeOrigin)
  if (!id || !relyingParty.name.trim() || origins.length === 0) {
    throw new Error('Invalid passkey relying party')
  }
  return { id, name: relyingParty.name.trim(), origins }
}

function normalizeCredentialDescriptor(credential: PasskeyCredentialDescriptor): PasskeyCredentialDescriptor {
  if (!credential.id || credential.type !== 'public-key') {
    throw new Error('Invalid passkey credential descriptor')
  }
  return credential
}

function normalizeOrigin(origin: string): string {
  return origin.trim().toLowerCase().replace(/\/+$/, '')
}

function randomChallenge(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Buffer.from(bytes).toString('base64url')
}
