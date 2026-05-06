import { describe, expect, it } from 'vitest'
import {
  createPasskeyAuthenticationChallenge,
  createPasskeyRegistrationChallenge,
  verifyPasskeyAuthentication,
  verifyPasskeyRegistration,
} from '../src/passkey.js'
import type { PasskeyVerifierAdapter, PrincipalIdentity } from '../src/index.js'

const principal: PrincipalIdentity = {
  did: 'did:fides:principal1',
  type: 'individual',
  displayName: 'Alice',
}

const relyingParty = {
  id: 'Example.COM',
  name: 'Example',
  origins: ['https://Example.COM/'],
}

const adapter: PasskeyVerifierAdapter = {
  provider: 'test-webauthn',
  async verifyRegistration(input) {
    return {
      verified: true,
      principalDid: input.challenge.principalDid,
      credentialId: input.credentialId,
      binding: {
        principalDid: input.challenge.principalDid,
        credentialId: input.credentialId,
        publicKey: 'p256-public-key',
        relyingPartyId: input.challenge.relyingParty.id,
        signCount: 0,
        createdAt: new Date().toISOString(),
      },
    }
  },
  async verifyAuthentication(input) {
    return {
      verified: true,
      principalDid: input.challenge.principalDid,
      credentialId: input.credentialId,
    }
  },
}

describe('passkey identity primitives', () => {
  it('creates registration challenges with normalized relying-party policy', () => {
    const challenge = createPasskeyRegistrationChallenge({
      principal,
      relyingParty,
      userVerification: 'required',
    })

    expect(challenge.type).toBe('passkey.registration')
    expect(challenge.principalDid).toBe(principal.did)
    expect(challenge.relyingParty).toEqual({
      id: 'example.com',
      name: 'Example',
      origins: ['https://example.com'],
    })
    expect(challenge.challenge.length).toBeGreaterThan(20)
    expect(challenge.userVerification).toBe('required')
  })

  it('rejects invalid registration challenge inputs', () => {
    expect(() => createPasskeyRegistrationChallenge({
      principal: { ...principal, did: 'did:web:alice' },
      relyingParty,
    })).toThrow('Invalid principal DID')

    expect(() => createPasskeyRegistrationChallenge({
      principal,
      relyingParty: { id: '', name: 'Example', origins: [] },
    })).toThrow('Invalid passkey relying party')
  })

  it('creates authentication challenges with allowed credentials', () => {
    const challenge = createPasskeyAuthenticationChallenge({
      principalDid: principal.did,
      relyingParty,
      allowCredentials: [{ id: 'cred-1', type: 'public-key', transports: ['internal'] }],
    })

    expect(challenge.type).toBe('passkey.authentication')
    expect(challenge.allowCredentials).toEqual([{ id: 'cred-1', type: 'public-key', transports: ['internal'] }])
  })

  it('rejects authentication challenges without credentials', () => {
    expect(() => createPasskeyAuthenticationChallenge({
      principalDid: principal.did,
      relyingParty,
      allowCredentials: [],
    })).toThrow('At least one passkey credential is required')
  })

  it('delegates registration verification after local policy checks', async () => {
    const challenge = createPasskeyRegistrationChallenge({ principal, relyingParty })
    await expect(verifyPasskeyRegistration(adapter, {
      challenge,
      origin: 'https://example.com',
      credentialId: 'cred-1',
      adapterPayload: { clientDataJSON: '...' },
    })).resolves.toMatchObject({
      verified: true,
      principalDid: principal.did,
      credentialId: 'cred-1',
      binding: {
        credentialId: 'cred-1',
        relyingPartyId: 'example.com',
      },
    })
  })

  it('rejects registration verification for invalid origins before adapter invocation', async () => {
    const challenge = createPasskeyRegistrationChallenge({ principal, relyingParty })
    await expect(verifyPasskeyRegistration(adapter, {
      challenge,
      origin: 'https://evil.example',
      credentialId: 'cred-1',
      adapterPayload: {},
    })).resolves.toEqual({
      verified: false,
      principalDid: principal.did,
      credentialId: 'cred-1',
      reason: 'invalid-origin',
    })
  })

  it('rejects expired challenges before adapter invocation', async () => {
    const challenge = createPasskeyRegistrationChallenge({
      principal,
      relyingParty,
      expiresInMs: -1000,
    })

    await expect(verifyPasskeyRegistration(adapter, {
      challenge,
      origin: 'https://example.com',
      credentialId: 'cred-1',
      adapterPayload: {},
    })).resolves.toMatchObject({
      verified: false,
      reason: 'expired-challenge',
    })
  })

  it('delegates authentication verification for allowed credentials', async () => {
    const challenge = createPasskeyAuthenticationChallenge({
      principalDid: principal.did,
      relyingParty,
      allowCredentials: [{ id: 'cred-1', type: 'public-key' }],
    })

    await expect(verifyPasskeyAuthentication(adapter, {
      challenge,
      origin: 'https://example.com',
      credentialId: 'cred-1',
      adapterPayload: { authenticatorData: '...' },
    })).resolves.toMatchObject({
      verified: true,
      principalDid: principal.did,
      credentialId: 'cred-1',
    })
  })

  it('rejects authentication verification for credentials outside the allow-list', async () => {
    const challenge = createPasskeyAuthenticationChallenge({
      principalDid: principal.did,
      relyingParty,
      allowCredentials: [{ id: 'cred-1', type: 'public-key' }],
    })

    await expect(verifyPasskeyAuthentication(adapter, {
      challenge,
      origin: 'https://example.com',
      credentialId: 'cred-2',
      adapterPayload: {},
    })).resolves.toEqual({
      verified: false,
      principalDid: principal.did,
      credentialId: 'cred-2',
      reason: 'adapter-rejected',
    })
  })
})
