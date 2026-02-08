import { describe, it, expect } from 'vitest'
import {
  generateKeyPair,
  generateDID,
  parseDID,
  signRequest,
  verifyRequest,
  createAttestation,
  verifyAttestation,
  TrustLevel,
  MemoryKeyStore,
  type RequestLike,
} from '@fides/sdk'

describe('FIDES E2E: Full Authentication and Trust Flow', () => {

  it('Two agents complete full authentication and trust flow', async () => {
    // 1. Agent A creates identity (keypair + DID)
    const agentAKeyPair = await generateKeyPair()
    const agentADid = generateDID(agentAKeyPair.publicKey)
    expect(agentADid).toMatch(/^did:fides:/)

    // Store in keystore
    const keyStore = new MemoryKeyStore()
    await keyStore.save(agentADid, agentAKeyPair)

    // 2. Agent B creates identity
    const agentBKeyPair = await generateKeyPair()
    const agentBDid = generateDID(agentBKeyPair.publicKey)
    expect(agentBDid).toMatch(/^did:fides:/)
    await keyStore.save(agentBDid, agentBKeyPair)

    // 3. Verify DIDs encode/decode correctly (round-trip)
    const aPubKeyDecoded = parseDID(agentADid)
    expect(Buffer.from(aPubKeyDecoded)).toEqual(Buffer.from(agentAKeyPair.publicKey))

    const bPubKeyDecoded = parseDID(agentBDid)
    expect(Buffer.from(bPubKeyDecoded)).toEqual(Buffer.from(agentBKeyPair.publicKey))

    // 4. Agent A signs an HTTP request
    const request: RequestLike = {
      method: 'POST',
      url: 'https://api.example.com/data',
      headers: {
        'Content-Type': 'application/json',
        'Host': 'api.example.com',
      },
      body: JSON.stringify({ message: 'hello from Agent A' }),
    }

    const signedRequest = await signRequest(request, agentAKeyPair.privateKey, {
      keyid: agentADid,
    })

    expect(signedRequest.headers['Signature']).toBeDefined()
    expect(signedRequest.headers['Signature-Input']).toBeDefined()
    expect(signedRequest.headers['Signature-Input']).toContain(agentADid)

    // 5. Agent B verifies Agent A's signature using A's public key
    const verifyResult = await verifyRequest(signedRequest, agentAKeyPair.publicKey)
    expect(verifyResult.valid).toBe(true)
    expect(verifyResult.keyId).toBe(agentADid)

    // 6. Signature verification fails with wrong key
    const verifyResultWrongKey = await verifyRequest(signedRequest, agentBKeyPair.publicKey)
    expect(verifyResultWrongKey.valid).toBe(false)

    // 7. Tampered request fails verification
    const tamperedRequest = {
      ...signedRequest,
      body: JSON.stringify({ message: 'tampered!' }),
    }
    // Note: body is not in the default signed components, so this won't fail
    // But tampering with a signed header WILL fail:
    const tamperedHeaders = {
      ...signedRequest,
      method: 'DELETE', // tamper with @method which IS signed
    }
    const verifyTampered = await verifyRequest(tamperedHeaders, agentAKeyPair.publicKey)
    expect(verifyTampered.valid).toBe(false)

    // 8. Agent A creates trust attestation for Agent B (level: HIGH = 75)
    const attestation = await createAttestation(
      agentADid,
      agentBDid,
      TrustLevel.HIGH,
      agentAKeyPair.privateKey
    )

    expect(attestation.issuerDid).toBe(agentADid)
    expect(attestation.subjectDid).toBe(agentBDid)
    expect(attestation.trustLevel).toBe(75)
    expect(attestation.signature).toBeDefined()
    expect(attestation.id).toBeDefined()

    // 9. Verify attestation with correct key
    const attestValid = await verifyAttestation(attestation, agentAKeyPair.publicKey)
    expect(attestValid).toBe(true)

    // 10. Verify attestation fails with wrong key
    const attestInvalid = await verifyAttestation(attestation, agentBKeyPair.publicKey)
    expect(attestInvalid).toBe(false)

    // 11. Attestation tampering detected (tampering with payload)
    const tamperedAttestation = {
      ...attestation,
      trustLevel: 100,
      payload: JSON.stringify({
        id: attestation.id,
        issuerDid: attestation.issuerDid,
        subjectDid: attestation.subjectDid,
        trustLevel: 100, // tampered value
        issuedAt: attestation.issuedAt,
      })
    }
    const tamperedValid = await verifyAttestation(tamperedAttestation, agentAKeyPair.publicKey)
    expect(tamperedValid).toBe(false)
  })

  it('Agent C trusts Agent A, Agent A trusts Agent B — transitive trust chain', async () => {
    // Create three agents
    const agentA = await generateKeyPair()
    const agentADid = generateDID(agentA.publicKey)

    const agentB = await generateKeyPair()
    const agentBDid = generateDID(agentB.publicKey)

    const agentC = await generateKeyPair()
    const agentCDid = generateDID(agentC.publicKey)

    // C trusts A (ABSOLUTE)
    const cTrustsA = await createAttestation(agentCDid, agentADid, TrustLevel.ABSOLUTE, agentC.privateKey)
    expect(await verifyAttestation(cTrustsA, agentC.publicKey)).toBe(true)

    // A trusts B (HIGH)
    const aTrustsB = await createAttestation(agentADid, agentBDid, TrustLevel.HIGH, agentA.privateKey)
    expect(await verifyAttestation(aTrustsB, agentA.publicKey)).toBe(true)

    // Verify the chain: each attestation is independently verifiable
    expect(cTrustsA.issuerDid).toBe(agentCDid)
    expect(cTrustsA.subjectDid).toBe(agentADid)
    expect(aTrustsB.issuerDid).toBe(agentADid)
    expect(aTrustsB.subjectDid).toBe(agentBDid)
  })

  it('Keystore round-trip preserves identity', async () => {
    const keyStore = new MemoryKeyStore()

    const keyPair = await generateKeyPair()
    const did = generateDID(keyPair.publicKey)

    await keyStore.save(did, keyPair)
    const loaded = await keyStore.load(did)

    expect(Buffer.from(loaded.publicKey)).toEqual(Buffer.from(keyPair.publicKey))
    expect(Buffer.from(loaded.privateKey)).toEqual(Buffer.from(keyPair.privateKey))

    // Can sign with loaded key
    const request: RequestLike = {
      method: 'GET',
      url: 'https://example.com/test',
      headers: { 'Content-Type': 'application/json' },
    }

    const signed = await signRequest(request, loaded.privateKey, { keyid: did })
    const verified = await verifyRequest(signed, loaded.publicKey)
    expect(verified.valid).toBe(true)
  })

  it('Multiple attestations from different issuers', async () => {
    const target = await generateKeyPair()
    const targetDid = generateDID(target.publicKey)

    // Create 5 issuers who all trust the target
    const attestations = []
    for (let i = 0; i < 5; i++) {
      const issuer = await generateKeyPair()
      const issuerDid = generateDID(issuer.publicKey)
      const level = TrustLevel.MEDIUM + i * 10 // 50, 60, 70, 80, 90

      const att = await createAttestation(issuerDid, targetDid, level, issuer.privateKey)
      expect(await verifyAttestation(att, issuer.publicKey)).toBe(true)
      attestations.push(att)
    }

    expect(attestations).toHaveLength(5)
    // All target the same DID
    for (const att of attestations) {
      expect(att.subjectDid).toBe(targetDid)
    }
    // All have different issuers
    const issuers = new Set(attestations.map(a => a.issuerDid))
    expect(issuers.size).toBe(5)
  })

  it('Expired signature is rejected', async () => {
    const keyPair = await generateKeyPair()
    const did = generateDID(keyPair.publicKey)

    const request: RequestLike = {
      method: 'GET',
      url: 'https://example.com/test',
      headers: { 'Content-Type': 'application/json' },
    }

    // Sign with already-expired time (expirySeconds = -1 to force expiry)
    // Actually, we need to sign with a very short expiry and then wait
    // Instead, let's sign normally and then manually modify the expires time
    const signed = await signRequest(request, keyPair.privateKey, {
      keyid: did,
      expirySeconds: -1, // This should create a signature that's already expired
    })

    const result = await verifyRequest(signed, keyPair.publicKey)
    expect(result.valid).toBe(false)
    expect(result.error).toContain('expired')
  })
})
