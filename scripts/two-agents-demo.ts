#!/usr/bin/env npx tsx
/**
 * Demo: Two AI agents discover and authenticate each other
 */

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
} from '../packages/sdk/dist/index.js'

async function main() {
  console.log('═══════════════════════════════════════════════════')
  console.log('  FIDES Demo: Two Agents Authenticate Each Other')
  console.log('═══════════════════════════════════════════════════\n')

  // ── Step 1: Agent A creates identity ──
  console.log('── Step 1: Agent A creates identity ──')
  const agentA = await generateKeyPair()
  const agentADid = generateDID(agentA.publicKey)
  console.log(`  Agent A DID: ${agentADid}`)
  console.log(`  Agent A Public Key: ${Buffer.from(agentA.publicKey).toString('hex').slice(0, 32)}...`)

  // ── Step 2: Agent B creates identity ──
  console.log('\n── Step 2: Agent B creates identity ──')
  const agentB = await generateKeyPair()
  const agentBDid = generateDID(agentB.publicKey)
  console.log(`  Agent B DID: ${agentBDid}`)
  console.log(`  Agent B Public Key: ${Buffer.from(agentB.publicKey).toString('hex').slice(0, 32)}...`)

  // ── Step 3: Agent A sends a signed HTTP request to Agent B ──
  console.log('\n── Step 3: Agent A sends signed HTTP request ──')
  const request: RequestLike = {
    method: 'POST',
    url: 'https://agent-b.example.com/api/collaborate',
    headers: {
      'Content-Type': 'application/json',
      'Host': 'agent-b.example.com',
    },
    body: JSON.stringify({
      action: 'propose_collaboration',
      from: agentADid,
      message: 'Hey Agent B, want to work together?',
    }),
  }

  const signedRequest = await signRequest(request, agentA.privateKey, {
    keyid: agentADid,
  })
  console.log(`  Signature-Input: ${signedRequest.headers['Signature-Input'].slice(0, 80)}...`)
  console.log(`  Signature: ${signedRequest.headers['Signature'].slice(0, 50)}...`)

  // ── Step 4: Agent B verifies Agent A's request ──
  console.log('\n── Step 4: Agent B verifies Agent A\'s signature ──')

  // Agent B extracts the keyId (DID) from the signature
  const keyIdMatch = signedRequest.headers['Signature-Input'].match(/keyid="([^"]+)"/)
  const senderDid = keyIdMatch![1]
  console.log(`  Sender DID from signature: ${senderDid}`)

  // Agent B resolves the DID to get the public key
  // (In production this would go through the discovery service)
  const senderPubKey = parseDID(senderDid)
  console.log(`  Resolved public key: ${Buffer.from(senderPubKey).toString('hex').slice(0, 32)}...`)

  // Agent B verifies the signature
  const verifyResult = await verifyRequest(signedRequest, senderPubKey)
  console.log(`  Signature valid: ${verifyResult.valid ? '✓ YES' : '✗ NO'}`)
  console.log(`  Verified keyId: ${verifyResult.keyId}`)

  // ── Step 5: Agent B responds with a signed request ──
  console.log('\n── Step 5: Agent B responds with signed request ──')
  const response: RequestLike = {
    method: 'POST',
    url: 'https://agent-a.example.com/api/collaborate',
    headers: {
      'Content-Type': 'application/json',
      'Host': 'agent-a.example.com',
    },
    body: JSON.stringify({
      action: 'accept_collaboration',
      from: agentBDid,
      message: 'Sure Agent A, let\'s collaborate!',
    }),
  }

  const signedResponse = await signRequest(response, agentB.privateKey, {
    keyid: agentBDid,
  })

  // Agent A verifies Agent B's response
  const bPubKey = parseDID(agentBDid)
  const verifyB = await verifyRequest(signedResponse, bPubKey)
  console.log(`  Agent A verifies Agent B: ${verifyB.valid ? '✓ YES' : '✗ NO'}`)

  // ── Step 6: Mutual trust attestations ──
  console.log('\n── Step 6: Mutual trust attestations ──')

  // Agent A trusts Agent B (HIGH = 75)
  const aTrustsB = await createAttestation(agentADid, agentBDid, TrustLevel.HIGH, agentA.privateKey)
  console.log(`  A → B trust: level=${aTrustsB.trustLevel}, id=${aTrustsB.id.slice(0, 8)}...`)

  // Agent B trusts Agent A (MEDIUM = 50)
  const bTrustsA = await createAttestation(agentBDid, agentADid, TrustLevel.MEDIUM, agentB.privateKey)
  console.log(`  B → A trust: level=${bTrustsA.trustLevel}, id=${bTrustsA.id.slice(0, 8)}...`)

  // Verify attestations
  const aAttestValid = await verifyAttestation(aTrustsB, agentA.publicKey)
  const bAttestValid = await verifyAttestation(bTrustsA, agentB.publicKey)
  console.log(`  A's attestation valid: ${aAttestValid ? '✓ YES' : '✗ NO'}`)
  console.log(`  B's attestation valid: ${bAttestValid ? '✓ YES' : '✗ NO'}`)

  // ── Step 7: Tampering detection ──
  console.log('\n── Step 7: Tampering detection ──')

  // Someone tampers with Agent A's request (changes method)
  const tamperedRequest = { ...signedRequest, method: 'DELETE' }
  const tamperedResult = await verifyRequest(tamperedRequest, senderPubKey)
  console.log(`  Tampered request detected: ${!tamperedResult.valid ? '✓ YES (rejected)' : '✗ NO'}`)

  // Someone tampers with trust attestation (changes level)
  const tamperedAttestation = { ...aTrustsB, trustLevel: 100 }
  const tamperedAttestResult = await verifyAttestation(tamperedAttestation, agentA.publicKey)
  console.log(`  Tampered attestation detected: ${!tamperedAttestResult ? '✓ YES (rejected)' : '✗ NO'}`)

  // ── Step 8: Third agent joins ──
  console.log('\n── Step 8: Third agent (C) joins the network ──')
  const agentC = await generateKeyPair()
  const agentCDid = generateDID(agentC.publicKey)
  console.log(`  Agent C DID: ${agentCDid.slice(0, 30)}...`)

  // C trusts A (ABSOLUTE = 100)
  const cTrustsA = await createAttestation(agentCDid, agentADid, TrustLevel.ABSOLUTE, agentC.privateKey)
  const cAttestValid = await verifyAttestation(cTrustsA, agentC.publicKey)
  console.log(`  C → A trust: level=${cTrustsA.trustLevel} (ABSOLUTE)`)
  console.log(`  C's attestation valid: ${cAttestValid ? '✓ YES' : '✗ NO'}`)

  // Transitive trust chain: C → A → B
  console.log(`\n  Trust chain: C →(100)→ A →(75)→ B`)
  console.log(`  Transitive trust (with 0.85 decay): ${(100/100 * 75/100 * 0.85).toFixed(2)}`)

  // ── Summary ──
  console.log('\n═══════════════════════════════════════════════════')
  console.log('  Summary')
  console.log('═══════════════════════════════════════════════════')
  console.log(`  ✓ Agent A created identity: ${agentADid.slice(0, 25)}...`)
  console.log(`  ✓ Agent B created identity: ${agentBDid.slice(0, 25)}...`)
  console.log(`  ✓ Agent C created identity: ${agentCDid.slice(0, 25)}...`)
  console.log(`  ✓ A ↔ B: Mutual authentication via RFC 9421 signatures`)
  console.log(`  ✓ A → B: Trust level HIGH (75)`)
  console.log(`  ✓ B → A: Trust level MEDIUM (50)`)
  console.log(`  ✓ C → A: Trust level ABSOLUTE (100)`)
  console.log(`  ✓ Tampering detected on both requests and attestations`)
  console.log(`  ✓ Transitive trust chain: C → A → B`)
  console.log('')
}

main().catch(console.error)
