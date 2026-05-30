/**
 * FIDES v2 End-to-End Demo
 *
 * Demonstrates the full trust fabric flow.
 * Run: pnpm demo
 */

import { createAgentIdentity, createPrincipalIdentity, classifyCapabilityRisk, validateAgentCard, createDelegationToken, validateDelegationToken, signDelegationToken } from '@fides/core'
import type { AgentCard, CapabilityDescriptor } from '@fides/core'
import { evaluatePolicy } from '@fides/policy'
import { createEvidenceChain, appendEvidenceEvent, buildMerkleRoot, verifyEvidenceChain, hashEvidenceValue } from '@fides/evidence'
import { MockTEEProvider, InMemoryKillSwitch } from '@fides/runtime'
import { evaluateGuard, createTrustContext } from './src/index.js'

async function demo() {
  console.log('═'.repeat(60))
  console.log('  FIDES v2 — Agent Trust Fabric Demo')
  console.log('═'.repeat(60))
  console.log()

  // Step 1: Identities
  console.log('📝 Step 1: Creating Identities')
  const { identity: alice } = await createAgentIdentity()
  alice.metadata = { name: 'Alice Assistant' }
  const { identity: bob } = await createAgentIdentity()
  bob.metadata = { name: 'Bob Scheduler' }
  const { identity: charlie, privateKey: charliePrivateKey } = await createPrincipalIdentity({
    type: 'individual',
    displayName: 'Charlie User',
  })
  console.log(`  Alice: ${alice.did}`)
  console.log(`  Bob: ${bob.did}`)
  console.log(`  Charlie: ${charlie.did}`)
  console.log()

  // Step 2: AgentCard
  console.log('🃏 Step 2: AgentCard')
  const caps: CapabilityDescriptor[] = [
    { id: 'email:send', name: 'Send Email', description: 'Send emails', riskLevel: 'high', parameters: [], output: { type: 'boolean', description: 'Sent' }, constraints: [] },
    { id: 'calendar:create', name: 'Create Event', description: 'Calendar events', riskLevel: 'medium', parameters: [], output: { type: 'object', description: 'Event' }, constraints: [] },
  ]
  const aliceCard: AgentCard = {
    id: alice.did,
    identity: alice,
    capabilities: caps,
    endpoints: [{ url: 'https://alice.example.com/fides', protocol: 'https', capabilities: ['email:send', 'calendar:create'], auth: 'signature' }],
    policies: [{ requiresRuntimeAttestation: true, requiresApproval: false }],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }
  const cardValid = validateAgentCard(aliceCard)
  console.log(`  ${aliceCard.identity.metadata.name}: ${aliceCard.capabilities.length} capabilities, valid: ${cardValid.valid}`)
  console.log()

  // Step 3: Risk
  console.log('⚠️  Step 3: Risk Classification')
  for (const cap of aliceCard.capabilities) {
    const risk = classifyCapabilityRisk(cap.id)
    console.log(`  ${cap.id}: ${risk}`)
  }
  console.log()

  // Step 4: Delegation
  console.log('🔑 Step 4: Delegation Token')
  const delegation = await signDelegationToken(createDelegationToken({
    delegator: charlie.did, delegatee: alice.did,
    capabilities: ['email:send', 'calendar:create'],
    constraints: { maxActions: 10, maxSpend: '10.00', allowedContexts: ['work'] },
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
  }), charliePrivateKey)
  const valid = validateDelegationToken(delegation)
  console.log(`  Token: ${delegation.id}`)
  console.log(`  Delegator: ${delegation.delegator} → ${delegation.delegatee}`)
  console.log(`  Valid: ${valid.valid}`)
  console.log()

  // Step 5: Policy
  console.log('📋 Step 5: Policy Evaluation')
  const policy = {
    id: 'demo', version: '1.0.0',
    rules: [
      { id: 'rate', condition: { operator: 'gt', field: 'requestCount', value: 100 }, action: 'deny' as const, explanation: 'Rate limit' },
      { id: 'trust', condition: { operator: 'gte', field: 'reputationScore', value: 0.8 }, action: 'allow' as const, explanation: 'High trust' },
    ],
    defaultAction: 'deny' as const,
  }
  const r1 = evaluatePolicy(policy, { requestCount: 10, reputationScore: 0.9 })
  const r2 = evaluatePolicy(policy, { requestCount: 200, reputationScore: 0.5 })
  console.log(`  Low usage, high trust: ${r1.decision}`)
  console.log(`  High usage, mid trust: ${r2.decision}`)
  console.log()

  // Step 6: Evidence
  console.log('📜 Step 6: Evidence Ledger')
  let chain = createEvidenceChain()
  for (const evt of [
    { id: 'e1', type: 'invoke', timestamp: new Date().toISOString(), actor: alice.did, action: 'email:send', payload: {}, privacy: { level: 'redacted' as const } },
    { id: 'e2', type: 'invoke', timestamp: new Date().toISOString(), actor: alice.did, action: 'calendar:create', payload: {}, privacy: { level: 'hash_only' as const } },
    { id: 'e3', type: 'policy', timestamp: new Date().toISOString(), actor: alice.did, action: 'evaluate', payload: {}, privacy: { level: 'public' as const } },
  ]) {
    chain = appendEvidenceEvent(chain, evt, localEvidenceSignature(evt))
  }
  console.log(`  Events: ${chain.events.length}`)
  console.log(`  Chain valid: ${verifyEvidenceChain(chain)}`)
  console.log(`  Merkle root: ${buildMerkleRoot(chain.events.map(e => e.hash)).slice(0, 16)}...`)
  console.log()

  // Step 7: Attestation
  console.log('🔒 Step 7: Runtime Attestation')
  const tee = new MockTEEProvider()
  const att = await tee.attest(alice.did)
  console.log(`  Provider: ${att.provider}`)
  console.log(`  Verified: ${await tee.verify(att)}`)
  console.log()

  // Step 8: Kill Switch
  console.log('🛑 Step 8: Kill Switch')
  const ks = new InMemoryKillSwitch()
  ks.engage({ type: 'agent', did: alice.did })
  console.log(`  Alice killed: ${ks.isEngaged({ type: 'agent', did: alice.did })}`)
  ks.disengage({ type: 'agent', did: alice.did })
  console.log(`  Alice revived: ${!ks.isEngaged({ type: 'agent', did: alice.did })}`)
  console.log()

  // Step 9: Guard
  console.log('🛡️  Step 9: Guard Decision Engine')
  const trustGood = createTrustContext({ reputationScore: 0.9, capabilityScore: 0.95, attestation: att, evidenceChain: chain, killSwitchEngaged: false, recentIncidents: 0 })
  const d1 = await evaluateGuard({ agentDid: alice.did, capabilityId: 'email:send', policy, context: { requestCount: 10 }, trust: trustGood })
  console.log(`  Good agent: ${d1.decision}`)

  const trustBad = createTrustContext({ reputationScore: 0.05, killSwitchEngaged: false, recentIncidents: 10 })
  const d2 = await evaluateGuard({ agentDid: bob.did, capabilityId: 'task:create', policy, context: { requestCount: 10 }, trust: trustBad })
  console.log(`  Bad agent: ${d2.decision}`)

  const trustKill = createTrustContext({ reputationScore: 0.9, killSwitchEngaged: true, recentIncidents: 0 })
  const d3 = await evaluateGuard({ agentDid: alice.did, capabilityId: 'email:send', policy, context: { requestCount: 10 }, trust: trustKill })
  console.log(`  Kill switch: ${d3.decision}`)
  console.log()

  console.log('═'.repeat(60))
  console.log('  Demo Complete — All 9 subsystems operational')
  console.log('═'.repeat(60))
}

function localEvidenceSignature(event: unknown): string {
  return `local-evidence:${hashEvidenceValue(event).slice('sha256:'.length)}`
}

demo().catch(console.error)
