/**
 * FIDES v2 end-to-end demo.
 *
 * Demonstrates the local Agent Trust Fabric primitives:
 * identity, AgentCard, capabilities, delegation, policy, evidence,
 * runtime attestation, kill switch, and guard decisions.
 *
 * Run: pnpm exec tsx examples/demo.ts
 */

import {
  createIdentity,
  classifyCapabilityRisk,
  validateAgentCard,
  createDelegationToken,
  validateDelegationToken,
  type AgentCard,
  type CapabilityDescriptor,
} from '@fides/core'
import { evaluatePolicy } from '@fides/policy'
import { createEvidenceChain, appendEvidenceEvent, buildMerkleRoot, verifyEvidenceChain } from '@fides/evidence'
import { MockTEEProvider, InMemoryKillSwitch } from '@fides/runtime'
import { evaluateGuard, createTrustContext } from '@fides/guard'

async function demo() {
  console.log('='.repeat(60))
  console.log('  FIDES v2 - Agent Trust Fabric Demo')
  console.log('='.repeat(60))

  console.log('\nStep 1: Creating identities')
  const alice = createIdentity('did:fides:alice', 'agent', { name: 'Alice Assistant' })
  const bob = createIdentity('did:fides:bob', 'agent', { name: 'Bob Scheduler' })
  const charlie = createIdentity('did:fides:charlie', 'principal', { name: 'Charlie User' })
  console.log(`  Alice: ${alice.did}`)
  console.log(`  Bob: ${bob.did}`)
  console.log(`  Charlie: ${charlie.did}`)

  console.log('\nStep 2: Creating an AgentCard')
  const capabilities: CapabilityDescriptor[] = [
    {
      id: 'email:send',
      name: 'Send Email',
      description: 'Send emails on behalf of a principal',
      inputSchema: { type: 'object', required: ['to', 'subject'] },
      outputSchema: { type: 'object' },
      riskLevel: 'high',
      requiresApproval: true,
      requiresRuntimeAttestation: true,
    },
    {
      id: 'calendar:create',
      name: 'Create Calendar Event',
      description: 'Create calendar events on behalf of a principal',
      inputSchema: { type: 'object', required: ['title', 'start'] },
      outputSchema: { type: 'object' },
      riskLevel: 'medium',
      requiresApproval: false,
      requiresRuntimeAttestation: false,
    },
  ]

  const aliceCard: AgentCard = {
    id: alice.did,
    identity: alice,
    capabilities,
    endpoints: [
      {
        url: 'https://alice.example.com/fides',
        protocol: 'https',
        capabilities: ['email:send', 'calendar:create'],
        auth: 'signature',
      },
    ],
    policies: [{ requiresRuntimeAttestation: true, requiresApproval: true, minTrustScore: 0.8 }],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }
  const cardValidation = validateAgentCard(aliceCard)
  console.log(`  Card valid: ${cardValidation.valid}`)
  console.log(`  Capabilities: ${aliceCard.capabilities.length}`)

  console.log('\nStep 3: Classifying capability risk')
  for (const capability of aliceCard.capabilities) {
    console.log(`  ${capability.id}: ${classifyCapabilityRisk(capability.id)}`)
  }

  console.log('\nStep 4: Creating a delegation token')
  const delegation = createDelegationToken({
    delegator: charlie.did,
    delegatee: alice.did,
    capabilities: ['email:send', 'calendar:create'],
    constraints: { maxActions: 10, maxSpend: '10.00', allowedContexts: ['work'] },
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
  })
  const delegationValidation = validateDelegationToken({ ...delegation, signature: 'demo-signature' })
  console.log(`  Token: ${delegation.id}`)
  console.log(`  Delegator -> delegatee: ${delegation.delegator} -> ${delegation.delegatee}`)
  console.log(`  Structure valid with demo signature: ${delegationValidation.valid}`)

  console.log('\nStep 5: Evaluating policy')
  const policy = {
    id: 'demo-policy',
    version: '1.0.0',
    rules: [
      {
        id: 'rate-limit',
        condition: { operator: 'gt' as const, field: 'requestCount', value: 100 },
        action: 'deny' as const,
        explanation: 'Rate limit exceeded',
      },
      {
        id: 'high-trust',
        condition: { operator: 'gte' as const, field: 'reputationScore', value: 0.8 },
        action: 'allow' as const,
        explanation: 'High trust agent',
      },
    ],
    defaultAction: 'deny' as const,
  }
  console.log(`  High trust: ${evaluatePolicy(policy, { requestCount: 10, reputationScore: 0.9 }).decision}`)
  console.log(`  Rate limited: ${evaluatePolicy(policy, { requestCount: 200, reputationScore: 0.9 }).decision}`)

  console.log('\nStep 6: Appending evidence events')
  let chain = createEvidenceChain()
  for (const event of [
    { id: 'e1', type: 'invoke', timestamp: new Date().toISOString(), actor: alice.did, action: 'email:send', payload: {}, privacy: { level: 'redacted' as const } },
    { id: 'e2', type: 'invoke', timestamp: new Date().toISOString(), actor: alice.did, action: 'calendar:create', payload: {}, privacy: { level: 'hash-only' as const } },
    { id: 'e3', type: 'policy', timestamp: new Date().toISOString(), actor: alice.did, action: 'evaluate', payload: {}, privacy: { level: 'public' as const } },
  ]) {
    chain = appendEvidenceEvent(chain, event, 'demo-signature')
  }
  console.log(`  Events: ${chain.events.length}`)
  console.log(`  Chain valid: ${verifyEvidenceChain(chain)}`)
  console.log(`  Merkle root: ${buildMerkleRoot(chain.events.map((event) => event.hash)).slice(0, 16)}...`)

  console.log('\nStep 7: Runtime attestation')
  const tee = new MockTEEProvider()
  const attestation = await tee.attest(alice.did)
  console.log(`  Provider: ${attestation.provider}`)
  console.log(`  Verified: ${await tee.verify(attestation)}`)

  console.log('\nStep 8: Kill switch')
  const killSwitch = new InMemoryKillSwitch()
  killSwitch.engage({ type: 'agent', did: alice.did })
  console.log(`  Alice engaged: ${killSwitch.isEngaged({ type: 'agent', did: alice.did })}`)
  killSwitch.disengage({ type: 'agent', did: alice.did })
  console.log(`  Alice disengaged: ${!killSwitch.isEngaged({ type: 'agent', did: alice.did })}`)

  console.log('\nStep 9: Guard decisions')
  const goodTrust = createTrustContext({
    reputationScore: 0.9,
    capabilityScore: 0.95,
    attestation,
    evidenceChain: chain,
    killSwitchEngaged: false,
    recentIncidents: 0,
  })
  const goodDecision = await evaluateGuard({
    agentDid: alice.did,
    capabilityId: 'email:send',
    policy,
    context: { requestCount: 10 },
    trust: goodTrust,
  })
  console.log(`  Good agent: ${goodDecision.decision}`)

  const badTrust = createTrustContext({ reputationScore: 0.05, killSwitchEngaged: false, recentIncidents: 10 })
  const badDecision = await evaluateGuard({
    agentDid: bob.did,
    capabilityId: 'calendar:create',
    policy,
    context: { requestCount: 10 },
    trust: badTrust,
  })
  console.log(`  Bad agent: ${badDecision.decision}`)

  const killSwitchTrust = createTrustContext({ reputationScore: 0.9, killSwitchEngaged: true, recentIncidents: 0 })
  const killSwitchDecision = await evaluateGuard({
    agentDid: alice.did,
    capabilityId: 'email:send',
    policy,
    context: { requestCount: 10 },
    trust: killSwitchTrust,
  })
  console.log(`  Kill switch: ${killSwitchDecision.decision}`)

  console.log('\n' + '='.repeat(60))
  console.log('  Demo complete - all 9 subsystems exercised')
  console.log('='.repeat(60))
}

demo().catch((error) => {
  console.error(error)
  process.exit(1)
})
