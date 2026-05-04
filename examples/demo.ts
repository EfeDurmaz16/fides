/**
 * FIDES v2 End-to-End Demo
 *
 * Demonstrates the full trust fabric flow:
 * 1. Identity creation & AgentCard
 * 2. Trust graph edges & reputation scoring
 * 3. Capability descriptors & risk classification
 * 4. Delegation tokens
 * 5. Policy evaluation with pre-execution guards
 * 6. Evidence ledger with Merkle root
 * 7. Runtime attestation
 * 8. Unified guard decision engine
 * 9. Kill switch
 *
 * Run: npx tsx examples/demo.ts
 */

import { createIdentity, signObject, canonicalJson } from '@fides/core'
import { createAgentCard, classifyCapabilityRisk } from '@fides/core'
import { createDelegationToken, validateDelegationToken } from '@fides/core'
import { evaluatePolicy, runPreExecutionPipeline, type Guard } from '@fides/policy'
import { createEvidenceChain, appendEvidenceEvent, buildMerkleRoot, verifyEvidenceChain } from '@fides/evidence'
import { MockTEEProvider, InMemoryKillSwitch } from '@fides/runtime'
import { evaluateGuard, createTrustContext } from '@fides/guard'

async function demo() {
  console.log('═'.repeat(60))
  console.log('  FIDES v2 — Agent Trust Fabric Demo')
  console.log('═'.repeat(60))
  console.log()

  // ─── Step 1: Create Identities ───────────────────────────────
  console.log('📝 Step 1: Creating Identities')
  console.log('─'.repeat(40))

  const alice = createIdentity('did:fides:alice', 'agent', { name: 'Alice Assistant' })
  const bob = createIdentity('did:fides:bob', 'agent', { name: 'Bob Scheduler' })
  const charlie = createIdentity('did:fides:charlie', 'principal', { name: 'Charlie User' })

  console.log(`  Alice:   ${alice.did}`)
  console.log(`  Bob:     ${bob.did}`)
  console.log(`  Charlie: ${charlie.did}`)
  console.log()

  // ─── Step 2: Create AgentCards ───────────────────────────────
  console.log('🃏 Step 2: Creating AgentCards')
  console.log('─'.repeat(40))

  const aliceCard = createAgentCard({
    did: alice.did,
    name: 'Alice Assistant',
    description: 'General-purpose AI assistant',
    capabilities: [
      { id: 'email:send', name: 'Send Email', description: 'Send emails on behalf of user', riskLevel: 'high', parameters: [], output: { type: 'boolean', description: 'Sent successfully' }, constraints: [] },
      { id: 'calendar:create', name: 'Create Calendar Event', description: 'Create calendar events', riskLevel: 'medium', parameters: [], output: { type: 'object', description: 'Created event' }, constraints: [] },
    ],
    protocols: ['mcp', 'a2a'],
    endpoints: [{ url: 'https://alice.example.com/fides', protocol: 'mcp', capabilities: ['email:send', 'calendar:create'] }],
  })

  const bobCard = createAgentCard({
    did: bob.did,
    name: 'Bob Scheduler',
    description: 'Task scheduling agent',
    capabilities: [
      { id: 'task:create', name: 'Create Task', description: 'Create tasks in project management', riskLevel: 'medium', parameters: [], output: { type: 'object', description: 'Created task' }, constraints: [] },
    ],
    protocols: ['mcp'],
    endpoints: [{ url: 'https://bob.example.com/fides', protocol: 'mcp', capabilities: ['task:create'] }],
  })

  console.log(`  Alice: ${aliceCard.name} (${aliceCard.capabilities.length} capabilities)`)
  console.log(`  Bob:   ${bobCard.name} (${bobCard.capabilities.length} capabilities)`)
  console.log()

  // ─── Step 3: Capability Risk Classification ──────────────────
  console.log('⚠️  Step 3: Capability Risk Classification')
  console.log('─'.repeat(40))

  for (const cap of aliceCard.capabilities) {
    const risk = classifyCapabilityRisk(cap)
    console.log(`  ${cap.id}: ${risk.level} (${risk.factors.join(', ')})`)
  }
  console.log()

  // ─── Step 4: Delegation Token ────────────────────────────────
  console.log('🔑 Step 4: Delegation Token')
  console.log('─'.repeat(40))

  const delegation = createDelegationToken({
    delegator: charlie.did,
    delegatee: alice.did,
    capabilities: ['email:send', 'calendar:create'],
    constraints: {
      maxActions: 10,
      maxSpend: '10.00',
      allowedContexts: ['work'],
    },
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
  })

  const validation = validateDelegationToken(delegation)
  console.log(`  Token ID: ${delegation.id}`)
  console.log(`  Delegator: ${delegation.delegator}`)
  console.log(`  Delegatee: ${delegation.delegatee}`)
  console.log(`  Valid: ${validation.valid}`)
  console.log()

  // ─── Step 5: Policy Evaluation ───────────────────────────────
  console.log('📋 Step 5: Policy Evaluation')
  console.log('─'.repeat(40))

  const policy = {
    id: 'demo-policy',
    version: '1.0.0',
    rules: [
      { id: 'rate-limit', condition: { operator: 'gt', field: 'requestCount', value: 100 }, action: 'deny' as const, explanation: 'Rate limit exceeded' },
      { id: 'high-trust', condition: { operator: 'gte', field: 'reputationScore', value: 0.8 }, action: 'allow' as const, explanation: 'High trust agent' },
    ],
    defaultAction: 'deny' as const,
  }

  const allowResult = evaluatePolicy(policy, { requestCount: 10, reputationScore: 0.9 })
  const denyResult = evaluatePolicy(policy, { requestCount: 200, reputationScore: 0.5 })

  console.log(`  Low usage, high trust: ${allowResult.decision} (${allowResult.explanation.decision})`)
  console.log(`  High usage, mid trust: ${denyResult.decision} (${denyResult.explanation.decision})`)
  console.log()

  // ─── Step 6: Evidence Ledger ─────────────────────────────────
  console.log('📜 Step 6: Evidence Ledger')
  console.log('─'.repeat(40))

  let chain = createEvidenceChain()

  const events = [
    { id: 'e1', type: 'capability_invoke', timestamp: new Date().toISOString(), actor: alice.did, action: 'email:send', target: 'user@example.com', payload: { subject: 'Hello' }, privacy: { level: 'redacted' as const } },
    { id: 'e2', type: 'capability_invoke', timestamp: new Date().toISOString(), actor: alice.did, action: 'calendar:create', target: 'meeting', payload: { title: 'Standup' }, privacy: { level: 'hash-only' as const } },
    { id: 'e3', type: 'policy_eval', timestamp: new Date().toISOString(), actor: alice.did, action: 'evaluate', payload: { policy: 'demo-policy', decision: 'allow' }, privacy: { level: 'public' as const } },
  ]

  for (const evt of events) {
    chain = appendEvidenceEvent(chain, evt, 'mock-signature')
  }

  const chainValid = verifyEvidenceChain(chain)
  const merkleRoot = buildMerkleRoot(chain.events.map(e => e.hash))

  console.log(`  Events: ${chain.events.length}`)
  console.log(`  Chain valid: ${chainValid}`)
  console.log(`  Merkle root: ${merkleRoot.slice(0, 16)}...`)
  console.log(`  Privacy levels: ${chain.events.map(e => e.privacy.level).join(', ')}`)
  console.log()

  // ─── Step 7: Runtime Attestation ─────────────────────────────
  console.log('🔒 Step 7: Runtime Attestation')
  console.log('─'.repeat(40))

  const teeProvider = new MockTEEProvider()
  const attestation = await teeProvider.attest(alice.did)
  const verified = await teeProvider.verify(attestation)

  console.log(`  Provider: ${attestation.provider}`)
  console.log(`  Agent: ${attestation.agentDid}`)
  console.log(`  Verified: ${verified}`)
  console.log(`  Expires: ${attestation.expiresAt}`)
  console.log()

  // ─── Step 8: Kill Switch ─────────────────────────────────────
  console.log('🛑 Step 8: Kill Switch')
  console.log('─'.repeat(40))

  const killSwitch = new InMemoryKillSwitch()

  console.log(`  Global engaged: ${killSwitch.isEngaged({ type: 'global' })}`)
  console.log(`  Alice engaged: ${killSwitch.isEngaged({ type: 'agent', did: alice.did })}`)

  killSwitch.engage({ type: 'agent', did: alice.did })
  console.log(`  After engaging Alice: ${killSwitch.isEngaged({ type: 'agent', did: alice.did })}`)

  killSwitch.disengage({ type: 'agent', did: alice.did })
  console.log(`  After disengaging: ${killSwitch.isEngaged({ type: 'agent', did: alice.did })}`)
  console.log()

  // ─── Step 9: Unified Guard Decision ──────────────────────────
  console.log('🛡️  Step 9: Unified Guard Decision Engine')
  console.log('─'.repeat(40))

  // Scenario A: Good agent, good trust
  const trustA = createTrustContext({
    reputationScore: 0.9,
    capabilityScore: 0.95,
    attestation,
    evidenceChain: chain,
    killSwitchEngaged: false,
    recentIncidents: 0,
  })

  const decisionA = await evaluateGuard({
    agentDid: alice.did,
    capabilityId: 'email:send',
    policy,
    context: { requestCount: 10 },
    trust: trustA,
  })

  console.log(`  Scenario A (good agent):`)
  console.log(`    Decision: ${decisionA.decision}`)
  console.log(`    Factors: ${decisionA.factors.length}`)
  console.log(`    Explanation: ${decisionA.explanation}`)
  console.log()

  // Scenario B: Kill switch engaged
  const trustB = createTrustContext({
    reputationScore: 0.9,
    killSwitchEngaged: true,
    recentIncidents: 0,
  })

  const decisionB = await evaluateGuard({
    agentDid: alice.did,
    capabilityId: 'email:send',
    policy,
    context: { requestCount: 10 },
    trust: trustB,
  })

  console.log(`  Scenario B (kill switch):`)
  console.log(`    Decision: ${decisionB.decision}`)
  console.log(`    Explanation: ${decisionB.explanation}`)
  console.log()

  // Scenario C: Low trust, many incidents
  const trustC = createTrustContext({
    reputationScore: 0.05,
    killSwitchEngaged: false,
    recentIncidents: 10,
  })

  const decisionC = await evaluateGuard({
    agentDid: bob.did,
    capabilityId: 'task:create',
    policy,
    context: { requestCount: 10 },
    trust: trustC,
  })

  console.log(`  Scenario C (low trust, high incidents):`)
  console.log(`    Decision: ${decisionC.decision}`)
  console.log(`    Explanation: ${decisionC.explanation}`)
  console.log()

  // ─── Summary ─────────────────────────────────────────────────
  console.log('═'.repeat(60))
  console.log('  Demo Complete')
  console.log('═'.repeat(60))
  console.log()
  console.log('  Packages demonstrated:')
  console.log('    @fides/core      — Identity, AgentCard, delegation, canonical signing')
  console.log('    @fides/policy    — Policy evaluation, pre-execution pipeline')
  console.log('    @fides/evidence  — Hash chain, Merkle root, privacy levels')
  console.log('    @fides/runtime   — TEE attestation, kill switch')
  console.log('    @fides/guard     — Unified decision engine')
  console.log()
  console.log('  Services available:')
  console.log('    services/discovery   — Agent discovery (well-known, registry, DHT)')
  console.log('    services/trust-graph — Trust edges, reputation, capability scoring')
  console.log('    services/registry    — Agent registry (stub)')
  console.log('    services/relay       — Message relay (stub)')
  console.log('    services/agentd      — Local daemon (stub)')
  console.log()
}

demo().catch(console.error)
