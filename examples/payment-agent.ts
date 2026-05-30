/**
 * Payment Agent — Processes payments
 *
 * Demonstrates:
 * - Identity creation and AgentCard publishing
 * - Critical risk capability classification
 * - Guard decision engine with trust context
 * - Kill switch engagement for fraud detection
 * - Evidence recording for payment audit trail
 *
 * Run: npx tsx examples/payment-agent.ts
 */

import { createAgentIdentity, createPrincipalIdentity, validateAgentCard, createDelegationToken, validateDelegationToken, signAgentCard, signDelegationToken } from '@fides/core'
import type { AgentCard, CapabilityDescriptor } from '@fides/core'
import { classifyCapabilityRisk } from '@fides/core'
import { evaluatePolicy, type PolicyBundle } from '@fides/policy'
import { createEvidenceChain, appendEvidenceEvent, verifyEvidenceChain, buildMerkleRoot, hashEvidenceValue } from '@fides/evidence'
import { MockTEEProvider, InMemoryKillSwitch } from '@fides/runtime'
import { evaluateGuard, createTrustContext } from '@fides/guard'
import { LocalDiscoveryProvider } from '@fides/discovery'

async function main() {
  console.log('═'.repeat(60))
  console.log('  Payment Agent — FIDES Example')
  console.log('═'.repeat(60))
  console.log()

  // ─── Step 1: Create Identities ───────────────────────────────
  console.log('📝 Step 1: Creating Identities')
  console.log('─'.repeat(40))

  const { identity: paymentAgent, privateKey: paymentAgentPrivateKey } = await createAgentIdentity()
  paymentAgent.metadata = { name: 'Payment Processor', version: '1.0.0' }
  const { identity: merchant, privateKey: merchantPrivateKey } = await createPrincipalIdentity({
    type: 'organization',
    displayName: 'ACME Corp',
  })
  const { identity: customer } = await createPrincipalIdentity({
    type: 'individual',
    displayName: 'Bob Customer',
  })

  console.log(`  Payment Agent: ${paymentAgent.did}`)
  console.log(`  Merchant:      ${merchant.did}`)
  console.log(`  Customer:      ${customer.did}`)
  console.log()

  // ─── Step 2: Create AgentCard ────────────────────────────────
  console.log('🃏 Step 2: Creating AgentCard')
  console.log('─'.repeat(40))

  const capabilities: CapabilityDescriptor[] = [
    {
      id: 'payment:charge',
      name: 'Charge Payment',
      description: 'Process a payment charge',
      inputSchema: { type: 'object', properties: { amount: { type: 'number' }, currency: { type: 'string' }, customerId: { type: 'string' } }, required: ['amount', 'currency', 'customerId'] },
      outputSchema: { type: 'object', properties: { transactionId: { type: 'string' }, status: { type: 'string' } } },
      riskLevel: 'high',
      requiresApproval: true,
      requiresRuntimeAttestation: true,
    },
    {
      id: 'payment:refund',
      name: 'Refund Payment',
      description: 'Process a payment refund',
      inputSchema: { type: 'object', properties: { transactionId: { type: 'string' }, amount: { type: 'number' } }, required: ['transactionId'] },
      outputSchema: { type: 'object', properties: { refundId: { type: 'string' }, status: { type: 'string' } } },
      riskLevel: 'high',
      requiresApproval: true,
      requiresRuntimeAttestation: true,
    },
    {
      id: 'payment:status',
      name: 'Check Payment Status',
      description: 'Check the status of a payment transaction',
      inputSchema: { type: 'object', properties: { transactionId: { type: 'string' } }, required: ['transactionId'] },
      outputSchema: { type: 'object', properties: { status: { type: 'string' }, amount: { type: 'number' } } },
      riskLevel: 'low',
      requiresApproval: false,
      requiresRuntimeAttestation: false,
    },
  ]

  const agentCard: AgentCard = {
    id: paymentAgent.did,
    identity: paymentAgent,
    capabilities,
    endpoints: [
      {
        url: 'https://payment-agent.example.com/fides',
        protocol: 'https',
        capabilities: ['payment:charge', 'payment:refund', 'payment:status'],
        auth: 'signature',
      },
    ],
    policies: [
      { requiresRuntimeAttestation: true, requiresApproval: true, minTrustScore: 0.8 },
    ],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  const validation = validateAgentCard(agentCard)
  console.log(`  Name: ${agentCard.identity.metadata!.name}`)
  console.log(`  Capabilities: ${agentCard.capabilities.map(c => c.id).join(', ')}`)
  console.log(`  Valid: ${validation.valid}`)
  if (!validation.valid) {
    console.log(`  Errors: ${validation.errors.join(', ')}`)
  }
  console.log()

  // ─── Step 3: Critical Risk Classification ────────────────────
  console.log('⚠️  Step 3: Critical Risk Classification')
  console.log('─'.repeat(40))

  for (const cap of agentCard.capabilities) {
    const risk = classifyCapabilityRisk(cap.id)
    const riskLabel = risk === 'critical' ? '🔴 CRITICAL' : risk === 'high' ? '🟠 HIGH' : risk === 'medium' ? '🟡 MEDIUM' : '🟢 LOW'
    console.log(`  ${cap.id}: ${risk} (declared: ${cap.riskLevel}) ${riskLabel}`)
  }
  console.log()

  // ─── Step 4: Delegation from Merchant ────────────────────────
  console.log('🔑 Step 4: Merchant Delegates Payment Access')
  console.log('─'.repeat(40))

  const merchantDelegation = await signDelegationToken(createDelegationToken({
    delegator: merchant.did,
    delegatee: paymentAgent.did,
    capabilities: ['payment:charge', 'payment:refund'],
    constraints: {
      maxActions: 1000,
      maxSpend: '100000.00',
      allowedContexts: ['production'],
      forbiddenContexts: ['test', 'staging'],
    },
    expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(), // 30 days
  }), merchantPrivateKey)

  const delegationValid = validateDelegationToken(merchantDelegation)
  console.log(`  Token ID: ${merchantDelegation.id}`)
  console.log(`  Merchant → Agent: ${merchantDelegation.delegator} → ${merchantDelegation.delegatee}`)
  console.log(`  Max spend: $${merchantDelegation.constraints.maxSpend}`)
  console.log(`  Valid: ${delegationValid.valid}`)
  console.log()

  // ─── Step 5: Register with Local Discovery ───────────────────
  console.log('🔍 Step 5: Registering with Local Discovery')
  console.log('─'.repeat(40))

  const localDiscovery = new LocalDiscoveryProvider()
  const signedCard = await signAgentCard(agentCard, paymentAgentPrivateKey, paymentAgent.did)
  await localDiscovery.register(signedCard)
  const resolved = await localDiscovery.resolve(paymentAgent.did)
  const discovered = await localDiscovery.discover({
    schema_version: 'fides.discovery_query.v1',
    id: 'payment-local-query',
    capability: 'payment:charge',
  })
  console.log(`  Registered: ${resolved ? 'yes' : 'no'}`)
  console.log(`  Verified candidate: ${discovered[0]?.verified ? 'yes' : 'no'}`)
  console.log(`  Resolved: ${resolved?.identity.metadata!.name}`)
  console.log()

  // ─── Step 6: Policy Evaluation ───────────────────────────────
  console.log('📋 Step 6: Policy Evaluation for Payment Processing')
  console.log('─'.repeat(40))

  const paymentPolicy = {
    id: 'payment-policy',
    version: '1.0.0',
    rules: [
      {
        id: 'high-trust-payment',
        condition: { operator: 'gte', field: 'reputationScore', value: 0.9 },
        action: 'allow' as const,
        explanation: 'High trust agent approved for payment operations',
      },
      {
        id: 'large-payment-approval',
        condition: { operator: 'gt', field: 'paymentAmount', value: 10000 },
        action: 'approve-required' as const,
        explanation: 'Payments over $10,000 require manual approval',
      },
      {
        id: 'fraud-block',
        condition: { operator: 'gt', field: 'fraudScore', value: 0.7 },
        action: 'deny' as const,
        explanation: 'High fraud score — payment blocked',
      },
      {
        id: 'velocity-check',
        condition: { operator: 'gt', field: 'transactionsPerMinute', value: 10 },
        action: 'deny' as const,
        explanation: 'Transaction velocity exceeded',
      },
      {
        id: 'medium-trust-dry-run',
        condition: { operator: 'gte', field: 'reputationScore', value: 0.6 },
        action: 'dry-run' as const,
        explanation: 'Medium trust — payment processed in dry-run mode',
      },
    ],
    defaultAction: 'deny' as const,
  } satisfies PolicyBundle

  // Scenario 1: High trust, normal payment
  const normalResult = evaluatePolicy(paymentPolicy, {
    reputationScore: 0.95,
    paymentAmount: 500,
    fraudScore: 0.05,
    transactionsPerMinute: 2,
  })
  console.log(`  High trust, $500 payment: ${normalResult.decision}`)
  console.log(`    Matched: ${normalResult.matchedRules.join(', ')}`)

  // Scenario 2: Large payment requiring approval
  const largeResult = evaluatePolicy(paymentPolicy, {
    reputationScore: 0.95,
    paymentAmount: 25000,
    fraudScore: 0.05,
    transactionsPerMinute: 1,
  })
  console.log(`  High trust, $25,000 payment: ${largeResult.decision}`)
  console.log(`    Explanation: ${largeResult.explanation.decision}`)

  // Scenario 3: Fraud detected
  const fraudResult = evaluatePolicy(paymentPolicy, {
    reputationScore: 0.95,
    paymentAmount: 500,
    fraudScore: 0.85,
    transactionsPerMinute: 2,
  })
  console.log(`  High trust, fraud score 0.85: ${fraudResult.decision}`)
  console.log(`    Explanation: ${fraudResult.explanation.decision}`)

  // Scenario 4: Velocity exceeded
  const velocityResult = evaluatePolicy(paymentPolicy, {
    reputationScore: 0.95,
    paymentAmount: 100,
    fraudScore: 0.05,
    transactionsPerMinute: 15,
  })
  console.log(`  High trust, 15 tx/min: ${velocityResult.decision}`)
  console.log(`    Explanation: ${velocityResult.explanation.decision}`)
  console.log()

  // ─── Step 7: Evidence Ledger (Payment Audit Trail) ──────────
  console.log('📜 Step 7: Evidence Ledger — Payment Audit Trail')
  console.log('─'.repeat(40))

  let evidenceChain = createEvidenceChain()

  const paymentEvents = [
    {
      id: 'pay-001',
      type: 'delegation_created',
      timestamp: new Date().toISOString(),
      actor: merchant.did,
      action: 'payment:charge',
      target: paymentAgent.did,
      payload: { maxSpend: '100000.00', maxActions: 1000 },
      privacy: { level: 'hash_only' as const },
    },
    {
      id: 'pay-002',
      type: 'capability_invoke',
      timestamp: new Date().toISOString(),
      actor: paymentAgent.did,
      action: 'payment:charge',
      target: 'TXN-001',
      payload: { amount: 500, currency: 'USD', customerId: customer.did },
      privacy: { level: 'redacted' as const },
    },
    {
      id: 'pay-003',
      type: 'policy_eval',
      timestamp: new Date().toISOString(),
      actor: paymentAgent.did,
      action: 'evaluate',
      payload: { policy: 'payment-policy', decision: normalResult.decision, fraudScore: 0.05 },
      privacy: { level: 'public' as const },
    },
    {
      id: 'pay-004',
      type: 'capability_invoke',
      timestamp: new Date().toISOString(),
      actor: paymentAgent.did,
      action: 'payment:charge',
      target: 'TXN-002',
      payload: { amount: 25000, currency: 'USD', customerId: customer.did },
      privacy: { level: 'redacted' as const },
    },
    {
      id: 'pay-005',
      type: 'approval_required',
      timestamp: new Date().toISOString(),
      actor: paymentAgent.did,
      action: 'payment:charge',
      target: 'TXN-002',
      payload: { reason: 'Amount exceeds $10,000 threshold', escalatedTo: merchant.did },
      privacy: { level: 'public' as const },
    },
    {
      id: 'pay-006',
      type: 'capability_invoke',
      timestamp: new Date().toISOString(),
      actor: paymentAgent.did,
      action: 'payment:refund',
      target: 'REF-001',
      payload: { transactionId: 'TXN-001', amount: 500 },
      privacy: { level: 'redacted' as const },
    },
  ]

  for (const evt of paymentEvents) {
    evidenceChain = appendEvidenceEvent(evidenceChain, evt, localEvidenceSignature(evt))
    console.log(`  Recorded: ${evt.type} — ${evt.action} → ${evt.target}`)
  }

  const chainValid = verifyEvidenceChain(evidenceChain)
  const merkleRoot = buildMerkleRoot(evidenceChain.events.map(e => e.hash))
  console.log(`  Chain valid: ${chainValid}`)
  console.log(`  Events: ${evidenceChain.events.length}`)
  console.log(`  Merkle root: ${merkleRoot.slice(0, 16)}...`)
  console.log()

  // ─── Step 8: Kill Switch — Fraud Detection ───────────────────
  console.log('🛑 Step 8: Kill Switch — Fraud Detection')
  console.log('─'.repeat(40))

  const killSwitch = new InMemoryKillSwitch()

  console.log(`  Initial state: engaged=${killSwitch.isEngaged({ type: 'agent', did: paymentAgent.did })}`)

  // Simulate fraud detection triggering kill switch
  console.log(`  ⚡ Fraud detected — engaging kill switch...`)
  killSwitch.engage({ type: 'agent', did: paymentAgent.did })
  console.log(`  After engagement: engaged=${killSwitch.isEngaged({ type: 'agent', did: paymentAgent.did })}`)

  // Verify global kill also works
  killSwitch.engage({ type: 'global' })
  console.log(`  Global kill engaged: ${killSwitch.isEngaged({ type: 'global' })}`)
  console.log(`  Agent still killed: ${killSwitch.isEngaged({ type: 'agent', did: paymentAgent.did })}`)

  // Disengage and verify recovery
  killSwitch.disengage({ type: 'global' })
  killSwitch.disengage({ type: 'agent', did: paymentAgent.did })
  console.log(`  After disengage: engaged=${killSwitch.isEngaged({ type: 'agent', did: paymentAgent.did })}`)
  console.log()

  // ─── Step 9: Guard Decision Engine ───────────────────────────
  console.log('🛡️  Step 9: Guard Decision Engine')
  console.log('─'.repeat(40))

  const teeProvider = new MockTEEProvider()
  const attestation = await teeProvider.attest(paymentAgent.did)

  // Scenario A: Good agent, normal payment
  const goodTrust = createTrustContext({
    reputationScore: 0.95,
    capabilityScore: 0.98,
    attestation,
    evidenceChain,
    killSwitchEngaged: false,
    recentIncidents: 0,
  })

  const goodDecision = await evaluateGuard({
    agentDid: paymentAgent.did,
    capabilityId: 'payment:charge',
    policy: paymentPolicy,
    context: { paymentAmount: 500, fraudScore: 0.05, transactionsPerMinute: 2 },
    trust: goodTrust,
  })

  console.log(`  Scenario A: Good agent, $500 payment`)
  console.log(`    Decision: ${goodDecision.decision}`)
  console.log(`    Explanation: ${goodDecision.explanation}`)
  console.log(`    Factors: ${goodDecision.factors.length}`)

  // Scenario B: Kill switch engaged (fraud)
  const killedTrust = createTrustContext({
    reputationScore: 0.95,
    killSwitchEngaged: true,
    recentIncidents: 0,
  })

  const killedDecision = await evaluateGuard({
    agentDid: paymentAgent.did,
    capabilityId: 'payment:charge',
    policy: paymentPolicy,
    context: { paymentAmount: 500 },
    trust: killedTrust,
  })

  console.log(`  Scenario B: Kill switch engaged (fraud)`)
  console.log(`    Decision: ${killedDecision.decision}`)
  console.log(`    Explanation: ${killedDecision.explanation}`)

  // Scenario C: Low trust, many incidents
  const badTrust = createTrustContext({
    reputationScore: 0.1,
    killSwitchEngaged: false,
    recentIncidents: 8,
  })

  const badDecision = await evaluateGuard({
    agentDid: paymentAgent.did,
    capabilityId: 'payment:charge',
    policy: paymentPolicy,
    context: { paymentAmount: 500 },
    trust: badTrust,
  })

  console.log(`  Scenario C: Low trust (0.1), 8 incidents`)
  console.log(`    Decision: ${badDecision.decision}`)
  console.log(`    Explanation: ${badDecision.explanation}`)
  console.log()

  // ─── Summary ─────────────────────────────────────────────────
  console.log('═'.repeat(60))
  console.log('  Payment Agent Demo Complete')
  console.log('═'.repeat(60))
  console.log()
  console.log('  Demonstrated:')
  console.log('    ✅ Identity creation (agent + merchant + customer)')
  console.log('    ✅ AgentCard with payment capabilities')
  console.log('    ✅ Critical risk classification (payment keywords)')
  console.log('    ✅ Delegation with spending constraints')
  console.log('    ✅ Policy evaluation (allow / approve-required / deny / dry-run)')
  console.log('    ✅ Fraud detection policies (fraud score, velocity)')
  console.log('    ✅ Evidence chain for payment audit trail')
  console.log('    ✅ Kill switch engagement and recovery')
  console.log('    ✅ Guard decision engine (good / killed / bad trust)')
  console.log()
}

function localEvidenceSignature(event: unknown): string {
  return `local-evidence:${hashEvidenceValue(event).slice('sha256:'.length)}`
}

main().catch(console.error)
