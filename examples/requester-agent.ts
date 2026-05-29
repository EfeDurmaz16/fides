/**
 * Requester Agent — Discovers and invokes other agents
 *
 * Demonstrates:
 * - Identity creation for a requester agent
 * - Discovery using LocalDiscoveryProvider
 * - Trust score checking before invoking capabilities
 * - Full flow: discover → check trust → evaluate guard → invoke
 * - Evidence recording for the complete interaction
 *
 * Run: npx tsx examples/requester-agent.ts
 */

import { createIdentity, validateAgentCard, createDelegationToken, validateDelegationToken } from '@fides/core'
import type { AgentCard, CapabilityDescriptor } from '@fides/core'
import { classifyCapabilityRisk } from '@fides/core'
import { evaluatePolicy, type PolicyBundle } from '@fides/policy'
import { createEvidenceChain, appendEvidenceEvent, verifyEvidenceChain, buildMerkleRoot } from '@fides/evidence'
import { MockTEEProvider, InMemoryKillSwitch } from '@fides/runtime'
import { evaluateGuard, createTrustContext } from '@fides/guard'
import { LocalDiscoveryProvider } from '@fides/discovery'

async function main() {
  console.log('═'.repeat(60))
  console.log('  Requester Agent — FIDES Example')
  console.log('═'.repeat(60))
  console.log()

  // ─── Step 1: Create Identities ───────────────────────────────
  console.log('📝 Step 1: Creating Identities')
  console.log('─'.repeat(40))

  const requesterAgent = createIdentity('did:fides:requester', 'agent', {
    name: 'Task Orchestrator',
    version: '1.0.0',
  })
  const user = createIdentity('did:fides:user-alice', 'principal', {
    name: 'Alice',
    type: 'individual',
  })

  console.log(`  Requester: ${requesterAgent.did}`)
  console.log(`  User:      ${user.did}`)
  console.log()

  // ─── Step 2: Create Service Provider AgentCards ──────────────
  console.log('🃏 Step 2: Creating Service Provider AgentCards')
  console.log('─'.repeat(40))

  // Calendar service provider
  const calendarAgent = createIdentity('did:fides:calendar-svc', 'agent', {
    name: 'Calendar Service',
  })
  const calendarCapabilities: CapabilityDescriptor[] = [
    {
      id: 'calendar:create',
      name: 'Create Event',
      description: 'Create a calendar event',
      inputSchema: { type: 'object', properties: { title: { type: 'string' }, date: { type: 'string' } }, required: ['title', 'date'] },
      outputSchema: { type: 'object', properties: { eventId: { type: 'string' } } },
      riskLevel: 'medium',
      requiresApproval: false,
      requiresRuntimeAttestation: false,
    },
    {
      id: 'calendar:list',
      name: 'List Events',
      description: 'List calendar events',
      inputSchema: { type: 'object', properties: { start: { type: 'string' }, end: { type: 'string' } } },
      outputSchema: { type: 'array', items: { type: 'object' } },
      riskLevel: 'low',
      requiresApproval: false,
      requiresRuntimeAttestation: false,
    },
  ]
  const calendarCard: AgentCard = {
    id: calendarAgent.did,
    identity: calendarAgent,
    capabilities: calendarCapabilities,
    endpoints: [
      { url: 'https://calendar.example.com/fides', protocol: 'https', capabilities: ['calendar:create', 'calendar:list'], auth: 'signature' },
    ],
    policies: [{ requiresRuntimeAttestation: false, requiresApproval: false, minTrustScore: 0.5 }],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  // Payment service provider
  const paymentAgent = createIdentity('did:fides:payment-svc', 'agent', {
    name: 'Payment Service',
  })
  const paymentCapabilities: CapabilityDescriptor[] = [
    {
      id: 'payment:charge',
      name: 'Charge Payment',
      description: 'Process a payment charge',
      inputSchema: { type: 'object', properties: { amount: { type: 'number' }, currency: { type: 'string' } }, required: ['amount', 'currency'] },
      outputSchema: { type: 'object', properties: { transactionId: { type: 'string' } } },
      riskLevel: 'high',
      requiresApproval: true,
      requiresRuntimeAttestation: true,
    },
    {
      id: 'payment:status',
      name: 'Check Payment Status',
      description: 'Check payment transaction status',
      inputSchema: { type: 'object', properties: { transactionId: { type: 'string' } } },
      outputSchema: { type: 'object', properties: { status: { type: 'string' } } },
      riskLevel: 'low',
      requiresApproval: false,
      requiresRuntimeAttestation: false,
    },
  ]
  const paymentCard: AgentCard = {
    id: paymentAgent.did,
    identity: paymentAgent,
    capabilities: paymentCapabilities,
    endpoints: [
      { url: 'https://payment.example.com/fides', protocol: 'https', capabilities: ['payment:charge', 'payment:status'], auth: 'signature' },
    ],
    policies: [{ requiresRuntimeAttestation: true, requiresApproval: true, minTrustScore: 0.8 }],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  // Invoice service provider
  const invoiceAgent = createIdentity('did:fides:invoice-svc', 'agent', {
    name: 'Invoice Service',
  })
  const invoiceCapabilities: CapabilityDescriptor[] = [
    {
      id: 'invoice:create',
      name: 'Create Invoice',
      description: 'Generate an invoice',
      inputSchema: { type: 'object', properties: { orderId: { type: 'string' }, amount: { type: 'number' } }, required: ['orderId', 'amount'] },
      outputSchema: { type: 'object', properties: { invoiceId: { type: 'string' } } },
      riskLevel: 'high',
      requiresApproval: false,
      requiresRuntimeAttestation: true,
    },
    {
      id: 'invoice:list',
      name: 'List Invoices',
      description: 'List invoices',
      inputSchema: { type: 'object', properties: { status: { type: 'string' } } },
      outputSchema: { type: 'array', items: { type: 'object' } },
      riskLevel: 'low',
      requiresApproval: false,
      requiresRuntimeAttestation: false,
    },
  ]
  const invoiceCard: AgentCard = {
    id: invoiceAgent.did,
    identity: invoiceAgent,
    capabilities: invoiceCapabilities,
    endpoints: [
      { url: 'https://invoice.example.com/fides', protocol: 'https', capabilities: ['invoice:create', 'invoice:list'], auth: 'signature' },
    ],
    policies: [{ requiresRuntimeAttestation: true, requiresApproval: false, minTrustScore: 0.7 }],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  console.log(`  Calendar: ${calendarCard.identity.metadata!.name} (${calendarCard.capabilities.length} caps)`)
  console.log(`  Payment:  ${paymentCard.identity.metadata!.name} (${paymentCard.capabilities.length} caps)`)
  console.log(`  Invoice:  ${invoiceCard.identity.metadata!.name} (${invoiceCard.capabilities.length} caps)`)
  console.log()

  // ─── Step 3: Register All Providers with Local Discovery ─────
  console.log('🔍 Step 3: Registering with Local Discovery')
  console.log('─'.repeat(40))

  const localDiscovery = new LocalDiscoveryProvider()
  localDiscovery.registerCard(calendarCard)
  localDiscovery.registerCard(paymentCard)
  localDiscovery.registerCard(invoiceCard)

  console.log(`  Registered 3 service providers`)

  // Discover each provider
  const discoveredCalendar = await localDiscovery.resolve(calendarAgent.did)
  const discoveredPayment = await localDiscovery.resolve(paymentAgent.did)
  const discoveredInvoice = await localDiscovery.resolve(invoiceAgent.did)

  console.log(`  Discovered calendar: ${discoveredCalendar ? discoveredCalendar.identity.metadata!.name : 'NOT FOUND'}`)
  console.log(`  Discovered payment:  ${discoveredPayment ? discoveredPayment.identity.metadata!.name : 'NOT FOUND'}`)
  console.log(`  Discovered invoice:  ${discoveredInvoice ? discoveredInvoice.identity.metadata!.name : 'NOT FOUND'}`)

  // List all available agents
  const allAgents = localDiscovery.list()
  console.log(`  Total agents in discovery: ${allAgents.length}`)
  console.log()

  // ─── Step 4: User Delegates to Requester ─────────────────────
  console.log('🔑 Step 4: User Delegates to Requester Agent')
  console.log('─'.repeat(40))

  const userDelegation = createDelegationToken({
    delegator: user.did,
    delegatee: requesterAgent.did,
    capabilities: ['calendar:create', 'payment:charge', 'invoice:create'],
    constraints: {
      maxActions: 20,
      maxSpend: '5000.00',
      allowedContexts: ['work'],
    },
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
  })
  userDelegation.signature = 'mock-user-sig'

  const delegationValid = validateDelegationToken(userDelegation)
  console.log(`  Token ID: ${userDelegation.id}`)
  console.log(`  User → Requester: ${userDelegation.delegator} → ${userDelegation.delegatee}`)
  console.log(`  Capabilities: ${userDelegation.capabilities.join(', ')}`)
  console.log(`  Max spend: $${userDelegation.constraints.maxSpend}`)
  console.log(`  Valid: ${delegationValid.valid}`)
  console.log()

  // ─── Step 5: Trust Score Checking ────────────────────────────
  console.log('📊 Step 5: Trust Score Checking Before Invocation')
  console.log('─'.repeat(40))

  // Simulate trust scores for each provider
  const trustScores: Record<string, number> = {
    [calendarAgent.did]: 0.85,
    [paymentAgent.did]: 0.95,
    [invoiceAgent.did]: 0.70,
  }

  for (const [did, score] of Object.entries(trustScores)) {
    const card = await localDiscovery.resolve(did)
    const minRequired = card?.policies[0]?.minTrustScore ?? 0
    const meetsThreshold = score >= minRequired
    const status = meetsThreshold ? '✅ PASS' : '❌ FAIL'
    console.log(`  ${card?.identity.metadata!.name}: score=${score.toFixed(2)}, required=${minRequired.toFixed(2)} ${status}`)
  }
  console.log()

  // ─── Step 6: Full Flow — Discover → Trust → Guard → Invoke ──
  console.log('🔄 Step 6: Full Flow — Discover → Trust → Guard → Invoke')
  console.log('─'.repeat(40))

  // Shared policy for all invocations
  const requesterPolicy = {
    id: 'requester-policy',
    version: '1.0.0',
    rules: [
      {
        id: 'high-trust',
        condition: { operator: 'gte', field: 'reputationScore', value: 0.8 },
        action: 'allow' as const,
        explanation: 'High trust service provider',
      },
      {
        id: 'medium-trust',
        condition: { operator: 'gte', field: 'reputationScore', value: 0.5 },
        action: 'dry-run' as const,
        explanation: 'Medium trust — dry-run mode',
      },
      {
        id: 'rate-limit',
        condition: { operator: 'gt', field: 'requestCount', value: 50 },
        action: 'deny' as const,
        explanation: 'Rate limit exceeded',
      },
    ],
    defaultAction: 'deny' as const,
  } satisfies PolicyBundle

  const evidenceChain = createEvidenceChain()
  const teeProvider = new MockTEEProvider()
  const requesterAttestation = await teeProvider.attest(requesterAgent.did)

  // Flow 1: Invoke calendar service (medium risk, high trust)
  console.log(`  ┌─ Flow 1: Create Calendar Event`)
  console.log(`  │`)

  // 1a. Discover
  const calendarProvider = await localDiscovery.resolve(calendarAgent.did)
  console.log(`  │ 1a. Discovered: ${calendarProvider?.identity.metadata!.name}`)

  // 1b. Check trust
  const calendarTrustScore = trustScores[calendarAgent.did] ?? 0
  const calendarMeetsTrust = calendarTrustScore >= (calendarProvider?.policies[0]?.minTrustScore ?? 0)
  console.log(`  │ 1b. Trust score: ${calendarTrustScore.toFixed(2)} (meets threshold: ${calendarMeetsTrust})`)

  // 1c. Evaluate guard
  const calendarTrust = createTrustContext({
    reputationScore: calendarTrustScore,
    capabilityScore: 0.9,
    attestation: requesterAttestation,
    evidenceChain,
    killSwitchEngaged: false,
    recentIncidents: 0,
  })

  const calendarGuard = await evaluateGuard({
    agentDid: calendarAgent.did,
    capabilityId: 'calendar:create',
    policy: requesterPolicy,
    context: { requestCount: 5, reputationScore: calendarTrustScore },
    trust: calendarTrust,
  })
  console.log(`  │ 1c. Guard decision: ${calendarGuard.decision}`)

  if (calendarGuard.decision === 'allow') {
    console.log(`  │ 1d. ✅ Invoked calendar:create successfully`)
    evidenceChain.events.length // just to reference the chain

    // Record evidence
    const calendarEvent = {
      id: 'req-001',
      type: 'capability_invoke',
      timestamp: new Date().toISOString(),
      actor: requesterAgent.did,
      action: 'calendar:create',
      target: calendarAgent.did,
      payload: { title: 'Team Meeting', date: '2026-05-06T10:00:00Z' },
      privacy: { level: 'redacted' as const },
    }
    evidenceChain.events.push({
      ...calendarEvent,
      prevHash: evidenceChain.events.length > 0 ? evidenceChain.events[evidenceChain.events.length - 1].hash : '0',
      hash: 'mock-hash-001',
      signature: 'mock-sig',
    } as any)
  } else {
    console.log(`  │ 1d. ❌ Invocation blocked: ${calendarGuard.explanation}`)
  }
  console.log(`  │`)

  // Flow 2: Invoke payment service (high risk, high trust)
  console.log(`  ┌─ Flow 2: Process Payment`)
  console.log(`  │`)

  const paymentProvider = await localDiscovery.resolve(paymentAgent.did)
  console.log(`  │ 2a. Discovered: ${paymentProvider?.identity.metadata!.name}`)

  const paymentTrustScore = trustScores[paymentAgent.did] ?? 0
  const paymentMeetsTrust = paymentTrustScore >= (paymentProvider?.policies[0]?.minTrustScore ?? 0)
  console.log(`  │ 2b. Trust score: ${paymentTrustScore.toFixed(2)} (meets threshold: ${paymentMeetsTrust})`)

  const paymentTrust = createTrustContext({
    reputationScore: paymentTrustScore,
    capabilityScore: 0.98,
    attestation: requesterAttestation,
    evidenceChain,
    killSwitchEngaged: false,
    recentIncidents: 0,
  })

  const paymentGuard = await evaluateGuard({
    agentDid: paymentAgent.did,
    capabilityId: 'payment:charge',
    policy: requesterPolicy,
    context: { requestCount: 5, reputationScore: paymentTrustScore },
    trust: paymentTrust,
  })
  console.log(`  │ 2c. Guard decision: ${paymentGuard.decision}`)

  if (paymentGuard.decision === 'allow') {
    console.log(`  │ 2d. ✅ Invoked payment:charge successfully`)
    const paymentEvent = {
      id: 'req-002',
      type: 'capability_invoke',
      timestamp: new Date().toISOString(),
      actor: requesterAgent.did,
      action: 'payment:charge',
      target: paymentAgent.did,
      payload: { amount: 150, currency: 'USD' },
      privacy: { level: 'redacted' as const },
    }
    evidenceChain.events.push({
      ...paymentEvent,
      prevHash: evidenceChain.events.length > 0 ? evidenceChain.events[evidenceChain.events.length - 1].hash : '0',
      hash: 'mock-hash-002',
      signature: 'mock-sig',
    } as any)
  } else {
    console.log(`  │ 2d. ❌ Invocation blocked: ${paymentGuard.explanation}`)
  }
  console.log(`  │`)

  // Flow 3: Invoke invoice service (high risk, medium trust)
  console.log(`  ┌─ Flow 3: Create Invoice`)
  console.log(`  │`)

  const invoiceProvider = await localDiscovery.resolve(invoiceAgent.did)
  console.log(`  │ 3a. Discovered: ${invoiceProvider?.identity.metadata!.name}`)

  const invoiceTrustScore = trustScores[invoiceAgent.did] ?? 0
  const invoiceMeetsTrust = invoiceTrustScore >= (invoiceProvider?.policies[0]?.minTrustScore ?? 0)
  console.log(`  │ 3b. Trust score: ${invoiceTrustScore.toFixed(2)} (meets threshold: ${invoiceMeetsTrust})`)

  const invoiceTrust = createTrustContext({
    reputationScore: invoiceTrustScore,
    capabilityScore: 0.75,
    attestation: requesterAttestation,
    evidenceChain,
    killSwitchEngaged: false,
    recentIncidents: 0,
  })

  const invoiceGuard = await evaluateGuard({
    agentDid: invoiceAgent.did,
    capabilityId: 'invoice:create',
    policy: requesterPolicy,
    context: { requestCount: 5, reputationScore: invoiceTrustScore },
    trust: invoiceTrust,
  })
  console.log(`  │ 3c. Guard decision: ${invoiceGuard.decision}`)

  if (invoiceGuard.decision === 'allow') {
    console.log(`  │ 3d. ✅ Invoked invoice:create successfully`)
  } else if (invoiceGuard.decision === 'dry-run') {
    console.log(`  │ 3d. ⚠️  Dry-run mode (trust score below optimal)`)
  } else {
    console.log(`  │ 3d. ❌ Invocation blocked: ${invoiceGuard.explanation}`)
  }
  console.log(`  │`)

  // ─── Step 7: Evidence Chain ──────────────────────────────────
  console.log('📜 Step 7: Evidence Chain for Requester Flow')
  console.log('─'.repeat(40))

  // Add policy evaluation events
  const policyEvents = [
    {
      id: 'req-policy-001',
      type: 'policy_eval',
      timestamp: new Date().toISOString(),
      actor: requesterAgent.did,
      action: 'evaluate',
      target: calendarAgent.did,
      payload: { capability: 'calendar:create', decision: calendarGuard.decision },
      privacy: { level: 'public' as const },
    },
    {
      id: 'req-policy-002',
      type: 'policy_eval',
      timestamp: new Date().toISOString(),
      actor: requesterAgent.did,
      action: 'evaluate',
      target: paymentAgent.did,
      payload: { capability: 'payment:charge', decision: paymentGuard.decision },
      privacy: { level: 'public' as const },
    },
    {
      id: 'req-policy-003',
      type: 'policy_eval',
      timestamp: new Date().toISOString(),
      actor: requesterAgent.did,
      action: 'evaluate',
      target: invoiceAgent.did,
      payload: { capability: 'invoice:create', decision: invoiceGuard.decision },
      privacy: { level: 'public' as const },
    },
  ]

  let fullChain = createEvidenceChain()
  for (const evt of [...evidenceChain.events, ...policyEvents]) {
    fullChain = appendEvidenceEvent(fullChain, evt, 'mock-signature')
    console.log(`  Recorded: ${evt.type} — ${evt.action} → ${evt.target}`)
  }

  const chainValid = verifyEvidenceChain(fullChain)
  const merkleRoot = buildMerkleRoot(fullChain.events.map(e => e.hash))
  console.log(`  Chain valid: ${chainValid}`)
  console.log(`  Events: ${fullChain.events.length}`)
  console.log(`  Merkle root: ${merkleRoot.slice(0, 16)}...`)
  console.log()

  // ─── Step 8: Capability Risk Summary ─────────────────────────
  console.log('⚠️  Step 8: Capability Risk Summary')
  console.log('─'.repeat(40))

  const allCapabilities = [
    ...calendarCapabilities,
    ...paymentCapabilities,
    ...invoiceCapabilities,
  ]

  for (const cap of allCapabilities) {
    const risk = classifyCapabilityRisk(cap.id)
    const riskLabel = risk === 'critical' ? '🔴' : risk === 'high' ? '🟠' : risk === 'medium' ? '🟡' : '🟢'
    console.log(`  ${riskLabel} ${cap.id}: ${risk} (declared: ${cap.riskLevel})`)
  }
  console.log()

  // ─── Summary ─────────────────────────────────────────────────
  console.log('═'.repeat(60))
  console.log('  Requester Agent Demo Complete')
  console.log('═'.repeat(60))
  console.log()
  console.log('  Demonstrated:')
  console.log('    ✅ Identity creation for requester agent')
  console.log('    ✅ Multiple service provider AgentCards')
  console.log('    ✅ Local discovery registration and resolution')
  console.log('    ✅ User delegation to requester')
  console.log('    ✅ Trust score checking against provider thresholds')
  console.log('    ✅ Full flow: discover → trust → guard → invoke')
  console.log('    ✅ Evidence chain for multi-agent interaction')
  console.log('    ✅ Capability risk classification across providers')
  console.log()
}

main().catch(console.error)
