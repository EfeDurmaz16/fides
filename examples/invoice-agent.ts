/**
 * Invoice Agent — Handles invoice processing
 *
 * Demonstrates:
 * - Identity creation and AgentCard publishing
 * - Delegation with financial constraints
 * - Capability risk classification (financial = high risk)
 * - Policy evaluation with approval-required rules
 * - Evidence recording for audit trail
 *
 * Run: npx tsx examples/invoice-agent.ts
 */

import { createIdentity, validateAgentCard, createDelegationToken, validateDelegationToken } from '@fides/core'
import type { AgentCard, CapabilityDescriptor } from '@fides/core'
import { classifyCapabilityRisk } from '@fides/core'
import { evaluatePolicy } from '@fides/policy'
import { createEvidenceChain, appendEvidenceEvent, verifyEvidenceChain, buildMerkleRoot } from '@fides/evidence'
import { MockTEEProvider } from '@fides/runtime'
import { evaluateGuard, createTrustContext } from '@fides/guard'
import { LocalDiscoveryProvider } from '@fides/discovery'

async function main() {
  console.log('═'.repeat(60))
  console.log('  Invoice Agent — FIDES Example')
  console.log('═'.repeat(60))
  console.log()

  // ─── Step 1: Create Identities ───────────────────────────────
  console.log('📝 Step 1: Creating Identities')
  console.log('─'.repeat(40))

  const invoiceAgent = createIdentity('did:fides:invoice-agent', 'agent', {
    name: 'Invoice Processor',
    version: '1.0.0',
  })
  const financeManager = createIdentity('did:fides:finance-mgr', 'principal', {
    name: 'Finance Manager',
    type: 'individual',
  })
  const cfo = createIdentity('did:fides:cfo', 'principal', {
    name: 'CFO',
    type: 'individual',
  })

  console.log(`  Invoice Agent:  ${invoiceAgent.did}`)
  console.log(`  Finance Mgr:    ${financeManager.did}`)
  console.log(`  CFO:            ${cfo.did}`)
  console.log()

  // ─── Step 2: Create AgentCard ────────────────────────────────
  console.log('🃏 Step 2: Creating AgentCard')
  console.log('─'.repeat(40))

  const capabilities: CapabilityDescriptor[] = [
    {
      id: 'invoice:create',
      name: 'Create Invoice',
      description: 'Generate a new invoice from order data',
      inputSchema: { type: 'object', properties: { orderId: { type: 'string' }, amount: { type: 'number' }, currency: { type: 'string' } }, required: ['orderId', 'amount'] },
      outputSchema: { type: 'object', properties: { invoiceId: { type: 'string' } } },
      riskLevel: 'high',
      requiresApproval: false,
      requiresRuntimeAttestation: true,
    },
    {
      id: 'invoice:approve',
      name: 'Approve Invoice',
      description: 'Approve an invoice for payment',
      inputSchema: { type: 'object', properties: { invoiceId: { type: 'string' }, approverDid: { type: 'string' } }, required: ['invoiceId', 'approverDid'] },
      outputSchema: { type: 'object', properties: { approved: { type: 'boolean' } } },
      riskLevel: 'high',
      requiresApproval: true,
      requiresRuntimeAttestation: true,
    },
    {
      id: 'invoice:list',
      name: 'List Invoices',
      description: 'List invoices with optional filters',
      inputSchema: { type: 'object', properties: { status: { type: 'string' }, dateFrom: { type: 'string' } } },
      outputSchema: { type: 'array', items: { type: 'object' } },
      riskLevel: 'low',
      requiresApproval: false,
      requiresRuntimeAttestation: false,
    },
  ]

  const agentCard: AgentCard = {
    id: invoiceAgent.did,
    identity: invoiceAgent,
    capabilities,
    endpoints: [
      {
        url: 'https://invoice-agent.example.com/fides',
        protocol: 'https',
        capabilities: ['invoice:create', 'invoice:approve', 'invoice:list'],
        auth: 'signature',
      },
    ],
    policies: [
      { requiresRuntimeAttestation: true, requiresApproval: true, minTrustScore: 0.7 },
    ],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  const validation = validateAgentCard(agentCard)
  console.log(`  Name: ${agentCard.identity.metadata.name}`)
  console.log(`  Capabilities: ${agentCard.capabilities.map(c => c.id).join(', ')}`)
  console.log(`  Valid: ${validation.valid}`)
  if (!validation.valid) {
    console.log(`  Errors: ${validation.errors.join(', ')}`)
  }
  console.log()

  // ─── Step 3: Financial Risk Classification ───────────────────
  console.log('⚠️  Step 3: Financial Risk Classification')
  console.log('─'.repeat(40))

  for (const cap of agentCard.capabilities) {
    const risk = classifyCapabilityRisk(cap.id)
    const isHighRisk = cap.riskLevel === 'high' || risk === 'high' || risk === 'critical'
    console.log(`  ${cap.id}: ${risk} (declared: ${cap.riskLevel}) ${isHighRisk ? '⚡ HIGH RISK' : ''}`)
  }
  console.log()

  // ─── Step 4: Delegation with Financial Constraints ───────────
  console.log('🔑 Step 4: Delegation with Financial Constraints')
  console.log('─'.repeat(40))

  // CFO delegates invoice processing to the agent with spending limits
  const cfoDelegation = createDelegationToken({
    delegator: cfo.did,
    delegatee: invoiceAgent.did,
    capabilities: ['invoice:create', 'invoice:approve'],
    constraints: {
      maxActions: 100,
      maxSpend: '50000.00',
      allowedContexts: ['business'],
      forbiddenContexts: ['personal', 'test'],
    },
    expiresAt: new Date(Date.now() + 7 * 86400000).toISOString(), // 7 days
  })
  cfoDelegation.signature = 'mock-cfo-sig'

  const cfoValid = validateDelegationToken(cfoDelegation)
  console.log(`  Token ID: ${cfoDelegation.id}`)
  console.log(`  CFO → Agent: ${cfoDelegation.delegator} → ${cfoDelegation.delegatee}`)
  console.log(`  Max spend: $${cfoDelegation.constraints.maxSpend}`)
  console.log(`  Max actions: ${cfoDelegation.constraints.maxActions}`)
  console.log(`  Allowed: ${cfoDelegation.constraints.allowedContexts?.join(', ')}`)
  console.log(`  Forbidden: ${cfoDelegation.constraints.forbiddenContexts?.join(', ')}`)
  console.log(`  Valid: ${cfoValid.valid}`)
  console.log()

  // Finance manager also delegates (chain of authority)
  const mgrDelegation = createDelegationToken({
    delegator: financeManager.did,
    delegatee: invoiceAgent.did,
    capabilities: ['invoice:list', 'invoice:create'],
    constraints: {
      maxActions: 50,
      maxSpend: '10000.00',
      allowedContexts: ['business'],
    },
    expiresAt: new Date(Date.now() + 86400000).toISOString(), // 24h
  })
  mgrDelegation.signature = 'mock-mgr-sig'

  console.log(`  Finance Mgr → Agent: ${mgrDelegation.delegator} → ${mgrDelegation.delegatee}`)
  console.log(`  Max spend: $${mgrDelegation.constraints.maxSpend}`)
  console.log()

  // ─── Step 5: Register with Local Discovery ───────────────────
  console.log('🔍 Step 5: Registering with Local Discovery')
  console.log('─'.repeat(40))

  const localDiscovery = new LocalDiscoveryProvider()
  localDiscovery.registerCard(agentCard)
  const resolved = await localDiscovery.resolve(invoiceAgent.did)
  console.log(`  Registered: ${resolved ? 'yes' : 'no'}`)
  console.log(`  Resolved: ${resolved?.identity.metadata.name}`)
  console.log()

  // ─── Step 6: Policy Evaluation ───────────────────────────────
  console.log('📋 Step 6: Policy Evaluation for Invoice Processing')
  console.log('─'.repeat(40))

  const invoicePolicy = {
    id: 'invoice-policy',
    version: '1.0.0',
    rules: [
      {
        id: 'high-trust-allow',
        condition: { operator: 'gte', field: 'reputationScore', value: 0.8 },
        action: 'allow' as const,
        explanation: 'High trust agent approved for invoice operations',
      },
      {
        id: 'large-invoice-approval',
        condition: { operator: 'gt', field: 'invoiceAmount', value: 25000 },
        action: 'approve-required' as const,
        explanation: 'Invoices over $25,000 require CFO approval',
      },
      {
        id: 'fraud-detection',
        condition: { operator: 'gt', field: 'suspiciousFlags', value: 0 },
        action: 'deny' as const,
        explanation: 'Suspicious activity detected — invoice blocked',
      },
      {
        id: 'medium-trust-warn',
        condition: { operator: 'gte', field: 'reputationScore', value: 0.5 },
        action: 'dry-run' as const,
        explanation: 'Medium trust — processing in dry-run mode',
      },
    ],
    defaultAction: 'deny' as const,
  }

  // Scenario 1: High trust, normal invoice
  const normalResult = evaluatePolicy(invoicePolicy, {
    reputationScore: 0.9,
    invoiceAmount: 5000,
    suspiciousFlags: 0,
  })
  console.log(`  High trust, $5,000 invoice: ${normalResult.decision}`)
  console.log(`    Matched: ${normalResult.matchedRules.join(', ')}`)

  // Scenario 2: Large invoice requiring approval
  const largeResult = evaluatePolicy(invoicePolicy, {
    reputationScore: 0.9,
    invoiceAmount: 50000,
    suspiciousFlags: 0,
  })
  console.log(`  High trust, $50,000 invoice: ${largeResult.decision}`)
  console.log(`    Explanation: ${largeResult.explanation.decision}`)

  // Scenario 3: Fraud detected
  const fraudResult = evaluatePolicy(invoicePolicy, {
    reputationScore: 0.9,
    invoiceAmount: 5000,
    suspiciousFlags: 2,
  })
  console.log(`  High trust, fraud flags: ${fraudResult.decision}`)
  console.log(`    Explanation: ${fraudResult.explanation.decision}`)

  // Scenario 4: Medium trust
  const mediumResult = evaluatePolicy(invoicePolicy, {
    reputationScore: 0.6,
    invoiceAmount: 5000,
    suspiciousFlags: 0,
  })
  console.log(`  Medium trust, $5,000 invoice: ${mediumResult.decision}`)
  console.log()

  // ─── Step 7: Evidence Ledger (Audit Trail) ───────────────────
  console.log('📜 Step 7: Evidence Ledger — Audit Trail')
  console.log('─'.repeat(40))

  let evidenceChain = createEvidenceChain()

  const auditEvents = [
    {
      id: 'audit-001',
      type: 'delegation_created',
      timestamp: new Date().toISOString(),
      actor: cfo.did,
      action: 'invoice:create',
      target: invoiceAgent.did,
      payload: { maxSpend: '50000.00', maxActions: 100 },
      privacy: { level: 'hash-only' as const },
    },
    {
      id: 'audit-002',
      type: 'capability_invoke',
      timestamp: new Date().toISOString(),
      actor: invoiceAgent.did,
      action: 'invoice:create',
      target: 'INV-2026-001',
      payload: { orderId: 'ORD-123', amount: 5000, currency: 'USD' },
      privacy: { level: 'redacted' as const },
    },
    {
      id: 'audit-003',
      type: 'capability_invoke',
      timestamp: new Date().toISOString(),
      actor: invoiceAgent.did,
      action: 'invoice:approve',
      target: 'INV-2026-001',
      payload: { approverDid: financeManager.did, approved: true },
      privacy: { level: 'redacted' as const },
    },
    {
      id: 'audit-004',
      type: 'policy_eval',
      timestamp: new Date().toISOString(),
      actor: invoiceAgent.did,
      action: 'evaluate',
      payload: { policy: 'invoice-policy', decision: normalResult.decision, invoiceAmount: 5000 },
      privacy: { level: 'public' as const },
    },
    {
      id: 'audit-005',
      type: 'capability_invoke',
      timestamp: new Date().toISOString(),
      actor: invoiceAgent.did,
      action: 'invoice:create',
      target: 'INV-2026-002',
      payload: { orderId: 'ORD-456', amount: 50000, currency: 'USD' },
      privacy: { level: 'redacted' as const },
    },
    {
      id: 'audit-006',
      type: 'approval_required',
      timestamp: new Date().toISOString(),
      actor: invoiceAgent.did,
      action: 'invoice:approve',
      target: 'INV-2026-002',
      payload: { reason: 'Amount exceeds $25,000 threshold', escalatedTo: cfo.did },
      privacy: { level: 'public' as const },
    },
  ]

  for (const evt of auditEvents) {
    evidenceChain = appendEvidenceEvent(evidenceChain, evt, 'mock-signature')
    console.log(`  Recorded: ${evt.type} — ${evt.action} → ${evt.target}`)
  }

  const chainValid = verifyEvidenceChain(evidenceChain)
  const merkleRoot = buildMerkleRoot(evidenceChain.events.map(e => e.hash))
  console.log(`  Chain valid: ${chainValid}`)
  console.log(`  Events: ${evidenceChain.events.length}`)
  console.log(`  Merkle root: ${merkleRoot.slice(0, 16)}...`)
  console.log()

  // ─── Step 8: Guard Decision Engine ───────────────────────────
  console.log('🛡️  Step 8: Guard Decision Engine')
  console.log('─'.repeat(40))

  const teeProvider = new MockTEEProvider()
  const attestation = await teeProvider.attest(invoiceAgent.did)

  // Good scenario
  const goodTrust = createTrustContext({
    reputationScore: 0.9,
    capabilityScore: 0.95,
    attestation,
    evidenceChain,
    killSwitchEngaged: false,
    recentIncidents: 0,
  })

  const goodDecision = await evaluateGuard({
    agentDid: invoiceAgent.did,
    capabilityId: 'invoice:create',
    policy: invoicePolicy,
    context: { invoiceAmount: 5000, suspiciousFlags: 0 },
    trust: goodTrust,
  })

  console.log(`  Scenario: Good agent, $5,000 invoice`)
  console.log(`    Decision: ${goodDecision.decision}`)
  console.log(`    Explanation: ${goodDecision.explanation}`)
  console.log(`    Factors: ${goodDecision.factors.length}`)

  // Low trust scenario
  const lowTrust = createTrustContext({
    reputationScore: 0.2,
    killSwitchEngaged: false,
    recentIncidents: 3,
  })

  const lowDecision = await evaluateGuard({
    agentDid: invoiceAgent.did,
    capabilityId: 'invoice:create',
    policy: invoicePolicy,
    context: { invoiceAmount: 5000 },
    trust: lowTrust,
  })

  console.log(`  Scenario: Low trust agent (0.2)`)
  console.log(`    Decision: ${lowDecision.decision}`)
  console.log(`    Explanation: ${lowDecision.explanation}`)
  console.log()

  // ─── Summary ─────────────────────────────────────────────────
  console.log('═'.repeat(60))
  console.log('  Invoice Agent Demo Complete')
  console.log('═'.repeat(60))
  console.log()
  console.log('  Demonstrated:')
  console.log('    ✅ Identity creation (agent + principals)')
  console.log('    ✅ AgentCard with financial capabilities')
  console.log('    ✅ Financial risk classification (high risk)')
  console.log('    ✅ Delegation with spending constraints')
  console.log('    ✅ Chain of authority (CFO + Finance Mgr)')
  console.log('    ✅ Policy evaluation (allow / approve-required / deny / dry-run)')
  console.log('    ✅ Evidence chain for audit trail')
  console.log('    ✅ Guard decision engine (good + low trust)')
  console.log()
}

main().catch(console.error)
