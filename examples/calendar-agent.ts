/**
 * Calendar Agent — Manages calendar events
 *
 * Demonstrates:
 * - Identity creation and AgentCard publishing
 * - Policy evaluation for calendar access
 * - Evidence recording for calendar operations
 * - Guard decision engine with trust context
 *
 * Run: npx tsx examples/calendar-agent.ts
 */

import { createIdentity, validateAgentCard, createDelegationToken, validateDelegationToken } from '@fides/core'
import type { AgentCard, CapabilityDescriptor } from '@fides/core'
import { classifyCapabilityRisk } from '@fides/core'
import { evaluatePolicy } from '@fides/policy'
import { createEvidenceChain, appendEvidenceEvent, verifyEvidenceChain, buildMerkleRoot } from '@fides/evidence'
import { MockTEEProvider, InMemoryKillSwitch } from '@fides/runtime'
import { evaluateGuard, createTrustContext } from '@fides/guard'
import { LocalDiscoveryProvider } from '@fides/discovery'

async function main() {
  console.log('═'.repeat(60))
  console.log('  Calendar Agent — FIDES Example')
  console.log('═'.repeat(60))
  console.log()

  // ─── Step 1: Create Identity ─────────────────────────────────
  console.log('📝 Step 1: Creating Agent Identity')
  console.log('─'.repeat(40))

  const calendarAgent = createIdentity('did:fides:calendar-agent', 'agent', {
    name: 'Calendar Assistant',
    version: '1.0.0',
  })
  const user = createIdentity('did:fides:user-alice', 'principal', {
    name: 'Alice',
    type: 'individual',
  })

  console.log(`  Agent:  ${calendarAgent.did}`)
  console.log(`  User:   ${user.did}`)
  console.log()

  // ─── Step 2: Create AgentCard ────────────────────────────────
  console.log('🃏 Step 2: Creating AgentCard')
  console.log('─'.repeat(40))

  const capabilities: CapabilityDescriptor[] = [
    {
      id: 'calendar:create',
      name: 'Create Event',
      description: 'Create a new calendar event',
      inputSchema: { type: 'object', properties: { title: { type: 'string' }, date: { type: 'string' } }, required: ['title', 'date'] },
      outputSchema: { type: 'object', properties: { eventId: { type: 'string' } } },
      riskLevel: 'medium',
      requiresApproval: false,
      requiresRuntimeAttestation: false,
    },
    {
      id: 'calendar:list',
      name: 'List Events',
      description: 'List calendar events for a date range',
      inputSchema: { type: 'object', properties: { start: { type: 'string' }, end: { type: 'string' } } },
      outputSchema: { type: 'array', items: { type: 'object' } },
      riskLevel: 'low',
      requiresApproval: false,
      requiresRuntimeAttestation: false,
    },
    {
      id: 'calendar:delete',
      name: 'Delete Event',
      description: 'Delete a calendar event',
      inputSchema: { type: 'object', properties: { eventId: { type: 'string' } }, required: ['eventId'] },
      outputSchema: { type: 'object', properties: { success: { type: 'boolean' } } },
      riskLevel: 'high',
      requiresApproval: true,
      requiresRuntimeAttestation: false,
    },
  ]

  const agentCard: AgentCard = {
    id: calendarAgent.did,
    identity: calendarAgent,
    capabilities,
    endpoints: [
      {
        url: 'https://calendar-agent.example.com/fides',
        protocol: 'https',
        capabilities: ['calendar:create', 'calendar:list', 'calendar:delete'],
        auth: 'signature',
      },
    ],
    policies: [
      { requiresRuntimeAttestation: false, requiresApproval: false, minTrustScore: 0.5 },
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

  // ─── Step 3: Capability Risk Classification ──────────────────
  console.log('⚠️  Step 3: Capability Risk Classification')
  console.log('─'.repeat(40))

  for (const cap of agentCard.capabilities) {
    const risk = classifyCapabilityRisk(cap.id)
    console.log(`  ${cap.id}: ${risk} (declared: ${cap.riskLevel})`)
  }
  console.log()

  // ─── Step 4: Register with Local Discovery ───────────────────
  console.log('🔍 Step 4: Registering with Local Discovery')
  console.log('─'.repeat(40))

  const localDiscovery = new LocalDiscoveryProvider()
  // Simulate a signed card for registration
  const signedCard = {
    payload: agentCard,
    signature: 'mock-signature',
    algorithm: 'Ed25519' as const,
    timestamp: new Date().toISOString(),
  }
  localDiscovery.registerCard(agentCard)
  const resolved = await localDiscovery.resolve(calendarAgent.did)
  console.log(`  Registered: ${resolved ? 'yes' : 'no'}`)
  console.log(`  Resolved name: ${resolved?.identity.metadata.name}`)
  console.log()

  // ─── Step 5: Delegation from User to Agent ───────────────────
  console.log('🔑 Step 5: User Delegates Calendar Access')
  console.log('─'.repeat(40))

  const delegation = createDelegationToken({
    delegator: user.did,
    delegatee: calendarAgent.did,
    capabilities: ['calendar:create', 'calendar:list'],
    constraints: {
      maxActions: 50,
      allowedContexts: ['work', 'personal'],
    },
    expiresAt: new Date(Date.now() + 86400000).toISOString(), // 24h
  })
  delegation.signature = 'mock-delegation-sig'

  const delegationValid = validateDelegationToken(delegation)
  console.log(`  Token ID: ${delegation.id}`)
  console.log(`  Delegator: ${delegation.delegator}`)
  console.log(`  Delegatee: ${delegation.delegatee}`)
  console.log(`  Capabilities: ${delegation.capabilities.join(', ')}`)
  console.log(`  Valid: ${delegationValid.valid}`)
  console.log()

  // ─── Step 6: Policy Evaluation ───────────────────────────────
  console.log('📋 Step 6: Policy Evaluation for Calendar Access')
  console.log('─'.repeat(40))

  const calendarPolicy = {
    id: 'calendar-policy',
    version: '1.0.0',
    rules: [
      {
        id: 'trusted-user',
        condition: { operator: 'gte', field: 'reputationScore', value: 0.7 },
        action: 'allow' as const,
        explanation: 'User has sufficient trust score',
      },
      {
        id: 'rate-limit',
        condition: { operator: 'gt', field: 'dailyEvents', value: 100 },
        action: 'deny' as const,
        explanation: 'Daily event creation limit exceeded',
      },
      {
        id: 'business-hours',
        condition: { operator: 'in', field: 'context', value: ['work'] },
        action: 'allow' as const,
        explanation: 'Request within business hours context',
      },
    ],
    defaultAction: 'deny' as const,
  }

  // Scenario: trusted user, normal usage
  const allowResult = evaluatePolicy(calendarPolicy, {
    reputationScore: 0.85,
    dailyEvents: 5,
    context: 'work',
  })
  console.log(`  Trusted user, 5 events: ${allowResult.decision}`)
  console.log(`    Matched: ${allowResult.matchedRules.join(', ')}`)

  // Scenario: rate limit exceeded
  const denyResult = evaluatePolicy(calendarPolicy, {
    reputationScore: 0.85,
    dailyEvents: 150,
    context: 'work',
  })
  console.log(`  Trusted user, 150 events: ${denyResult.decision}`)
  console.log(`    Explanation: ${denyResult.explanation.decision}`)
  console.log()

  // ─── Step 7: Evidence Ledger ─────────────────────────────────
  console.log('📜 Step 7: Recording Evidence Events')
  console.log('─'.repeat(40))

  let evidenceChain = createEvidenceChain()

  const calendarEvents = [
    {
      id: 'evt-001',
      type: 'capability_invoke',
      timestamp: new Date().toISOString(),
      actor: calendarAgent.did,
      action: 'calendar:create',
      target: 'team-standup',
      payload: { title: 'Team Standup', date: '2026-05-05T09:00:00Z' },
      privacy: { level: 'redacted' as const },
    },
    {
      id: 'evt-002',
      type: 'capability_invoke',
      timestamp: new Date().toISOString(),
      actor: calendarAgent.did,
      action: 'calendar:list',
      target: 'week-view',
      payload: { start: '2026-05-05', end: '2026-05-12' },
      privacy: { level: 'hash-only' as const },
    },
    {
      id: 'evt-003',
      type: 'policy_eval',
      timestamp: new Date().toISOString(),
      actor: calendarAgent.did,
      action: 'evaluate',
      payload: { policy: 'calendar-policy', decision: allowResult.decision },
      privacy: { level: 'public' as const },
    },
  ]

  for (const evt of calendarEvents) {
    evidenceChain = appendEvidenceEvent(evidenceChain, evt, 'mock-signature')
    console.log(`  Recorded: ${evt.type} — ${evt.action}`)
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
  const attestation = await teeProvider.attest(calendarAgent.did)

  // Good scenario
  const goodTrust = createTrustContext({
    reputationScore: 0.85,
    capabilityScore: 0.9,
    attestation,
    evidenceChain,
    killSwitchEngaged: false,
    recentIncidents: 0,
  })

  const goodDecision = await evaluateGuard({
    agentDid: calendarAgent.did,
    capabilityId: 'calendar:create',
    policy: calendarPolicy,
    context: { dailyEvents: 5, context: 'work' },
    trust: goodTrust,
  })

  console.log(`  Scenario: Good agent, normal usage`)
  console.log(`    Decision: ${goodDecision.decision}`)
  console.log(`    Explanation: ${goodDecision.explanation}`)
  console.log(`    Factors: ${goodDecision.factors.length}`)

  // Kill switch scenario
  const killSwitch = new InMemoryKillSwitch()
  killSwitch.engage({ type: 'agent', did: calendarAgent.did })

  const killedTrust = createTrustContext({
    reputationScore: 0.85,
    killSwitchEngaged: true,
    recentIncidents: 0,
  })

  const killedDecision = await evaluateGuard({
    agentDid: calendarAgent.did,
    capabilityId: 'calendar:create',
    policy: calendarPolicy,
    context: { dailyEvents: 5 },
    trust: killedTrust,
  })

  console.log(`  Scenario: Kill switch engaged`)
  console.log(`    Decision: ${killedDecision.decision}`)
  console.log(`    Explanation: ${killedDecision.explanation}`)

  killSwitch.disengage({ type: 'agent', did: calendarAgent.did })
  console.log()

  // ─── Summary ─────────────────────────────────────────────────
  console.log('═'.repeat(60))
  console.log('  Calendar Agent Demo Complete')
  console.log('═'.repeat(60))
  console.log()
  console.log('  Demonstrated:')
  console.log('    ✅ Identity creation')
  console.log('    ✅ AgentCard with calendar capabilities')
  console.log('    ✅ Capability risk classification')
  console.log('    ✅ Local discovery registration')
  console.log('    ✅ Delegation from user to agent')
  console.log('    ✅ Policy evaluation (allow + deny scenarios)')
  console.log('    ✅ Evidence chain with Merkle root')
  console.log('    ✅ Guard decision engine (good + kill switch)')
  console.log()
}

main().catch(console.error)
