import { describe, expect, it } from 'vitest'
import { createIdentityKeyPair } from '../src/identity.js'
import {
  createApprovalDecision,
  createApprovalRequest,
  createKillSwitchRule,
  isKillSwitchRuleActive,
  signApprovalDecision,
  signApprovalRequest,
  signKillSwitchRule,
  verifySignedApprovalDecision,
  verifySignedApprovalDecisionIssuer,
  verifySignedApprovalRequest,
  verifySignedApprovalRequestIssuer,
  verifySignedKillSwitchRule,
  verifySignedKillSwitchRuleIssuer,
} from '../src/approval.js'

describe('approval and kill switch primitives', () => {
  it('creates and verifies signed approval requests and decisions', async () => {
    const approver = await createIdentityKeyPair()
    const requester = await createIdentityKeyPair()
    const request = createApprovalRequest({
      requesterAgentId: requester.did,
      targetAgentId: 'did:fides:target',
      principalId: 'did:fides:principal',
      capability: 'payments.prepare',
      requestedScopes: ['payments:prepare'],
      riskLevel: 'high',
      policyDecisionHash: 'sha256:policy',
      evidenceRefs: ['evt_1'],
    })

    const signedRequest = await signApprovalRequest(request, requester.privateKey, requester.did)
    expect(request.issuer).toBe(requester.did)
    expect(request.subject).toBe('did:fides:target')
    expect(request.payload_hash).toMatch(/^sha256:/)
    expect(await verifySignedApprovalRequest(signedRequest)).toBe(true)
    expect(await verifySignedApprovalRequestIssuer(signedRequest)).toBe(true)

    const decision = createApprovalDecision({
      approvalRequestId: request.id,
      approverId: approver.did,
      decision: 'approved',
      reason: 'Runtime attestation accepted',
      constraints: { dryRunOnly: true },
    })

    const signedDecision = await signApprovalDecision(decision, approver.privateKey, approver.did)
    expect(decision.issuer).toBe(approver.did)
    expect(decision.subject).toBe(request.id)
    expect(decision.payload_hash).toMatch(/^sha256:/)
    expect(await verifySignedApprovalDecision(signedDecision)).toBe(true)
    expect(await verifySignedApprovalDecisionIssuer(signedDecision)).toBe(true)
  })

  it('creates active kill switch rules that can target risky capability classes', async () => {
    const issuer = await createIdentityKeyPair()
    const rule = createKillSwitchRule({
      issuer: issuer.did,
      targetType: 'risk_class',
      target: 'critical',
      reason: 'Emergency high-risk action freeze',
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    })

    expect(isKillSwitchRuleActive(rule)).toBe(true)

    const signedRule = await signKillSwitchRule(rule, issuer.privateKey, issuer.did)
    expect(await verifySignedKillSwitchRule(signedRule)).toBe(true)
    expect(await verifySignedKillSwitchRuleIssuer(signedRule)).toBe(true)
  })

  it('rejects authority proofs whose verification method is not the payload issuer', async () => {
    const issuer = await createIdentityKeyPair()
    const attacker = await createIdentityKeyPair()
    const decision = createApprovalDecision({
      approvalRequestId: 'approval_1',
      approverId: issuer.did,
      decision: 'approved',
    })
    const killSwitch = createKillSwitchRule({
      issuer: issuer.did,
      targetType: 'capability',
      target: 'payments.execute',
      reason: 'Freeze payment execution',
    })

    const signedDecision = await signApprovalDecision(decision, attacker.privateKey, attacker.did)
    const signedRule = await signKillSwitchRule(killSwitch, attacker.privateKey, attacker.did)

    expect(await verifySignedApprovalDecision(signedDecision)).toBe(true)
    expect(await verifySignedApprovalDecisionIssuer(signedDecision)).toBe(false)
    expect(await verifySignedKillSwitchRule(signedRule)).toBe(true)
    expect(await verifySignedKillSwitchRuleIssuer(signedRule)).toBe(false)
  })
})
