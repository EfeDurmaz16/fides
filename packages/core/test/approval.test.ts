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
  verifySignedApprovalRequest,
  verifySignedKillSwitchRule,
} from '../src/approval.js'

describe('approval and kill switch primitives', () => {
  it('creates and verifies signed approval requests and decisions', async () => {
    const approver = await createIdentityKeyPair()
    const request = createApprovalRequest({
      requesterAgentId: 'did:fides:requester',
      targetAgentId: 'did:fides:target',
      principalId: 'did:fides:principal',
      capability: 'payments.prepare',
      requestedScopes: ['payments:prepare'],
      riskLevel: 'high',
      policyDecisionHash: 'sha256:policy',
      evidenceRefs: ['evt_1'],
    })

    const signedRequest = await signApprovalRequest(request, approver.privateKey, approver.did)
    expect(await verifySignedApprovalRequest(signedRequest)).toBe(true)

    const decision = createApprovalDecision({
      approvalRequestId: request.id,
      approverId: approver.did,
      decision: 'approved',
      reason: 'Runtime attestation accepted',
      constraints: { dryRunOnly: true },
    })

    const signedDecision = await signApprovalDecision(decision, approver.privateKey, approver.did)
    expect(await verifySignedApprovalDecision(signedDecision)).toBe(true)
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
  })
})
