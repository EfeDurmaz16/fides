import { signObject, verifyObject, type SignedObject } from './canonical-signer.js'
import { hashProtocolPayload } from './protocol.js'

export type ApprovalDecisionValue = 'approved' | 'denied'
export type KillSwitchTargetType = 'agent' | 'publisher' | 'capability' | 'session' | 'principal' | 'risk_class'

export interface ApprovalRequest {
  schema_version: 'fides.approval.request.v1'
  id: string
  issuer: string
  subject: string
  requester_agent_id: string
  target_agent_id: string
  principal_id: string
  capability: string
  requested_scopes: string[]
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  policy_decision_hash?: string
  evidence_refs: string[]
  status: 'pending' | 'approved' | 'denied' | 'expired'
  created_at: string
  expires_at?: string
  payload_hash: string
}

export interface ApprovalDecision {
  schema_version: 'fides.approval.decision.v1'
  id: string
  issuer: string
  subject: string
  approval_request_id: string
  approver_id: string
  decision: ApprovalDecisionValue
  reason: string
  constraints: Record<string, unknown>
  evidence_refs: string[]
  decided_at: string
  payload_hash: string
}

export interface KillSwitchRule {
  schema_version: 'fides.kill_switch.rule.v1'
  id: string
  issuer: string
  target_type: KillSwitchTargetType
  target: string
  reason: string
  enabled: boolean
  created_at: string
  expires_at?: string
  payload_hash: string
}

export type SignedApprovalRequest = SignedObject<ApprovalRequest>
export type SignedApprovalDecision = SignedObject<ApprovalDecision>
export type SignedKillSwitchRule = SignedObject<KillSwitchRule>

export interface CreateApprovalRequestInput {
  requesterAgentId: string
  targetAgentId: string
  principalId: string
  capability: string
  requestedScopes?: string[]
  riskLevel: ApprovalRequest['risk_level']
  policyDecisionHash?: string
  evidenceRefs?: string[]
  expiresAt?: string
  createdAt?: string
}

export interface CreateApprovalDecisionInput {
  approvalRequestId: string
  approverId: string
  decision: ApprovalDecisionValue
  reason?: string
  constraints?: Record<string, unknown>
  evidenceRefs?: string[]
  decidedAt?: string
}

export interface CreateKillSwitchRuleInput {
  issuer: string
  targetType: KillSwitchTargetType
  target: string
  reason: string
  enabled?: boolean
  createdAt?: string
  expiresAt?: string
}

function withPayloadHash<T extends Record<string, unknown>>(payload: T): T & { payload_hash: string } {
  return {
    ...payload,
    payload_hash: hashProtocolPayload(payload),
  }
}

export function createApprovalRequest(input: CreateApprovalRequestInput): ApprovalRequest {
  return withPayloadHash({
    schema_version: 'fides.approval.request.v1' as const,
    id: crypto.randomUUID(),
    issuer: input.requesterAgentId,
    subject: input.targetAgentId,
    requester_agent_id: input.requesterAgentId,
    target_agent_id: input.targetAgentId,
    principal_id: input.principalId,
    capability: input.capability,
    requested_scopes: input.requestedScopes ?? [],
    risk_level: input.riskLevel,
    policy_decision_hash: input.policyDecisionHash,
    evidence_refs: input.evidenceRefs ?? [],
    status: 'pending' as const,
    created_at: input.createdAt ?? new Date().toISOString(),
    expires_at: input.expiresAt,
  })
}

export function createApprovalDecision(input: CreateApprovalDecisionInput): ApprovalDecision {
  return withPayloadHash({
    schema_version: 'fides.approval.decision.v1' as const,
    id: crypto.randomUUID(),
    issuer: input.approverId,
    subject: input.approvalRequestId,
    approval_request_id: input.approvalRequestId,
    approver_id: input.approverId,
    decision: input.decision,
    reason: input.reason ?? '',
    constraints: input.constraints ?? {},
    evidence_refs: input.evidenceRefs ?? [],
    decided_at: input.decidedAt ?? new Date().toISOString(),
  })
}

export function createKillSwitchRule(input: CreateKillSwitchRuleInput): KillSwitchRule {
  return withPayloadHash({
    schema_version: 'fides.kill_switch.rule.v1' as const,
    id: crypto.randomUUID(),
    issuer: input.issuer,
    target_type: input.targetType,
    target: input.target,
    reason: input.reason,
    enabled: input.enabled ?? true,
    created_at: input.createdAt ?? new Date().toISOString(),
    expires_at: input.expiresAt,
  })
}

export function isApprovalRequestExpired(request: ApprovalRequest, now: Date = new Date()): boolean {
  return request.expires_at ? new Date(request.expires_at) <= now : false
}

export function isKillSwitchRuleActive(rule: KillSwitchRule, now: Date = new Date()): boolean {
  if (!rule.enabled) return false
  if (!rule.expires_at) return true
  return new Date(rule.expires_at) > now
}

export function signApprovalRequest(
  request: ApprovalRequest,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<SignedApprovalRequest> {
  return signObject(request, privateKey, { verificationMethod, proofPurpose: 'assertionMethod' })
}

export function verifySignedApprovalRequest(signed: SignedApprovalRequest): Promise<boolean> {
  return verifyObject(signed)
}

export function signApprovalDecision(
  decision: ApprovalDecision,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<SignedApprovalDecision> {
  return signObject(decision, privateKey, { verificationMethod, proofPurpose: 'assertionMethod' })
}

export function verifySignedApprovalDecision(signed: SignedApprovalDecision): Promise<boolean> {
  return verifyObject(signed)
}

export function signKillSwitchRule(
  rule: KillSwitchRule,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<SignedKillSwitchRule> {
  return signObject(rule, privateKey, { verificationMethod, proofPurpose: 'assertionMethod' })
}

export function verifySignedKillSwitchRule(signed: SignedKillSwitchRule): Promise<boolean> {
  return verifyObject(signed)
}
